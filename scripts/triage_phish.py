#!/usr/bin/env python3
"""
SOC Phishing Email Triage & IOC Extractor
Author: SOC Engineering / Portfolio Lab
Description:
    Analyzes raw RFC 822 email files (.eml), extracts headers, validates
    SPF/DKIM/DMARC verdicts, defangs suspicious URLs, computes attachment
    hashes (MD5, SHA-256), applies SOC heuristic scoring, and generates
    structured IOC incident data for SIEM/EDR containment.
"""

import sys
import os
import re
import json
import hashlib
import argparse
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr

# ANSI color codes for terminal display
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"


def defang(value: str) -> str:
    """Defangs URLs, domains, and IP addresses to prevent accidental clicks."""
    if not value:
        return ""
    val = value.replace("http://", "hxxp://").replace("https://", "hxxps://")
    # Replace last period of domain or dots in IP with [.]
    val = re.sub(r'(\w+)\.(\w+)', r'\1[.]\2', val)
    return val


def get_hashes(data: bytes):
    """Computes MD5, SHA1, and SHA256 hashes for raw binary data."""
    md5 = hashlib.md5(data).hexdigest()
    sha1 = hashlib.sha1(data).hexdigest()
    sha256 = hashlib.sha256(data).hexdigest()
    return {"md5": md5, "sha1": sha1, "sha256": sha256}


def extract_ip_from_received(received_headers):
    """Extracts external sender IP and relay hops from Received headers."""
    hops = []
    ip_pattern = re.compile(r'\[?(\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b)\]?')
    
    for header in received_headers:
        hops.append(header.strip().replace("\n", " "))
        
    origin_ip = None
    # Traverse from earliest received (bottom of list) upward
    for hop in reversed(received_headers):
        ips = ip_pattern.findall(hop)
        for ip in ips:
            # Skip RFC 1918 private / loopback IP addresses
            if not (ip.startswith("10.") or ip.startswith("192.168.") or
                    ip.startswith("127.") or re.match(r'^172\.(1[6-9]|2[0-9]|3[0-1])\.', ip)):
                origin_ip = ip
                break
        if origin_ip:
            break
            
    return origin_ip, hops


def parse_authentication(msg):
    """Extracts SPF, DKIM, and DMARC results from Authentication-Results."""
    auth_results = msg.get_all("Authentication-Results", [])
    spf_res = msg.get("Received-SPF", "")
    
    results = {"spf": "unknown", "dkim": "unknown", "dmarc": "unknown", "raw": []}
    
    combined = " ".join(auth_results) + " " + spf_res
    results["raw"] = auth_results
    
    # Check SPF
    if re.search(r'spf=(fail|softfail)', combined, re.I):
        results["spf"] = "FAIL"
    elif re.search(r'spf=pass', combined, re.I):
        results["spf"] = "PASS"
    elif re.search(r'spf=neutral', combined, re.I):
        results["spf"] = "NEUTRAL"
        
    # Check DKIM
    if re.search(r'dkim=(fail|neutral)', combined, re.I):
        results["dkim"] = "FAIL"
    elif re.search(r'dkim=pass', combined, re.I):
        results["dkim"] = "PASS"
        
    # Check DMARC
    if re.search(r'dmarc=fail', combined, re.I):
        results["dmarc"] = "FAIL"
    elif re.search(r'dmarc=pass', combined, re.I):
        results["dmarc"] = "PASS"
        
    return results


def extract_links(html_content, text_content):
    """Extracts all hyperlinks and references in body."""
    urls = set()
    url_pattern = re.compile(r'https?://[^\s<>"\']+|www\.[^\s<>"\']+', re.I)
    href_pattern = re.compile(r'href=[\'"](https?://[^\'">]+)[\'"]', re.I)
    
    if html_content:
        for match in href_pattern.findall(html_content):
            urls.add(match)
        for match in url_pattern.findall(html_content):
            urls.add(match)
            
    if text_content:
        for match in url_pattern.findall(text_content):
            urls.add(match)
            
    return sorted(list(urls))


def calculate_risk(headers, auth, urls, attachments, body_text):
    """Calculates risk score (0-100) and suspicious triggers."""
    score = 0
    triggers = []

    # Authentication failures
    if auth["spf"] == "FAIL":
        score += 30
        triggers.append("SPF verification failed (Sender IP not permitted for domain)")
    if auth["dkim"] == "FAIL":
        score += 25
        triggers.append("DKIM signature validation failed or forged")
    if auth["dmarc"] == "FAIL":
        score += 25
        triggers.append("DMARC alignment failed")

    # From vs Reply-To mismatch
    from_name, from_email = parseaddr(headers.get("From", ""))
    reply_name, reply_email = parseaddr(headers.get("Reply-To", ""))
    from_domain = from_email.split("@")[-1].lower() if "@" in from_email else ""
    reply_domain = reply_email.split("@")[-1].lower() if "@" in reply_email else ""
    
    if reply_email and from_domain != reply_domain:
        score += 25
        triggers.append(f"Header mismatch: From domain ({from_domain}) differs from Reply-To ({reply_domain})")

    # High priority / Urgency flag
    if headers.get("X-Priority") in ["1", "Highest"] or headers.get("Importance") == "High":
        score += 10
        triggers.append("High urgency headers detected (X-Priority: 1 / High)")

    # Suspicious keywords in Subject or Body
    urgency_keywords = ["immediate review", "action required", "bonus payout", "direct deposit",
                        "suspend", "verify your account", "24 hours", "forfeiture", "pending verification"]
    content_to_check = (headers.get("Subject", "") + " " + body_text).lower()
    found_keywords = [kw for kw in urgency_keywords if kw in content_to_check]
    if found_keywords:
        score += 15
        triggers.append(f"Psychological urgency keywords detected: {', '.join(found_keywords[:3])}")

    # Suspicious TLDs or domains in URLs
    suspicious_tlds = [".online", ".xyz", ".top", ".club", ".buzz", ".work", ".ru", ".su"]
    for url in urls:
        if any(tld in url.lower() for tld in suspicious_tlds):
            score += 20
            triggers.append(f"Suspicious external TLD found in embedded URL: {defang(url)}")
            break

    # Dangerous attachments
    dangerous_exts = [".zip", ".exe", ".iso", ".hta", ".js", ".vbe", ".vbs", ".html", ".scr"]
    for att in attachments:
        fn = att["filename"].lower()
        if any(fn.endswith(ext) for ext in dangerous_exts):
            score += 25
            triggers.append(f"High-risk attachment extension detected: {att['filename']}")

    score = min(score, 100)
    
    if score >= 70:
        verdict = "MALICIOUS (High Confidence Phish)"
        severity = "HIGH / P1"
    elif score >= 40:
        verdict = "SUSPICIOUS (Requires Analyst Review)"
        severity = "MEDIUM / P2"
    else:
        verdict = "BENIGN / LOW RISK"
        severity = "LOW / P4"

    return score, verdict, severity, triggers


def analyze_email(filepath, dump_dir=None):
    """Main analysis engine for .eml files."""
    if not os.path.exists(filepath):
        print(f"{RED}Error: File not found: {filepath}{RESET}")
        sys.exit(1)

    with open(filepath, "rb") as f:
        msg = BytesParser(policy=policy.default).parse(f)

    # 1. Header extraction
    headers = {
        "From": msg.get("From", ""),
        "To": msg.get("To", ""),
        "Subject": msg.get("Subject", ""),
        "Date": msg.get("Date", ""),
        "Reply-To": msg.get("Reply-To", ""),
        "Return-Path": msg.get("Return-Path", ""),
        "Message-ID": msg.get("Message-ID", ""),
        "X-Mailer": msg.get("X-Mailer", ""),
        "X-Priority": msg.get("X-Priority", ""),
        "Importance": msg.get("Importance", "")
    }

    # 2. Origin IP and Relay
    received_headers = msg.get_all("Received", [])
    origin_ip, hops = extract_ip_from_received(received_headers)

    # 3. Authentication Results
    auth_results = parse_authentication(msg)

    # 4. Body & Attachments
    text_parts = []
    html_parts = []
    attachments = []

    for part in msg.walk():
        content_disposition = part.get_content_disposition()
        content_type = part.get_content_type()

        if content_disposition == "attachment" or part.get_filename():
            filename = part.get_filename() or "unnamed_attachment"
            payload = part.get_payload(decode=True) or b""
            hashes = get_hashes(payload)
            att_info = {
                "filename": filename,
                "content_type": content_type,
                "size_bytes": len(payload),
                "hashes": hashes
            }
            attachments.append(att_info)

            if dump_dir:
                os.makedirs(dump_dir, exist_ok=True)
                out_path = os.path.join(dump_dir, filename)
                with open(out_path, "wb") as af:
                    af.write(payload)
                att_info["saved_path"] = out_path

        elif content_type == "text/plain":
            text_parts.append(part.get_content())
        elif content_type == "text/html":
            html_parts.append(part.get_content())

    all_text = " ".join(text_parts)
    all_html = " ".join(html_parts)
    urls = extract_links(all_html, all_text)

    # 5. Risk Assessment
    score, verdict, severity, triggers = calculate_risk(
        headers, auth_results, urls, attachments, all_text
    )

    triage_result = {
        "analysis_metadata": {
            "target_file": os.path.abspath(filepath),
            "verdict": verdict,
            "severity": severity,
            "risk_score": score,
            "triggers": triggers
        },
        "email_headers": headers,
        "network_telemetry": {
            "origin_ip": origin_ip,
            "defanged_origin_ip": defang(origin_ip) if origin_ip else "N/A",
            "total_hops": len(hops),
            "authentication": auth_results
        },
        "indicators_of_compromise": {
            "sender_address": headers["From"],
            "reply_to": headers["Reply-To"],
            "defanged_urls": [defang(u) for u in urls],
            "raw_urls": urls,
            "attachments": attachments
        },
        "recommended_soc_actions": [
            f"Perimeter Firewall: Block inbound traffic from originating IP {defang(origin_ip)}",
            f"Email Gateway (SEG): Add sender domain/address to global blocklist",
            "Microsoft 365 Defender: Execute message trace and soft-delete/purge identical Subject/Message-ID across all tenant mailboxes",
            "Proxy / DNS: Block domain resolution for extracted malicious URLs on Secure Web Gateway (SWG)",
            "Identity / IAM: Check Azure AD / Okta sign-in logs for target user; enforce immediate password reset & revoke active OAuth refresh tokens if clicked"
        ]
    }

    return triage_result


def print_cli_summary(res):
    """Outputs a clean, professional SOC terminal summary."""
    meta = res["analysis_metadata"]
    hdr = res["email_headers"]
    net = res["network_telemetry"]
    iocs = res["indicators_of_compromise"]

    v_color = RED if "MALICIOUS" in meta["verdict"] else (YELLOW if "SUSPICIOUS" in meta["verdict"] else GREEN)

    print(f"\n{BOLD}{'='*70}{RESET}")
    print(f"{BOLD}           SOC PHISHING TRIAGE & INVESTIGATION REPORT{RESET}")
    print(f"{BOLD}{'='*70}{RESET}\n")

    print(f"VERDICT:       {v_color}{BOLD}{meta['verdict']}{RESET}")
    print(f"SEVERITY:      {meta['severity']}")
    print(f"RISK SCORE:    {v_color}{meta['risk_score']}/100{RESET}\n")

    print(f"{CYAN}{BOLD}[+] Header Summary:{RESET}")
    print(f"    From:       {hdr['From']}")
    print(f"    Reply-To:   {hdr['Reply-To']}")
    print(f"    To:         {hdr['To']}")
    print(f"    Subject:    {hdr['Subject']}")
    print(f"    Date:       {hdr['Date']}")
    print(f"    Mailer:     {hdr.get('X-Mailer', 'N/A')}")

    print(f"\n{CYAN}{BOLD}[+] Authentication & Network Origin:{RESET}")
    print(f"    Origin IP:  {net['defanged_origin_ip']}")
    spf_c = GREEN if net['authentication']['spf'] == 'PASS' else RED
    dkim_c = GREEN if net['authentication']['dkim'] == 'PASS' else RED
    dmarc_c = GREEN if net['authentication']['dmarc'] == 'PASS' else RED
    print(f"    SPF:        {spf_c}{net['authentication']['spf']}{RESET}")
    print(f"    DKIM:       {dkim_c}{net['authentication']['dkim']}{RESET}")
    print(f"    DMARC:      {dmarc_c}{net['authentication']['dmarc']}{RESET}")

    print(f"\n{CYAN}{BOLD}[+] Threat Triggers & Anomalies:{RESET}")
    for trigger in meta["triggers"]:
        print(f"    {RED}[!]{RESET} {trigger}")

    print(f"\n{CYAN}{BOLD}[+] Extracted Indicators of Compromise (IoCs):{RESET}")
    print(f"    Defanged URLs ({len(iocs['defanged_urls'])}):")
    for u in iocs["defanged_urls"]:
        print(f"      - {u}")

    print(f"    Attachments ({len(iocs['attachments'])}):")
    for att in iocs["attachments"]:
        print(f"      - File:   {att['filename']} ({att['size_bytes']} bytes)")
        print(f"        SHA256: {att['hashes']['sha256']}")
        print(f"        MD5:    {att['hashes']['md5']}")

    print(f"\n{CYAN}{BOLD}[+] Recommended SOC Containment Actions:{RESET}")
    for act in res["recommended_soc_actions"]:
        print(f"    [x] {act}")

    print(f"\n{BOLD}{'='*70}{RESET}\n")


def main():
    parser = argparse.ArgumentParser(description="SOC Phishing Email Triage & IOC Parser")
    parser.add_argument("--file", "-f", required=True, help="Path to .eml file to analyze")
    parser.add_argument("--output", "-o", help="Optional path to export JSON triage report")
    parser.add_argument("--dump-attachments", "-d", help="Directory to save extracted attachments safely")
    args = parser.parse_args()

    result = analyze_email(args.file, args.dump_attachments)
    print_cli_summary(result)

    if args.output:
        with open(args.output, "w") as out:
            json.dump(result, out, indent=2)
        print(f"{GREEN}[✓] Full structured JSON report saved to: {args.output}{RESET}\n")


if __name__ == "__main__":
    main()
