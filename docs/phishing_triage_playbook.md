# Enterprise SOC Standard Operating Procedure (SOP)
## Phishing Email Triage & Incident Containment Playbook

**Document ID:** SOP-SOC-PHISH-004  
**Classification:** Internal Security Operations  
**Target Roles:** Tier 1 Security Analyst, Tier 2 Incident Responder  
**Last Reviewed:** October 2024  

---

### 1. Objective & Scope
This Standard Operating Procedure outlines the technical steps required to triage, investigate, scope, and remediate suspected phishing emails reported by employees or flagged by Secure Email Gateways (SEG / Proofpoint / Microsoft Defender for Office 365).

---

### 2. Triage Workflow Diagram

```text
[User Report / SEG Alert]
          │
          ▼
┌─────────────────────────┐
│ Phase 1: Header Triage  │ ──► Verify SPF, DKIM, DMARC, Origin IP, Return-Path
└─────────────────────────┘
          │
          ▼
┌─────────────────────────┐
│ Phase 2: Content & IOCs │ ──► Extract URLs (Defang), Attachment Hashes (MD5/SHA256)
└─────────────────────────┘
          │
          ▼
┌─────────────────────────┐
│ Phase 3: Reputation     │ ──► VirusTotal, URLScan.io, Talos, AbuseIPDB, Any.Run
└─────────────────────────┘
          │
    Is Malicious?
     /        \
  [YES]       [NO] ──► Close as False Positive / Benign (Notify user)
   /
  ▼
┌─────────────────────────┐
│ Phase 4: Scoping        │ ──► M365 Message Trace / SIEM Query: Who else received it?
└─────────────────────────┘
          │
          ▼
┌─────────────────────────┐
│ Phase 5: Containment    │ ──► 1. Purge email tenant-wide (Hard Delete)
└─────────────────────────┘     2. Block IP on Perimeter Firewall / SWG
                                3. Block Domain & Sender on SEG
                                4. If clicked: Reset AD/O365 Password & Revoke Tokens
```

---

### 3. Step-by-Step Execution Guide

#### Phase 1: Header & Authentication Analysis
1. **Originating Server IP:**
   - Inspect the bottom-most non-private `Received:` header.
   - Record the sending MTA IP and resolve reverse DNS (`PTR`).
   - Query **AbuseIPDB** and **Cisco Talos** for reputation and Autonomous System Number (ASN).
2. **Email Authentication Validation:**
   - **SPF (Sender Policy Framework):** Verify if sending IP matches SPF record of envelope sender (`Return-Path`).
   - **DKIM (DomainKeys Identified Mail):** Check cryptographic signature status (`pass` vs `fail/none`).
   - **DMARC:** Check if `header.from` aligns with SPF or DKIM. An unaligned or failing DMARC indicates spoofing.
3. **Display Name & Address Spoofing:**
   - Check if the display name attempts to mimic executive staff, HR, IT, or well-known vendors (`Microsoft`, `DocuSign`, `PayPal`) while using an unrelated domain.

#### Phase 2: URL & Attachment Inspection
> **SAFETY RULE:** Never directly click links or open attachments on your host operating system. Always defang indicators immediately.

1. **Hyperlinks:**
   - Extract raw `href` destinations from HTML source.
   - Defang all strings: `http://` -> `hxxp://`, `.` -> `[.]`.
   - Submit URL to **urlscan.io** or **VirusTotal** in unauthenticated search mode.
2. **Attachments:**
   - Compute SHA-256 and MD5 hashes:
     ```bash
     sha256sum attachment.zip
     md5sum attachment.zip
     ```
   - Check hashes against VirusTotal / MalwareBazaar.
   - If novel/zero-day, detonate inside an isolated, non-persistent dynamic sandbox (e.g., Any.Run, Hybrid Analysis, or Cuckoo Sandbox).

#### Phase 3: Scoping & Threat Hunting (SIEM / M365)
Determine the blast radius across the enterprise:
1. **Microsoft 365 Exchange Online PowerShell:**
   ```powershell
   Get-MessageTrace -SenderAddress "payroll-noreply@microsoft-online-updates.xyz" -StartDate (Get-Date).AddDays(-3) -EndDate (Get-Date)
   ```
2. **SIEM (Splunk) Web Proxy Query:**
   Check if any corporate user navigated to the credential harvester:
   ```spl
   index=proxy (dest_host="*auth-office365-verify.online*" OR dest_ip="185.220.101.42")
   | stats count earliest(_time) as first_click latest(_time) as last_click by user, src_ip, dest_host, http_method, status
   ```

#### Phase 4: Containment & Remediation Actions
1. **Email Purge (Hard Delete):**
   * Use Microsoft Purview Compliance Search:
     ```powershell
     New-ComplianceSearch -Name "Purge-Phish-20241003" -ExchangeLocation All -ContentMatchQuery 'Subject:"[ACTION REQUIRED] IMMEDIATE REVIEW: Q3 Bonus Payout"'
     Start-ComplianceSearch -Identity "Purge-Phish-20241003"
     New-ComplianceSearchAction -SearchName "Purge-Phish-20241003" -Purge -PurgeType HardDelete
     ```
2. **Perimeter & Gateway Blocks:**
   * **SEG Blocklist:** Add `microsoft-online-updates.xyz` and `collector-harvest@proton.me`.
   * **Firewall / SWG:** Block destination IP `185.220.101.42` and URL domain `auth-office365-verify.online`.
3. **Identity Remediation (If User Clicked / Submitted Credentials):**
   * Force immediate Azure AD / Entra ID password reset.
   * Revoke all active refresh tokens using Microsoft Graph PowerShell:
     ```powershell
     Revoke-MgUserSignInSession -UserId "john.doe@enterprise-corp.com"
     ```
   * Enforce MFA re-registration and review recent sign-ins for anomalous Impossible Travel or foreign IP logins.

---

### 4. Severity Matrix & SLA
| Severity | Description | SLA (Initial Triage) | SLA (Containment) |
|---|---|---|---|
| **P1 - Critical** | Credential phish sent to 10+ users; confirmed password submission or active malware execution. | 15 minutes | 1 hour |
| **P2 - High** | Targeted spear-phishing email with valid payload; user received but did not interact. | 30 minutes | 2 hours |
| **P3 - Medium** | Generic bulk spam/phish caught by quarantine; no user exposure. | 2 hours | 8 hours |
| **P4 - Low** | Benign marketing email or false positive report. | 4 hours | 24 hours |
