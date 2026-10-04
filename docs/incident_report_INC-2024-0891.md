# Security Operations Center (SOC) - Incident Investigation Report

| Incident ID | Severity | Status | Incident Date | Analyst | Ticket Type |
|---|---|---|---|---|---|
| **INC-2024-0891** | **P2 - High** | **RESOLVED / CLOSED** | 2024-10-03 08:35 UTC | SOC Tier 1 Analyst | Phishing / Credential Harvesting |

---

### 1. Executive Summary
On October 3, 2024, at 08:22 EDT, a corporate employee (`john.doe@enterprise-corp.com`) submitted a suspicious email via the Outlook PhishAlarm add-in. The email claimed to originate from "HR Payroll Department" demanding urgent direct deposit verification for a "Q3 Corporate Bonus" with an aggressive deadline. 

Automated and manual SOC triage confirmed that the email was an external spear-phishing attack designed to harvest corporate Microsoft 365 credentials and deliver a malicious HTML payload. The sending infrastructure failed SPF, DKIM, and DMARC checks. Within 45 minutes of detection, the email was purged from all 4 recipient mailboxes across the organization, the sending IP and hosting domain were blocked at the firewall and web proxy, and no credential compromise occurred.

---

### 2. Threat Classification & MITRE ATT&CK Mapping

| Tactic | Technique ID | Technique Name | Evidence / Observation |
|---|---|---|---|
| **Initial Access** | `T1566.002` | Spearphishing Link | Email contained an embedded link disguised as a corporate M365 authentication portal. |
| **Initial Access** | `T1566.001` | Spearphishing Attachment | Email delivered `Q3_Bonus_DirectDeposit_Form.html.zip` containing an obfuscated credential harvester. |
| **Defense Evasion** | `T1036.005` | Match Legitimate Name | Display name set to "HR Payroll Department" while using unauthorized external domain. |
| **Credential Access** | `T1056.003` | Web-based Credential Harvesting | Target phishing page captured user email, corporate password, and session tokens. |

---

### 3. Technical Evidence & Analysis

#### A. Header & Authentication Breakdown
* **From:** `HR Payroll Department <payroll-noreply@microsoft-online-updates.xyz>`
* **Reply-To:** `HR Helpdesk Support <collector-harvest@proton.me>` *(Domain discrepancy)*
* **Return-Path:** `bounce-attacker@mail-relay-vps.ru`
* **Originating IP:** `185.220.101.42` (Hosting Provider: Petersburg Internet Network LLC, ASN 44050, Russia)
* **X-Mailer:** `PHPMailer 6.5.0`

**Authentication Status:**
* **SPF:** `FAIL` — Sending server `185.220.101.42` is not authorized in SPF record for `mail-relay-vps.ru`.
* **DKIM:** `FAIL` — Cryptographic signature body hash mismatch or invalid selector.
* **DMARC:** `FAIL` — Sender domain `microsoft-online-updates.xyz` does not align with envelope domain.

#### B. Extracted Indicators of Compromise (IoCs)

| IoC Type | Value (Defanged) | Context / Classification |
|---|---|---|
| **IPv4** | `185[.]220.101[.]42` | Attack MTA / Mail relay server |
| **Domain** | `microsoft-online-updates[.]xyz` | Sender spoof domain |
| **Domain** | `auth-office365-verify[.]online` | Phishing credential landing host |
| **URL** | `hxxps://auth-office365-verify[.]online/login[.]php?session_id=8923a1ef90&email=john[.]doe@enterprise-corp[.]com` | Credential phishing landing page |
| **File Name** | `Q3_Bonus_DirectDeposit_Form.html.zip` | Malicious email attachment (ZIP containing HTML form) |
| **File Hash (SHA256)**| `2ad72858d85581963e10c391fca6da0e9fa552868c293110d7e840b172e3b4cd` | Attachment SHA-256 |
| **File Hash (MD5)** | `fa9224cc6c58ba0150ee251ff791b6a4` | Attachment MD5 |

---

### 4. Incident Timeline

| Time (EDT) | Event Description |
|---|---|
| **08:14:58** | Phishing email delivered to inbound mail gateway `mx1.enterprise-corp.com`. |
| **08:15:02** | Email delivered to inbox of `john.doe@enterprise-corp.com` (Palo Alto SEG did not drop due to permissive DMARC policy `p=none`). |
| **08:22:15** | User John Doe reports email using PhishAlarm button. |
| **08:25:30** | Ticket `INC-2024-0891` created; assigned to Tier 1 SOC Analyst. |
| **08:31:10** | Triage script executed against `.eml`; confirmed malicious indicators and SPF/DKIM failures. |
| **08:35:00** | M365 Message Trace executed. Identified 3 additional recipients in Finance: `sarah.c@`, `mike.t@`, `kevin.l@`. |
| **08:42:00** | SIEM proxy query run: Verified **0 outbound clicks** across all 4 recipients. |
| **08:48:00** | Microsoft Purview compliance search executed; hard-deleted email from all 4 mailboxes. |
| **08:55:00** | Block rules implemented on Palo Alto Firewall and Cisco Umbrella SWG. |
| **09:10:00** | Case closed; user thanked for reporting. |

---

### 5. Containment & Remediation Actions Taken

1. **Email Purge:** Successfully removed the phishing email from all recipient inboxes before any user executed the link or unzipped the attachment.
2. **Perimeter Firewall Block:** Added `185.220.101.42` to the edge blocklist (Drop all traffic).
3. **DNS / Secure Web Gateway:** Added `auth-office365-verify.online` and `microsoft-online-updates.xyz` to Cisco Umbrella custom block category (Sinkholed).
4. **Email Security Gateway (SEG):** Added sender domain and `collector-harvest@proton.me` to tenant-wide transport quarantine.
5. **User Communication:** Sent confirmation email to `john.doe@enterprise-corp.com` acknowledging report and commending adherence to security awareness policy.

---

### 6. Lessons Learned & Recommendations
* **Root Cause:** Inbound SEG was set to honor external sender DMARC `p=none` without quarantining unauthenticated external emails.
* **Recommendation 1:** Configure SEG inbound policy to automatically quarantine or flag external emails that fail both SPF and DKIM regardless of the sender's DMARC policy.
* **Recommendation 2:** Enable automated external sender disclaimer banners (`[EXTERNAL EMAIL]`) across Microsoft 365 Exchange Online to visually warn employees of outside correspondence.
