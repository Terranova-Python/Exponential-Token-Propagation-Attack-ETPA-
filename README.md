Exponential Token Propagation Attack (ETPA)

Author: Anthony Terrano
Attack Class: Credential Harvesting + Token Abuse / Identity Propagation
Severity (Conceptual): High
Attack Vector: Network
Privileges Required: Low (valid user account)
User Interaction: Required
Scope: Changed
Impact: Confidentiality, Integrity

Overview

The Exponential Token Propagation Attack (ETPA) is an identity-based attack pattern targeting cloud collaboration platforms that rely on OAuth authentication and trusted file-sharing workflows, such as Microsoft 365 SharePoint Online and OneDrive.

ETPA combines credential harvesting via trusted SharePoint sharing links with OAuth token issuance and persistence, allowing attackers to bypass MFA after initial credential capture and propagate access across additional accounts. Each successful interaction results in a new account takeover, enabling exponential lateral spread without malware delivery or exploitation of a traditional software vulnerability.

Key Characteristics

Uses legitimate SharePoint and OneDrive sharing links

Harvests user credentials via trusted collaboration context

MFA satisfied or bypassed through token issuance/session persistence

No malware or exploit code required

Self-propagating account compromise

Difficult to detect using IOC-based controls

Attack Flow Summary

Initial user account compromise

Malicious SharePoint file or link creation

Credential harvesting through trusted SharePoint link

OAuth token issuance and MFA bypass via session persistence

Mailbox rule manipulation to suppress detection

Permission changes enabling external sharing

Propagation to additional users

Automated repetition at scale

Attack Phases (Detailed)
Phase 1 – Initial Compromise

The attacker gains access to a single Microsoft 365 account through phishing, prior compromise, or token theft. This account is used as the initial propagation point.

Phase 2 – Infected SharePoint File Creation

Using the compromised account, the attacker creates or modifies a SharePoint or OneDrive file containing a malicious authentication lure. The lure presents itself within the context of a legitimate SharePoint sharing experience.

The file is hosted within the tenant, increasing trust and reducing user suspicion.

Phase 3 – Credential Harvesting via Trusted Link

Recipients who open the SharePoint link are presented with a Microsoft-branded authentication prompt. The user enters their Microsoft account password, believing the request to be legitimate due to the trusted sender and SharePoint domain.

The attacker captures the credentials and initiates an authenticated session.

Phase 4 – MFA Bypass via Token Issuance

Although MFA is enabled, the successful credential submission results in:

OAuth access and/or refresh token issuance

Session persistence that satisfies MFA requirements

Once issued, the attacker can authenticate using the token without repeated MFA challenges.

Phase 5 – Hidden in Plain Sight (Mailbox Rule Abuse)

The attacker creates inbox rules on the newly compromised account to:

Redirect incoming mail

Auto-delete messages

Suppress SharePoint sharing notifications and security alerts

This prevents the victim from detecting unusual activity.

Phase 6 – File Permission Changes

The attacker modifies permissions on the SharePoint file to:

Enable external sharing

Add multiple recipients

Generate secure sharing links

Phase 7 – Spray and Pray

Legitimate SharePoint sharing links (e.g., contoso.sharepoint.com/...) are sent to all contacts of the compromised user, dramatically increasing reach.

Phase 8 – Exponential Growth

Each user who enters credentials becomes compromised, restarting the attack chain at Phase 2. This creates exponential growth across users, tenants, and partner organizations.

Phase 9 – Automation and Scale

The attacker automates the above steps to compromise thousands of accounts with minimal effort and infrastructure.

Phase 10 – Post-Compromise Activity

Once sufficient scale or high-value accounts are obtained, attackers may:

Monitor email and documents

Exfiltrate sensitive data

Conduct extortion or ransomware operations

Sell access or harvested data on underground markets

Impact

Widespread account takeover

MFA bypass through token persistence

Unauthorized access to cloud data

Abuse of trusted collaboration features

Cross-tenant identity compromise

Affected Systems

Microsoft 365

SharePoint Online

OneDrive

Exchange Online

Any SaaS platform using:

OAuth authentication

External file sharing

Trusted identity workflows

Microsoft Audit Log Indicators

The following indicators map directly to Microsoft Purview / Unified Audit Log and Entra ID logs.

Initial Compromise & Credential Use

Entra ID

SignInLogs

AuthenticationDetails.authenticationMethod = Password

Followed by TokenIssued

MFA satisfied but not repeatedly challenged

New IP or device fingerprint

SharePoint File Creation / Modification

Operations

SharePointFileOperation

FileCreated

FileModified

FileModifiedExtended

Credential-Based Access Pattern

Indicators

Successful password authentication

Immediate OAuth token issuance

No interactive MFA prompts afterward

Mailbox Rule Abuse

Operations

New-InboxRule

Set-InboxRule

Red Flags

Auto-delete rules

External forwarding

Keyword-based suppression (e.g., “shared”, “Microsoft”)

SharePoint Sharing Abuse

Operations

SharePointSharingOperation

SharingLinkCreated

AddedToSharingLink

UserAddedToSecureLink

Patterns

Same file shared rapidly

External recipients

Identical sharing behavior across users

Exponential Growth Indicators

Repeated credential-based sign-ins across multiple users

Similar SharePoint links

Tight time correlation

Shared IP ranges or automation signatures

Classification

Attack Type: Credential Harvesting + Token Abuse

MITRE ATT&CK

Phishing (T1566)

Valid Accounts (T1078)

Token Impersonation

Lateral Movement via Trusted Relationships

CWE (Conceptual): Improper Authentication Token Handling

Why This Matters

ETPA demonstrates how trusted SaaS collaboration features can be weaponized to harvest credentials and silently bypass MFA at scale. The attack succeeds not by breaking security controls, but by operating entirely within them.

Disclaimer

This document describes an attack pattern, not a software vulnerability. All behaviors rely on legitimate platform features and user interaction. No product vulnerability is implied.
