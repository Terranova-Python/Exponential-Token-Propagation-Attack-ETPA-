# Exponential-Token-Propagation-Attack-ETPA-

Title: Exponential Token Propagation Attack (ETPA)
Author: Anthony Terrano
Attack Class: Token Abuse / Identity Propagation
Severity (Conceptual): High
Attack Vector: Network
Privileges Required: Low (valid user account)
User Interaction: Required
Scope: Changed
Impact: Confidentiality, Integrity

Description

An Exponential Token Propagation Attack (ETPA) is an identity-based attack pattern affecting cloud collaboration platforms that utilize OAuth authentication and external file-sharing workflows, such as Microsoft 365 SharePoint Online and OneDrive.

The attack begins with the compromise of a single user account and leverages legitimate SharePoint sharing operations and mailbox rule manipulation to distribute maliciously crafted sharing links. These links abuse trusted authentication tokens or session handling mechanisms to capture or reuse authentication tokens from recipients.

Each successful interaction results in additional account compromise, enabling the attack to self-propagate exponentially without exploiting a software vulnerability or deploying malware. The use of valid tokens, legitimate domains, and trusted sharing mechanisms allows the attack to evade traditional security controls and blend into normal user behavior.

Technical Details

The attack abuses:

OAuth access and refresh tokens

SharePoint secure sharing links

Exchange mailbox rules

Legitimate “SharingLinkCreated” and “AddedToSharingLink” operations

No memory corruption or code execution is required.

Attack Flow Summary

Attacker compromises a user account

Malicious SharePoint file or link is created

Mailbox rules suppress user awareness

File permissions are broadened for external sharing

Trusted sharing links are sent to contacts

Each recipient interaction results in additional account compromise

The process is automated for large-scale propagation

Impact

Successful exploitation may result in:

Widespread account takeover

Persistent access via token reuse

Unauthorized data access and exfiltration

Cross-tenant compromise through trusted sharing

Large-scale identity-based lateral movement

Mitigations (High-Level)

Enforce conditional access and token binding

Monitor abnormal SharePoint sharing activity

Audit mailbox rule creation

Limit external sharing permissions

Implement token lifetime and revocation controls

Exact Microsoft Audit Log Indicators (Mapped to Phases)

This section maps directly to Microsoft Purview / Unified Audit Log entries.

Phase 1 – Compromise

Common Indicators

UserLoggedIn

SignInLogs with:

Unfamiliar IPs

Impossible travel

Token-based sign-in without MFA

(Often not visible in Unified Audit Log alone; requires Entra ID logs)

Phase 2 – Infected SharePoint File Creation

Operations

SharePointFileOperation

FileCreated

FileModified

FileModifiedExtended

Key Fields

SiteUrl

SourceFileName

UserAgent (often browser-based, not automation)

ClientIP

Phase 3 – Hidden in Plain Sight (Mailbox Rule Abuse)

Operations

New-InboxRule

Set-InboxRule

Audit Log Entry

ExchangeAdmin

Operation: New-InboxRule or Set-InboxRule

Red Flags

Rules that:

Delete messages

Redirect mail externally

Match on keywords like “shared”, “access”, “security”, “Microsoft”

Phase 4 – File Permission Change

Operations

SharePointSharingOperation

SharingLinkCreated

AddedToSharingLink

UserAddedToSecureLink

Key Indicators

Repeated permission changes in short time window

External principals added

Sharing links created immediately after file creation

Phase 5 – Spray and Pray

Operations

SharePointSharingOperation

SharingLinkCreated

AddedToSharingLink

Patterns

Same file shared with:

Many recipients

External users

Same timestamp or narrow time window

Same ClientIP

Phase 6 – Exponential Growth

Correlated Indicators

Multiple users performing:

SharingLinkCreated

AddedToSharingLink

Identical or near-identical file names

Same link structure across different accounts

Repeated pattern every few minutes/hours

This is where detection should pivot from single-user alerts to behavioral correlation.

Phase 7 – Rinse and Repeat (Automation)

Indicators

High-frequency repetition of:

SharePoint sharing operations

Inbox rule creation

Same IP ranges across many users

Identical sharing behavior across accounts

Phase 8 – Post-Compromise Activity

Possible Indicators

FileAccessed

FileDownloaded

SearchQueryPerformed

Unusual data access patterns

Long-lived token activity without interactive logins

Why This Is Important

This attack:

Does not require malware

Does not exploit a software vulnerability

Uses only legitimate Microsoft 365 features

Evades traditional IOC-based detection

ETPA represents a systemic identity abuse pattern, not a bug — which is why naming and documenting it matters.
