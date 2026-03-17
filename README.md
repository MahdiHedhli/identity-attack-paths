# Identity Attack Paths

Mini research briefs for common Microsoft identity attack paths in Microsoft Entra ID and Microsoft 365. The focus is hunting, triage, and containment rather than full incident response playbooks.

## Scope

- Microsoft Entra ID identities, applications, service principals, and Conditional Access
- Exchange Online mailbox persistence and forwarding abuse
- Detection-first writeups for analysts, threat hunters, and defenders building a KB

## How To Use This Repo

1. Start with the brief that matches the hypothesis or alert.
2. Confirm the required telemetry is enabled in your tenant.
3. Adapt the sample KQL to your own table names, allowlists, and high-value identities.
4. Promote the logic into analytics, workbooks, or investigation checklists.

## Assumed Log Sources

The examples assume Microsoft Sentinel or Log Analytics connectors that expose data in tables such as:

- `AuditLogs`
- `SigninLogs`
- `AADNonInteractiveUserSignInLogs`
- `AADServicePrincipalSignInLogs`
- `OfficeActivity`
- `CloudAppEvents`
- `DeviceProcessEvents`
- `DeviceFileEvents`

Some fields and table names vary by connector and export method. Treat the queries as starter logic, not copy-paste detections.

## Briefs

| Brief | Primary focus | Core telemetry | Primary ATT&CK |
| --- | --- | --- | --- |
| [OAuth Consent Phishing](briefs/oauth-consent-phishing.md) | Malicious app consent and delegated access | `AuditLogs`, `SigninLogs` | `T1528` |
| [Token Theft](briefs/token-theft.md) | Replay of stolen access, refresh, or session tokens | `SigninLogs`, `AADNonInteractiveUserSignInLogs`, endpoint telemetry | `T1528`, `T1539` |
| [MFA Device Registration Abuse](briefs/mfa-device-registration-abuse.md) | Registering attacker-controlled methods or devices | `AuditLogs`, `SigninLogs` | `T1098.005` |
| [Privileged Role Escalation](briefs/privileged-role-escalation.md) | Adding high-value Entra or Azure roles | `AuditLogs`, `AzureActivity` | `T1098.003` |
| [Service Principal Abuse](briefs/service-principal-abuse.md) | Backdooring or abusing non-human identities | `AuditLogs`, `AADServicePrincipalSignInLogs` | `T1098.001` |
| [Mailbox Rule Persistence](briefs/mailbox-rule-persistence.md) | Hidden forwarding, redirect, or delete rules | `OfficeActivity`, mailbox audit logs | `T1114.003` |
| [Conditional Access Bypass Opportunities](briefs/conditional-access-bypass-opportunities.md) | Policy gaps, exclusions, and change-driven bypass paths | `SigninLogs`, `AuditLogs` | `T1556.009` |

## Common Hunting Themes

- A benign-looking control-plane change is often the earliest signal. Audit events usually appear before follow-on abuse.
- Persistence in Microsoft identity systems often survives password resets unless the app grant, token, device, or role assignment is also removed.
- Service principals, delegated grants, and mailbox rules are attractive because they create durable access with low user friction.
- Conditional Access and MFA abuse are usually change-management problems as much as authentication problems.

## Suggested Next Additions

- A shared glossary for Entra, Exchange, and Graph terms
- A detection index grouped by table and ATT&CK technique
- An investigation checklist for cross-brief pivots such as `CorrelationId`, `AppId`, `ServicePrincipalId`, and `UserPrincipalName`
