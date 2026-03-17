# Identity Attack Paths

Markdown-heavy research briefs for high-value Microsoft identity attack paths across Microsoft Entra ID and Microsoft 365.

This repository is built as a practical defender KB: short writeups, hunt-oriented telemetry, sample KQL, containment guidance, and ATT&CK mapping for common identity-centric intrusion paths.

## What This Repo Covers

- OAuth and application-consent abuse
- Token replay and session theft
- MFA method and device registration abuse
- Privileged role escalation in Entra ID and Azure
- Service principal and non-human identity abuse
- Exchange Online mailbox rule persistence
- Conditional Access bypass opportunities and policy gaps

## Who This Is For

- Threat hunters building Microsoft identity hypotheses
- Detection engineers converting research into analytics
- Incident responders triaging cloud identity persistence
- Security teams building a lightweight internal identity-defense KB

## Brief Format

Each brief follows the same structure:

- What the technique is
- Why it works
- Telemetry to hunt
- Sample detection logic
- Containment steps
- MITRE mapping

## Quick Start

1. Pick the brief that matches the alert, hypothesis, or control gap.
2. Validate that the required Entra, Microsoft 365, and endpoint telemetry is enabled.
3. Adapt the sample KQL to your table names, watchlists, and allowlists.
4. Use the containment guidance to shape triage and response steps.

## Briefs

| Brief | Focus | Core telemetry | ATT&CK |
| --- | --- | --- | --- |
| [OAuth Consent Phishing](briefs/oauth-consent-phishing.md) | Malicious app consent and delegated access | `AuditLogs`, `SigninLogs` | `T1528` |
| [Token Theft](briefs/token-theft.md) | Replay of stolen access, refresh, or session artifacts | `SigninLogs`, `AADNonInteractiveUserSignInLogs`, endpoint telemetry | `T1528`, `T1539` |
| [MFA Device Registration Abuse](briefs/mfa-device-registration-abuse.md) | Attacker-controlled MFA method or device enrollment | `AuditLogs`, `SigninLogs` | `T1098.005`, `T1556.006` |
| [Privileged Role Escalation](briefs/privileged-role-escalation.md) | Illicit assignment or activation of high-value roles | `AuditLogs`, `AzureActivity` | `T1098.003` |
| [Service Principal Abuse](briefs/service-principal-abuse.md) | Backdooring or abusing non-human identities | `AuditLogs`, `AADServicePrincipalSignInLogs` | `T1098.001`, `T1098.003` |
| [Mailbox Rule Persistence](briefs/mailbox-rule-persistence.md) | Forwarding, hiding, and collection through mail rules | `OfficeActivity`, mailbox audit logs | `T1114.003` |
| [Conditional Access Bypass Opportunities](briefs/conditional-access-bypass-opportunities.md) | Exclusions, weak scoping, and policy-driven bypass paths | `SigninLogs`, `AuditLogs` | `T1556.009` |

## Assumed Data Sources

The examples assume Microsoft Sentinel or Log Analytics ingestion for sources such as:

- `AuditLogs`
- `SigninLogs`
- `AADNonInteractiveUserSignInLogs`
- `AADServicePrincipalSignInLogs`
- `OfficeActivity`
- `CloudAppEvents`
- `DeviceProcessEvents`
- `DeviceFileEvents`
- `AzureActivity`

Field names and table availability vary by connector and export path. Treat the KQL in this repo as starter logic that should be tuned for your tenant.

## Hunting Principles

- Control-plane changes are often the earliest high-signal indicators.
- Password resets alone rarely remove identity persistence in cloud environments.
- Non-human identities deserve the same monitoring rigor as privileged user accounts.
- Conditional Access and MFA failures are often governance problems before they are detection problems.

## Repository Layout

```text
.
├── README.md
├── LICENSE
└── briefs/
    ├── conditional-access-bypass-opportunities.md
    ├── mailbox-rule-persistence.md
    ├── mfa-device-registration-abuse.md
    ├── oauth-consent-phishing.md
    ├── privileged-role-escalation.md
    ├── service-principal-abuse.md
    └── token-theft.md
```

## Roadmap

- Add a detection index grouped by telemetry source and ATT&CK technique
- Add a shared glossary for Entra, Exchange, Graph, and Sentinel terms
- Add analyst pivot guidance for entities such as `CorrelationId`, `AppId`, `ServicePrincipalId`, and `UserPrincipalName`

## 🚧 Notes

These queries are intended for research, hunting, and detection engineering workflows. They should be tuned and validated within your environment to reduce noise and improve signal.

This repository reflects ongoing research into attacker behavior and defensive detection strategies in Microsoft cloud environments.

## 🧩 Related Work

- [ThreatPedia](https://threatpedia.wiki)
  Threat intelligence platform mapping attacker TTPs to detection logic and defensive strategies.
- [KQL Detection Lab](https://github.com/MahdiHedhli/kql-detection-lab)
  Detection engineering lab with KQL-based threat hunting queries for Microsoft Sentinel, Entra ID, and Microsoft 365 telemetry.
- [Cloud Threat Hunting Playbook](https://github.com/MahdiHedhli/cloud-threat-hunting-playbook)
  End-to-end investigation workflows for cloud and identity-focused incidents, aligned to real-world attacker behavior.
