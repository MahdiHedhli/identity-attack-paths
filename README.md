# Identity Attack Paths

![Status](https://img.shields.io/badge/status-active%20research-0b7285)
![Focus](https://img.shields.io/badge/focus-Entra%20ID%20%7C%20M365%20%7C%20Azure-1d3557)
![Content](https://img.shields.io/badge/content-mini%20briefs%20%2B%20KQL-6c584c)
![Maintained](https://img.shields.io/badge/updated-2026--03--17-588157)

> A research-focused repository documenting modern identity-based attack techniques across Microsoft cloud environments, including Microsoft Entra ID, Microsoft 365, and Azure.

This project explores how attackers exploit identity systems for initial access, persistence, privilege escalation, and lateral movement, with a strong emphasis on detection and defensive visibility.

## 🧠 Why Identity?

Identity is the control plane of modern cloud environments. Attackers increasingly target identity systems to bypass traditional defenses, maintain persistence, and escalate privileges without triggering conventional alerts.

This repository is written as a practical defender KB: short research briefs, hunt-oriented telemetry, sample KQL, containment guidance, and MITRE ATT&CK mapping for common identity-centric abuse paths.

## ⚡ Quick Start

| If you are researching... | Start here |
| --- | --- |
| Malicious app consent, suspicious enterprise apps, or delegated abuse | [OAuth Consent Phishing](briefs/oauth-consent-phishing.md) |
| Token replay, unusual successful sign-ins, or session theft | [Token Theft](briefs/token-theft.md) |
| New MFA methods, rogue device enrollment, or suspicious registration events | [MFA Device Registration Abuse](briefs/mfa-device-registration-abuse.md) |
| High-risk role grants, PIM activation abuse, or cloud privilege escalation | [Privileged Role Escalation](briefs/privileged-role-escalation.md) |
| App-only authentication drift, secret injection, or non-human identity misuse | [Service Principal Abuse](briefs/service-principal-abuse.md) |
| Mail forwarding, hidden rules, or persistence in Exchange Online | [Mailbox Rule Persistence](briefs/mailbox-rule-persistence.md) |
| Conditional Access exclusions, weak policy scope, or bypass paths | [Conditional Access Bypass Opportunities](briefs/conditional-access-bypass-opportunities.md) |

## 🔍 What This Repo Covers

Across the repo, the research is organized around:

- Technique overviews and likely abuse patterns
- Required access or preconditions defenders should care about
- Telemetry and logs to monitor
- Detection opportunities with KQL or SIEM starter logic
- Containment, mitigation, and hardening guidance
- MITRE ATT&CK mapping for fast operational context

## ⚔️ Attack Paths In Scope

- OAuth consent phishing and malicious app registration
- Service principal abuse and credential injection
- Token theft and replay attacks
- MFA device registration and bypass techniques
- Privileged role escalation in Entra ID
- Mailbox rule persistence and data exfiltration paths
- Conditional Access bypass scenarios

## 📘 Research Briefs

| Brief | Focus | Core telemetry | ATT&CK |
| --- | --- | --- | --- |
| [OAuth Consent Phishing](briefs/oauth-consent-phishing.md) | Malicious app consent and delegated access | `AuditLogs`, `SigninLogs` | `T1528` |
| [Token Theft](briefs/token-theft.md) | Replay of stolen access, refresh, or session artifacts | `SigninLogs`, `AADNonInteractiveUserSignInLogs`, endpoint telemetry | `T1528`, `T1539` |
| [MFA Device Registration Abuse](briefs/mfa-device-registration-abuse.md) | Attacker-controlled MFA method or device enrollment | `AuditLogs`, `SigninLogs` | `T1098.005`, `T1556.006` |
| [Privileged Role Escalation](briefs/privileged-role-escalation.md) | Illicit assignment or activation of high-value roles | `AuditLogs`, `AzureActivity` | `T1098.003` |
| [Service Principal Abuse](briefs/service-principal-abuse.md) | Backdooring or abusing non-human identities | `AuditLogs`, `AADServicePrincipalSignInLogs` | `T1098.001`, `T1098.003` |
| [Mailbox Rule Persistence](briefs/mailbox-rule-persistence.md) | Forwarding, hiding, and collection through mail rules | `OfficeActivity`, mailbox audit logs | `T1114.003` |
| [Conditional Access Bypass Opportunities](briefs/conditional-access-bypass-opportunities.md) | Exclusions, weak scoping, and policy-driven bypass paths | `SigninLogs`, `AuditLogs` | `T1556.009` |

## 👥 Who This Repo Is For

- Threat hunters building Microsoft identity hypotheses
- Detection engineers converting research into analytics
- Incident responders triaging cloud identity persistence
- Security teams building a lightweight internal identity-defense knowledge base

## 📡 Telemetry Focus

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

## 🛡️ Working Principles

- Control-plane changes are often the earliest high-signal indicators.
- Password resets alone rarely remove identity persistence in cloud environments.
- Non-human identities deserve the same monitoring rigor as privileged user accounts.
- KQL is written to be reused and tuned, not copied blindly.
- Conditional Access and MFA failures are often governance problems before they are detection problems.

## 📂 Repository Layout

| Path | What it contains |
| --- | --- |
| `briefs/` | Identity attack path research briefs with hunt logic, containment guidance, and ATT&CK mapping |
| `README.md` | Landing page, navigation, and repo context |
| `.gitignore` | Local hygiene for env files, common secret material, and macOS artifacts |
| `LICENSE` | Repository licensing information |

## 🎯 Goal

To provide defenders with a clear understanding of how identity attacks actually work in practice, and how to detect and mitigate them using available telemetry.

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

## 🛣️ Roadmap

- Add a detection index grouped by telemetry source and ATT&CK technique
- Add a shared glossary for Entra, Exchange, Graph, and Sentinel terms
- Add analyst pivot guidance for entities such as `CorrelationId`, `AppId`, `ServicePrincipalId`, and `UserPrincipalName`
