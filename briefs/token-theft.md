# Token Theft

Token theft covers the theft and replay of access tokens, refresh tokens, session cookies, or similar session artifacts so an attacker can act as a user without repeatedly presenting credentials.

## What The Technique Is

- The attacker steals bearer material from a browser, endpoint, infostealer infection, malicious extension, or adversary-in-the-middle phishing flow.
- The stolen artifact is replayed against Microsoft 365 or Graph-backed services.
- In practice this often looks like cookie theft, refresh token theft, or replay of tokens issued after a legitimate MFA challenge.

## Why It Works

- Access tokens and session cookies are meant to prove a user already authenticated, so replay can look like a valid session.
- Refresh tokens can extend attacker access by minting new access tokens after the original access token expires.
- MFA may already have been satisfied earlier in the session, so replay can bypass repeated prompts.
- Not all client flows are device-bound, and browser-based sessions remain attractive because they blend into normal user activity.

## Telemetry To Hunt

- `SigninLogs` and `AADNonInteractiveUserSignInLogs` for unusual successful sign-ins after MFA
- `RiskDetail`, `RiskLevelDuringSignIn`, and Microsoft Entra ID Protection detections such as anomalous token activity
- `DeviceProcessEvents` and `DeviceFileEvents` for access to browser cookie stores, browser profile data, or token caches
- Defender XDR alerts for infostealers, browser credential theft, or suspicious browser child processes
- Conditional Access details showing a session succeeded from an unexpected device, user agent, or geography

## Sample Detection Logic

Illustrative KQL for successful sign-ins that diverge from the user's recent IP and user-agent baseline:

```kusto
let baseline =
    SigninLogs
    | where TimeGenerated between (ago(30d) .. ago(1d))
    | where ResultType == 0
    | summarize KnownIPs = make_set(IPAddress, 200),
                KnownAgents = make_set(UserAgent, 200)
      by UserPrincipalName, AppDisplayName;
SigninLogs
| where TimeGenerated > ago(1d)
| where ResultType == 0
| where AuthenticationRequirement has "multiFactor"
| join kind=leftouter baseline on UserPrincipalName, AppDisplayName
| where isnotempty(IPAddress) and not(set_has_element(KnownIPs, IPAddress))
| where isnotempty(UserAgent) and not(set_has_element(KnownAgents, UserAgent))
| project TimeGenerated, UserPrincipalName, AppDisplayName, IPAddress, Location, UserAgent, ClientAppUsed, RiskDetail, RiskLevelDuringSignIn, CorrelationId
| order by TimeGenerated desc
```

Hunt upgrades:

- Correlate unusual sign-ins with endpoint evidence of browser cookie or token-store access.
- Prioritize sessions with `RiskDetail` or `RiskLevelDuringSignIn` populated.
- Separate browser-based sessions from native client sessions; replay patterns differ.

## Containment Steps

- Revoke all refresh tokens and active sessions for the affected user.
- Confirm compromise in Entra ID Protection if the investigation supports it.
- Isolate and investigate the source device for infostealers, malicious extensions, or browser tampering.
- Reset credentials after session revocation and review whether OAuth grants or app passwords were also abused.
- Deploy token protection, require compliant devices where possible, and use phishing-resistant MFA for high-value users.

## MITRE Mapping

- `T1528` - Steal Application Access Token
- `T1539` - Steal Web Session Cookie

## References

- [Protecting tokens in Microsoft Entra ID](https://learn.microsoft.com/en-us/entra/identity/devices/protecting-tokens-microsoft-entra-id)
- [Token protection in Microsoft Entra Conditional Access](https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-token-protection)
- [What are risk detections in Microsoft Entra ID Protection](https://learn.microsoft.com/en-us/azure/active-directory/identity-protection/concept-identity-protection-risks)
- [MITRE ATT&CK T1528](https://attack.mitre.org/techniques/T1528/)
- [MITRE ATT&CK T1539](https://attack.mitre.org/techniques/T1539/)
