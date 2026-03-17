# Conditional Access Bypass Opportunities

This brief treats Conditional Access bypass as a family of huntable gaps rather than a single exploit. Attackers look for exclusions, weak scoping, or recent policy changes that let a stolen or valid identity reach cloud resources without the controls defenders think are in place.

## What The Technique Is

- The attacker finds a sign-in path where Conditional Access is not applied, only applies in report-only mode, or can be satisfied from an unmanaged or attacker-controlled device.
- Common examples include broad trusted locations, excluded break-glass or service accounts used interactively, legacy authentication, app scope gaps, and weak device-registration controls.
- In some cases the attacker first modifies policy or named locations, then signs in through the newly weakened path.

## Why It Works

- Conditional Access depends on exact policy scope, supported client flows, and reliable identity and device signals.
- Exceptions accumulate over time for outages, third-party integrations, pilots, and help desk edge cases.
- A successful sign-in can still appear healthy even when the intended control never actually evaluated.
- Policy changes are legitimate administrative operations, so weakening events can hide in normal tenant maintenance.

## Telemetry To Hunt

- `SigninLogs` fields such as `ConditionalAccessStatus`, applied policy details, `ClientAppUsed`, `AuthenticationRequirement`, `DeviceDetail`, `IPAddress`, and `Location`
- `AuditLogs` where `LoggedByService == "Conditional Access"` and `Category == "Policy"`
- Activity names such as `Add Conditional Access policy`, `Update Conditional Access policy`, `Add named location`, `Update named location`, and `Update security defaults`
- Gap-analysis and sign-in reporting for successful sign-ins with no policy applied
- Sign-ins to sensitive apps from unmanaged devices or legacy client types

## Sample Detection Logic

Illustrative KQL for successful sign-ins to sensitive Microsoft 365 apps where Conditional Access was not applied or a weak client path was used:

```kusto
let sensitiveApps = dynamic([
  "Office 365 Exchange Online",
  "Microsoft Graph",
  "SharePoint Online",
  "Microsoft Teams"
]);
SigninLogs
| where TimeGenerated > ago(7d)
| where ResultType == 0
| where AppDisplayName has_any (sensitiveApps)
| where ConditionalAccessStatus == "notApplied"
   or ClientAppUsed in ("Other clients", "Exchange ActiveSync")
| extend DeviceCompliant = tostring(DeviceDetail.isCompliant),
         DeviceManaged = tostring(DeviceDetail.isManaged)
| where DeviceCompliant != "true" or DeviceManaged != "true"
| project TimeGenerated, UserPrincipalName, AppDisplayName, ClientAppUsed, IPAddress, Location, AuthenticationRequirement, ConditionalAccessStatus, DeviceDetail, CorrelationId
| order by TimeGenerated desc
```

Complementary query for recent policy or named-location changes:

```kusto
AuditLogs
| where LoggedByService == "Conditional Access"
| where Category == "Policy"
| where OperationName in (
    "Add Conditional Access policy",
    "Update Conditional Access policy",
    "Delete Conditional Access policy",
    "Add named location",
    "Update named location",
    "Delete named location",
    "Update security defaults"
)
| extend Actor = coalesce(
    tostring(InitiatedBy.user.userPrincipalName),
    tostring(InitiatedBy.app.displayName)
)
| project TimeGenerated, Actor, OperationName, TargetResources, CorrelationId
| order by TimeGenerated desc
```

Hunt upgrades:

- Maintain a watchlist of sensitive applications and identities that should never authenticate without Conditional Access.
- Treat interactive use of excluded emergency accounts as a separate high-severity signal.
- Correlate risky sign-ins with CA policy changes in the preceding 24 to 72 hours.

## Containment Steps

- Revert permissive policy changes and tighten named-location definitions.
- Disable legacy authentication paths and reduce exclusions to true emergency accounts only.
- Revoke sessions for identities that used the bypass path and review whether device registration or token replay was involved.
- Require compliant or hybrid joined devices and stronger authentication strength for sensitive resources.
- Review break-glass account governance and confirm excluded accounts are not used for daily administration.

## MITRE Mapping

- `T1556.009` - Modify Authentication Process: Conditional Access Policies
- `T1556.006` - Modify Authentication Process: Multi-Factor Authentication
- `T1078.004` - Valid Accounts: Cloud Accounts
- `T1098.005` - Account Manipulation: Device Registration

## References

- [Conditional Access and Microsoft Entra activity logs](https://learn.microsoft.com/en-us/entra/identity/monitoring-health/how-to-view-applied-conditional-access-policies)
- [Conditional Access gap analyzer workbook](https://learn.microsoft.com/en-us/entra/identity/monitoring-health/workbook-conditional-access-gap-analyzer)
- [Microsoft Entra audit log activity reference](https://learn.microsoft.com/en-us/entra/identity/monitoring-health/reference-audit-activities)
- [Require multifactor authentication for elevated sign-in risk](https://learn.microsoft.com/en-us/entra/identity/conditional-access/policy-risk-based-sign-in)
- [MITRE ATT&CK T1556.009](https://attack.mitre.org/techniques/T1556/009/)
