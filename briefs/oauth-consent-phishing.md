# OAuth Consent Phishing

An attacker registers or controls an application, tricks a user or admin into granting consent, and then uses the resulting delegated or app permissions to access Microsoft 365 data through APIs such as Microsoft Graph.

## What The Technique Is

- The attacker presents a malicious or lookalike app that requests OAuth permissions to mail, files, contacts, Teams data, or directory data.
- A user or admin approves the request, creating a delegated permission grant or app role assignment.
- The attacker then uses the granted access token or refresh token to interact with Microsoft 365 resources without needing the user's password again.

## Why It Works

- The Microsoft sign-in and consent experience looks trusted, so users often focus on branding instead of permissions.
- Many tenants still allow broad user consent or allow admins to grant high-impact permissions without a formal approval workflow.
- Password resets and MFA prompts do not remove the malicious app relationship by themselves; the consent grant persists until it is revoked.
- Legitimate SaaS integrations make new app consent events look normal unless defenders maintain an allowlist.

## Telemetry To Hunt

- `AuditLogs` with `Category == "ApplicationManagement"`
- Activity names such as `Consent to application`, `Add delegated permission grant`, `Add app role assignment to the service principal`, and `Add service principal`
- `SigninLogs` showing unusual access to Graph, Exchange Online, SharePoint Online, or Teams soon after a consent event
- Defender XDR or Cloud App telemetry showing API-heavy access by a recently consented app
- App metadata such as publisher verification, redirect URIs, first-seen time, and owner tenant

## Sample Detection Logic

Illustrative KQL for Sentinel or Log Analytics:

```kusto
let riskyScopes = dynamic([
  "offline_access",
  "Mail.Read",
  "Mail.ReadWrite",
  "Mail.Send",
  "Files.Read.All",
  "Files.ReadWrite.All",
  "User.Read.All",
  "Directory.Read.All",
  "Directory.ReadWrite.All"
]);
AuditLogs
| where Category == "ApplicationManagement"
| where OperationName in (
    "Consent to application",
    "Add delegated permission grant",
    "Add app role assignment to the service principal",
    "Add service principal"
)
| extend Actor = coalesce(
    tostring(InitiatedBy.user.userPrincipalName),
    tostring(InitiatedBy.app.displayName)
)
| mv-expand TargetResources
| extend AppName = tostring(TargetResources.displayName),
         ChangedProperties = tostring(TargetResources.modifiedProperties)
| where OperationName == "Consent to application" or ChangedProperties has_any (riskyScopes)
| project TimeGenerated, Actor, OperationName, AppName, ChangedProperties, CorrelationId
| order by TimeGenerated desc
```

Hunt upgrades:

- Maintain an allowlist of approved app IDs, verified publishers, and known redirect URIs.
- Alert when a consent event is followed by API-heavy access from a new geography, tenant, or ASN.
- Treat admin consent to broad scopes as high severity unless change-managed.

## Containment Steps

- Revoke the delegated permission grant or app role assignment.
- Disable the malicious enterprise application or service principal and remove any added credentials.
- Revoke user sessions and refresh tokens for affected users.
- Review accessed resources in Exchange Online, SharePoint, OneDrive, and Teams for post-consent activity.
- Restrict user consent, require admin approval workflows, and prefer verified publishers.

## MITRE Mapping

- `T1528` - Steal Application Access Token
- `T1566.002` - Phishing: Spearphishing Link

## References

- [Detect and remediate illicit consent grants](https://learn.microsoft.com/en-us/defender-office-365/detect-and-remediate-illicit-consent-grants)
- [View activity logs of application permissions](https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/app-perms-audit-logs)
- [Microsoft Entra audit log activity reference](https://learn.microsoft.com/en-us/entra/identity/monitoring-health/reference-audit-activities)
- [MITRE ATT&CK T1528](https://attack.mitre.org/techniques/T1528/)
