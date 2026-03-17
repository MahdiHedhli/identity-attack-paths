# Service Principal Abuse

Service principal abuse centers on creating, modifying, or backdooring non-human identities so the attacker can operate through application credentials instead of an interactive user account.

## What The Technique Is

- The attacker creates a new service principal or enterprise application in the tenant.
- The attacker adds a new client secret or certificate to an existing application or service principal.
- The attacker grants the service principal privileged app permissions or assigns it Microsoft Entra or Azure RBAC roles.
- The attacker then authenticates as the service principal and performs actions through Microsoft Graph, Exchange, Azure Resource Manager, or other APIs.

## Why It Works

- Service principals do not use interactive MFA in the same way user accounts do.
- Secrets and certificates can be long-lived, especially in older automation workflows.
- Non-human identities often have weak ownership hygiene and little day-to-day monitoring.
- Service-to-service traffic blends into normal automation, especially when an attacker reuses an existing app.

## Telemetry To Hunt

- `AuditLogs` with `Category == "ApplicationManagement"`
- Activity names such as `Add service principal`, `Add service principal credentials`, `Remove service principal credentials`, `Update application - Certificates and secrets management`, and `Add app role assignment to the service principal`
- Role-management events where the target type is a service principal
- `AADServicePrincipalSignInLogs` for new or unusual app-only sign-ins, IPs, or resource targets
- Sensitive operations reporting for bursts of credential changes to applications and service principals

## Sample Detection Logic

Illustrative KQL that pivots from control-plane changes into service principal sign-in activity:

```kusto
let spChanges =
    AuditLogs
    | where Category == "ApplicationManagement"
    | where OperationName in (
        "Add service principal",
        "Add service principal credentials",
        "Update application - Certificates and secrets management",
        "Add app role assignment to the service principal"
    )
    | extend Actor = coalesce(
        tostring(InitiatedBy.user.userPrincipalName),
        tostring(InitiatedBy.app.displayName)
    )
    | mv-expand TargetResources
    | extend ServicePrincipal = tostring(TargetResources.displayName)
    | project ChangeTime = TimeGenerated, Actor, OperationName, ServicePrincipal, CorrelationId;
spChanges
| join kind=leftouter (
    AADServicePrincipalSignInLogs
    | summarize FirstSeen = min(TimeGenerated),
                LastSeen = max(TimeGenerated),
                IPs = make_set(IPAddress, 20)
      by ServicePrincipalName
) on $left.ServicePrincipal == $right.ServicePrincipalName
| project ChangeTime, Actor, OperationName, ServicePrincipal, FirstSeen, LastSeen, IPs, CorrelationId
| order by ChangeTime desc
```

Hunt upgrades:

- Alert when a new credential is added to an app that previously used certificates only or managed identity only.
- Enrich creation events with service principal provisioning metadata to separate expected Microsoft-created apps from user-created apps.
- Prioritize service principals granted Graph scopes ending in `.All` or assigned privileged roles.

## Containment Steps

- Disable the affected service principal or enterprise application if business impact allows.
- Remove unauthorized secrets, certificates, app role assignments, and role assignments.
- Rotate all remaining credentials for the app and review who owns it.
- Review recent app-only activity in Graph, Exchange, SharePoint, and Azure.
- Reduce long-lived secrets, move eligible workloads to managed identities, and limit who can manage app credentials.

## MITRE Mapping

- `T1098.001` - Account Manipulation: Additional Cloud Credentials
- `T1098.003` - Account Manipulation: Additional Cloud Roles

## References

- [Microsoft Entra audit log activity reference](https://learn.microsoft.com/en-us/entra/identity/monitoring-health/reference-audit-activities)
- [Microsoft Entra security operations for applications](https://learn.microsoft.com/en-us/entra/architecture/security-operations-applications)
- [Investigate why a service principal was created in your tenant](https://learn.microsoft.com/en-us/entra/identity/monitoring-health/howto-view-service-principal-creation-with-audit-log-properties)
- [Service principal sign-in logs](https://learn.microsoft.com/en-us/entra/identity/monitoring-health/concept-service-principal-sign-ins)
- [Sensitive operations report workbook](https://learn.microsoft.com/en-us/entra/identity/monitoring-health/workbook-sensitive-operations-report)
- [MITRE ATT&CK T1098.001](https://attack.mitre.org/techniques/T1098/001/)
