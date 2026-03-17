# Privileged Role Escalation

An attacker adds a high-value Microsoft Entra role or Azure RBAC role to a controlled identity, or abuses Privileged Identity Management activation paths to obtain standing or time-bound administrative access.

## What The Technique Is

- The attacker assigns themselves or a controlled account a privileged Microsoft Entra role such as Global Administrator or Privileged Role Administrator.
- In Azure, the attacker may also grant a management-plane role such as Owner or User Access Administrator on subscriptions, management groups, or resource groups.
- Some campaigns use an intermediate role first, then escalate again once they can modify policy, credentials, or role assignments more freely.

## Why It Works

- Role management rights are often delegated more broadly than defenders realize.
- High-value assignments can be made quickly through portal, Graph, CLI, PowerShell, or PIM activation.
- Role changes are legitimate admin actions, so they can blend into real change activity unless privileged identities and service principals are tightly allowlisted.
- A successful role assignment often gives the attacker the ability to make persistence changes elsewhere in the tenant.

## Telemetry To Hunt

- `AuditLogs` with `Category == "RoleManagement"`
- Activity names such as `Add member to role`, `Add eligible member to role`, `Add scoped member to role`, and `Add member to role completed (PIM activation)`
- PIM audit activity for approvals, denials, and role setting changes
- `AzureActivity` for `Microsoft.Authorization/roleAssignments/write`
- `SigninLogs` around the same time to see where the actor authenticated from before the role change

## Sample Detection Logic

Illustrative KQL for high-value role assignments:

```kusto
let highValueRoles = dynamic([
  "Global Administrator",
  "Privileged Role Administrator",
  "Security Administrator",
  "Exchange Administrator",
  "User Administrator",
  "Application Administrator",
  "Cloud Application Administrator",
  "Owner",
  "User Access Administrator"
]);
AuditLogs
| where Category == "RoleManagement"
| where OperationName in (
    "Add member to role",
    "Add eligible member to role",
    "Add scoped member to role",
    "Add member to role completed (PIM activation)"
)
| extend Actor = coalesce(
    tostring(InitiatedBy.user.userPrincipalName),
    tostring(InitiatedBy.app.displayName)
)
| mv-expand TargetResources
| extend TargetName = tostring(TargetResources.displayName),
         ChangedProperties = tostring(TargetResources.modifiedProperties)
| where TargetName has_any (highValueRoles) or ChangedProperties has_any (highValueRoles)
| project TimeGenerated, Actor, OperationName, TargetName, ChangedProperties, CorrelationId
| order by TimeGenerated desc
```

Hunt upgrades:

- Maintain separate allowlists for PIM-approved activations and permanent assignments.
- Escalate all service principal role assignments.
- Join the event to recent app credential changes, Conditional Access changes, or admin consent events by the same actor.

## Containment Steps

- Remove the unauthorized assignment and expire active PIM elevations if relevant.
- Revoke sessions and refresh tokens for the actor and the newly privileged identity.
- Review all changes made after elevation, especially app credentials, Conditional Access, and mailbox settings.
- Rotate credentials for impacted privileged accounts and service principals.
- Tighten PIM settings, approval paths, and role assignment permissions.

## MITRE Mapping

- `T1098.003` - Account Manipulation: Additional Cloud Roles
- `T1078.004` - Valid Accounts: Cloud Accounts

## References

- [Microsoft Entra security operations for privileged accounts](https://learn.microsoft.com/en-us/entra/architecture/security-operations-privileged-accounts)
- [Microsoft Entra security operations for Privileged Identity Management](https://learn.microsoft.com/en-us/entra/architecture/security-operations-privileged-identity-management)
- [View audit report for Azure resource roles in PIM](https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/azure-pim-resource-rbac)
- [MITRE ATT&CK T1098.003](https://attack.mitre.org/techniques/T1098/003)
