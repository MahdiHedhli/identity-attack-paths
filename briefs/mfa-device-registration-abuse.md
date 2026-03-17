# MFA Device Registration Abuse

An attacker with control of a user's credentials registers an attacker-controlled authentication method or device so future sign-ins can satisfy MFA or device-based Conditional Access requirements.

## What The Technique Is

- The attacker enrolls a new MFA method such as a phone-based method, passkey, or Windows Hello for Business credential.
- The attacker may also register a new Entra device or add ownership and usage relationships to an attacker-controlled device.
- Once registration succeeds, the new method or device becomes part of the tenant's trusted authentication or compliance path.

## Why It Works

- Self-service registration is often designed for convenience and can be abused if identity proofing is weak.
- Dormant or newly compromised accounts may be allowed to register their first strong method.
- A newly registered device or method can satisfy later sign-ins that would otherwise be blocked by MFA or device requirements.
- Registration events can be mistaken for normal onboarding noise unless they are reviewed in context.

## Telemetry To Hunt

- `AuditLogs` from the Device Registration Service and Authentication Methods categories
- Activity names such as `Register device`, `Add registered owner to device`, `Add registered users to device`, `Add Passkey (device-bound)`, `Add Windows Hello for Business credential`, `Add passwordless phone sign-in credential`, and `Add platform credential`
- `SigninLogs` showing successful sign-ins from a newly registered device or newly seen device ID
- Conditional Access details showing a new device immediately satisfying device-based controls
- Temporary Access Pass issuance or recovery activity, if used in the environment

## Sample Detection Logic

Illustrative KQL for recent device or strong-auth registration events:

```kusto
AuditLogs
| where OperationName in (
    "Register device",
    "Add registered owner to device",
    "Add registered users to device",
    "Add Passkey (device-bound)",
    "Add Windows Hello for Business credential",
    "Add passwordless phone sign-in credential",
    "Add platform credential"
)
| extend Actor = coalesce(
    tostring(InitiatedBy.user.userPrincipalName),
    tostring(InitiatedBy.app.displayName)
)
| mv-expand TargetResources
| extend TargetName = tostring(TargetResources.displayName)
| project TimeGenerated, Actor, OperationName, TargetName, AdditionalDetails, CorrelationId
| order by TimeGenerated desc
```

Hunt upgrades:

- Alert when registration happens from a new country, new ASN, or outside local business hours.
- Correlate the registration event with the next successful sign-in from that user within 24 hours.
- Separate known device-enrollment workflows from one-off user-driven events.

## Containment Steps

- Remove the attacker-controlled authentication method and unregister the rogue device.
- Revoke sessions and refresh tokens for the affected identity.
- Reset the password after revocation and review whether self-service recovery, TAP, or help desk workflows were abused.
- Review Conditional Access outcomes to confirm whether the rogue device or method satisfied policy.
- Tighten registration controls, limit who can self-enroll, and require stronger proofing for first-time registrations.

## MITRE Mapping

- `T1098.005` - Account Manipulation: Device Registration
- `T1556.006` - Modify Authentication Process: Multi-Factor Authentication

## References

- [Microsoft Entra audit log activity reference](https://learn.microsoft.com/en-us/entra/identity/monitoring-health/reference-audit-activities)
- [MITRE ATT&CK T1098.005](https://attack.mitre.org/techniques/T1098/005/)
- [MITRE detection strategy for suspicious device registration](https://attack.mitre.org/detectionstrategies/DET0036/)
- [MITRE ATT&CK T1556.006](https://attack.mitre.org/techniques/T1556/006/)
