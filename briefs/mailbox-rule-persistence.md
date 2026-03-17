# Mailbox Rule Persistence

Mailbox rule persistence uses inbox rules, transport rules, or mailbox forwarding settings to collect, hide, or exfiltrate email long after the initial compromise.

## What The Technique Is

- The attacker creates or modifies inbox rules to forward, redirect, move, or delete mail.
- Some rules hide warning emails, MFA prompts, or security notifications by moving them out of view.
- More advanced abuse can use transport rules or mailbox-level forwarding so the victim does not need to be actively signed in.

## Why It Works

- Rules execute server-side and continue working after the initial sign-in session ends.
- Users rarely inspect their rule set unless something is visibly broken.
- External forwarding can look like routine business automation if it is not tightly governed.
- Rule changes are often investigated later than credential changes, even though they are durable persistence and collection mechanisms.

## Telemetry To Hunt

- `OfficeActivity` or Purview audit data for `New-InboxRule`, `Set-InboxRule`, `UpdateInboxRules`, `New-TransportRule`, `Set-TransportRule`, and `Set-Mailbox`
- Mailbox audit records such as `MailItemsAccessed` to understand what was read before or after the rule change
- Auto-forwarded message reporting in Exchange Online
- Sign-in telemetry around the time the rule was created or updated
- Delegate permission changes if the attacker also established mailbox-level access

## Sample Detection Logic

Illustrative KQL for suspicious forwarding or hide-and-delete behavior in Exchange audit data:

```kusto
OfficeActivity
| where OfficeWorkload == "Exchange"
| where Operation in (
    "New-InboxRule",
    "Set-InboxRule",
    "UpdateInboxRules",
    "New-TransportRule",
    "Set-TransportRule",
    "Set-Mailbox"
)
| extend ParametersText = tostring(Parameters)
| where ParametersText has_any (
    "ForwardTo",
    "ForwardAsAttachmentTo",
    "RedirectTo",
    "ForwardingSmtpAddress",
    "DeliverToMailboxAndForward",
    "DeleteMessage",
    "MoveToFolder"
)
| project TimeGenerated, UserId, Operation, ClientIP, ParametersText, ResultStatus
| order by TimeGenerated desc
```

Hunt upgrades:

- Split external forwarding from internal forwarding and treat external destinations as higher severity.
- Alert on rules that target security senders or move mail into low-visibility folders such as RSS, Archive, or custom folders.
- Correlate rule changes with sign-ins from unusual locations or impossible-travel conditions.

## Containment Steps

- Remove malicious inbox rules, transport rules, and mailbox forwarding settings.
- Review for hidden rules, delegate permissions, and mailbox-level forwarding that may not be obvious in Outlook.
- Revoke active sessions, reset credentials, and review MFA state for the mailbox owner.
- Search the exfiltration window for messages that were accessed, forwarded, or deleted.
- Disable external auto-forwarding unless there is a documented business requirement.

## MITRE Mapping

- `T1114.003` - Email Collection: Email Forwarding Rule
- `T1098.002` - Account Manipulation: Additional Email Delegate Permissions

## References

- [Use the audit log to identify Exchange inbox rules activities](https://learn.microsoft.com/en-us/purview/audit-log-search-mailbox-rules)
- [Audit log activities](https://learn.microsoft.com/en-us/purview/audit-log-activities)
- [Manage mailbox auditing](https://learn.microsoft.com/en-us/purview/audit-mailboxes)
- [Auto-forwarded messages report in Exchange Online](https://learn.microsoft.com/en-us/exchange/monitoring/mail-flow-reports/mfr-auto-forwarded-messages-report)
- [MITRE ATT&CK T1114.003](https://attack.mitre.org/techniques/T1114/003/)
