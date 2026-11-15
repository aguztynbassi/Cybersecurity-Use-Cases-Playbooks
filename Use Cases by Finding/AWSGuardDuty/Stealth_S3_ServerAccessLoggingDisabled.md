# S3 Server Access Logging Disabled

## Description
Alert generated when AWS GuardDuty identifies the finding type `Stealth:S3/ServerAccessLoggingDisabled`. Logging has been disabled or reduced in connection with the S3 bucket, which may indicate a defense-evasion attempt. The alert must be reviewed by the SOC to validate its legitimacy, scope, affected resource, and potential impact.

## Objective
Detect and prioritize potential malicious, anomalous, or unauthorized activities related to S3 buckets, enabling the SOC to initiate a structured investigation, reduce operational risk, and activate containment procedures when indicators of compromise are identified.

## Logic
The detection is triggered when an AWS GuardDuty event is received with `finding.type` equal to:

`Stealth:S3/ServerAccessLoggingDisabled`

The prioritization logic should consider severity, asset criticality, event recurrence, network source/destination, involved identity, AWS region, AWS account, and correlated activity in supporting data sources.

Patterns or conditions to validate:

- Exact match of `finding.type` with the use case.
- GuardDuty severity equal to or above the SOC-defined threshold.
- Production, critical, publicly exposed, or sensitive-data resource.
- IP address, domain, user, role, access key, pod, function, or bucket not recognized by the resource owner.
- CloudTrail events, VPC Flow Logs, DNS logs, service logs, or runtime activity occurring close to the first or last observed event.
- Sensitive changes following the event, such as permissions, policies, credentials, logging configurations, public exposure, command execution, or data access.

## Severity Matrix

| Priority | Label | Response Time | Description |
|-----------|--------|---------------|-------------|
| **P2** | High | < 1 hour | Confirmed compromise with containment needed, lateral movement detected, or privileged credential abuse |

## MITRE ATT&CK

- T1562.008 - Disable or Modify Cloud Logs

## Threat
- **Primary Threat:** Stealth.
- **Family or Mechanism:** ServerAccessLoggingDisabled.
- Logging has been disabled or reduced in connection with the S3 bucket, which may indicate a defense-evasion attempt. The analyst should consider credential compromise, malware infection, cloud service abuse, public exposure, evasion, reconnaissance, impact, or exfiltration depending on the technical context of the finding.
- **Data Sources:** AWS GuardDuty findings, CloudTrail S3 Data Events, S3 Server Access Logs, bucket policy/ACL configuration.

## Investigation Sources
- **AWS GuardDuty Finding Details:** finding ID, type, severity, title, description, firstSeen, lastSeen, count, accountId, region.
- **AWS CloudTrail:** API calls, userIdentity, sourceIPAddress, userAgent, errorCode, requestParameters, responseElements.
- **Network Logs:** VPC Flow Logs, DNS logs, ports, protocols, transferred bytes, remote IP, country, and ASN.
- **Resource Configuration:** tags, owner, policies, public exposure, security groups, ACLs, roles, or effective permissions.
- Operational validation with the resource owner, platform team, cloud team, DevOps team, or application owner.

## Sigma Rule

```yaml
title: 'AWS: S3 Server Access Logging Disabled'
id: 21ba9f04-25e7-549f-aaad-56ecf09fbb82
status: experimental
description: |
    This GuardDuty finding indicates that S3 server access logging was disabled. Disabling logging is a classic
    defense-evasion technique used by attackers to operate without leaving an audit trail, and should be treated
    as a high-priority event requiring immediate confirmation with the resource owner.
references:
    - 'https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-s3.html'
    - 'https://docs.aws.amazon.com/guardduty/latest/ug/compromised-s3.html'
    - 'https://csrc.nist.gov/pubs/sp/800/61/r3/final'
    - 'https://docs.aws.amazon.com/whitepapers/latest/aws-security-incident-response-guide/welcome.html'
date: '2026-10-13'
modified: '2026-10-13'
author: 'https://github.com/aguztynbassi'
tags:
    - attack.t1562.008
logsource:
    category: cloud
    product: aws
    service: guardduty
detection:
    selection:
        detail.type:
            - 'Stealth:S3/ServerAccessLoggingDisabled'
    condition: selection
falsepositives:
    - 'A platform or data-governance team intentionally disabled S3 server access logging as part of an approved cost-optimization or...'
    - 'Logging was migrated to a different, equally valid destination (e.g., a new trail or a centralized logging account) and the...'
level: high
```

## Investigation

Mandatory 5W Questions:

- **Who:** Which AWS account, identity, user, role, access key, workload, pod, bucket, instance, function, or database is involved?
- **What:** What action was observed, and what resource was affected? Was there access, execution, configuration change, network communication, or an authentication attempt?
- **When:** When did the first and last observations occur? Did the activity take place outside expected business hours or near other changes?
- **Where:** From which IP address, country, ASN, AWS region, VPC, subnet, namespace, or service did the activity originate?
- **Why:** Is there an operational justification, approved automation, authorized security testing activity, or planned change that explains the event?

## Detailed Checklist for Analysts Reviewing the Alert

- `Finding ID`, `finding type`, `severity`, `account`, `region`, and affected resource.
- Involved identity: `userName`, `role`, `accessKeyId`, `service account`, task role, or execution role.
- `Source` and `destination IPs`, `domain`, reputation score, `country`, `ASN`, `ports`, `protocols`, and traffic volume.
- First and last observed event, frequency, `service.count` value, and recurrence within the analysis period.
- Sensitive actions such as IAM changes, bucket policy modifications, security group updates, CloudTrail logging changes, command execution, and access to secrets or data.
- Relationship with other GuardDuty findings, SIEM alerts, EDR detections, Security Hub findings, or existing tickets.
- Confirmation with the owner regarding expected activity, authorized automation, controlled testing, or unknown behavior.

## Evidence for Determination

### False Positives

- A platform or data-governance team intentionally disabled S3 server access logging as part of an approved cost-optimization or architecture change, with change-management records on file.
- Logging was migrated to a different, equally valid destination (e.g., a new trail or a centralized logging account) and the disablement of the old configuration is expected.

### True Positives

- S3 server access logging was disabled by an identity with no administrative justification for managing logging configuration, immediately before or after other suspicious activity.
- The disablement is followed by activity that would otherwise have been captured in detail by the disabled logs (e.g., data access, configuration changes).
- No corresponding change ticket, deployment record, or administrator acknowledgment exists for the change.

### True Negatives

- The change is tied to an approved change ticket and performed by a known platform/security administrator.

### False Negatives

- The actor disables logging only for a subset of the scope (a single trail, one bucket) while leaving other logging intact, so the overall blind spot is only partially visible to the SOC.
- Logs continue to be delivered but are deleted or tampered with after the fact, a related but differently-detected technique.

## References

- [S3 Protection finding types](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-s3.html)
- [Remediating a potentially compromised S3 bucket](https://docs.aws.amazon.com/guardduty/latest/ug/compromised-s3.html)
- [NIST SP 800-61r3: Incident Response Recommendations](https://csrc.nist.gov/pubs/sp/800/61/r3/final)
- [AWS Security Incident Response Guide (2023)](https://docs.aws.amazon.com/whitepapers/latest/aws-security-incident-response-guide/welcome.html)
