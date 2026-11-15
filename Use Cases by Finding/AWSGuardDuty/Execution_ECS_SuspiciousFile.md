# Suspicious File - ECS

## Description
Alert generated when AWS GuardDuty identifies the finding type `Execution:ECS/SuspiciousFile`. A malicious or suspicious file associated with the ECS cluster has been identified. The alert must be reviewed by the SOC to validate its legitimacy, scope, affected resource, and potential impact.

## Objective
Detect and prioritize potential malicious, anomalous, or unauthorized activities related to ECS clusters and tasks, enabling the SOC to initiate a structured investigation, reduce operational risk, and activate containment procedures when indicators of compromise are identified.

## Logic
The detection is triggered when an AWS GuardDuty event is received with `finding.type` equal to:

`Execution:ECS/SuspiciousFile`

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
| **P3** | Medium | < 4 hours | Suspicious activity requiring investigation, potential compromise not yet confirmed, or policy violation with security implications |

## MITRE ATT&CK

- T1059 - Command and Scripting Interpreter

## Threat
- **Primary Threat:** Execution.
- **Family or Mechanism:** SuspiciousFile.
- A malicious or suspicious file associated with the ECS cluster has been identified. The analyst should consider credential compromise, malware infection, cloud service abuse, public exposure, evasion, reconnaissance, impact, or exfiltration depending on the technical context of the finding.
- **Data Sources:** AWS GuardDuty findings, ECS task/container logs, CloudTrail, VPC Flow Logs.

## Investigation Sources
- **AWS GuardDuty Finding Details:** finding ID, type, severity, title, description, firstSeen, lastSeen, count, accountId, region.
- **AWS CloudTrail:** API calls, userIdentity, sourceIPAddress, userAgent, errorCode, requestParameters, responseElements.
- **Network Logs:** VPC Flow Logs, DNS logs, ports, protocols, transferred bytes, remote IP, country, and ASN.
- **Resource Configuration:** tags, owner, policies, public exposure, security groups, ACLs, roles, or effective permissions.
- Operational validation with the resource owner, platform team, cloud team, DevOps team, or application owner.

## Sigma Rule

```yaml
title: 'AWS: Suspicious File - ECS'
id: 86d4453c-7cb7-5495-b3fd-a0a9f57d6b40
status: experimental
description: |
    This GuardDuty Malware Protection finding indicates that a file matching heuristic indicators of suspicious or
    unwanted software was found on the ECS task. Unlike a confirmed malware match, this requires analyst judgment
    to confirm whether the file is actually malicious or a legitimate, if uncommon, utility.
references:
    - 'https://docs.aws.amazon.com/guardduty/latest/ug/findings-runtime-monitoring.html'
    - 'https://docs.aws.amazon.com/guardduty/latest/ug/guardduty-attack-sequence-finding-types.html'
    - 'https://docs.aws.amazon.com/guardduty/latest/ug/compromised-ecs.html'
    - 'https://csrc.nist.gov/pubs/sp/800/61/r3/final'
    - 'https://docs.aws.amazon.com/whitepapers/latest/aws-security-incident-response-guide/welcome.html'
date: '2026-10-13'
modified: '2026-10-13'
author: 'https://github.com/aguztynbassi'
tags:
    - attack.t1059
logsource:
    category: cloud
    product: aws
    service: guardduty
detection:
    selection:
        detail.type:
            - 'Execution:ECS/SuspiciousFile'
    condition: selection
falsepositives:
    - 'A legitimate but uncommon utility, custom internal tool, or a file that merely resembles known attacker tooling (e.g., a...'
    - 'A security team''s own red-team or offensive-tooling package was deliberately placed on the resource for an approved exercise.'
level: medium
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

- A legitimate but uncommon utility, custom internal tool, or a file that merely resembles known attacker tooling (e.g., a password-recovery utility used for legitimate IT support) triggered a heuristic, not a confirmed-malicious, match.
- A security team's own red-team or offensive-tooling package was deliberately placed on the resource for an approved exercise.

### True Positives

- A file matching heuristic indicators of suspicious or potentially unwanted software was found on the ECS task, and its presence, path, or behavior has no legitimate explanation.
- The file is corroborated by other suspicious indicators on the same resource (unexpected process activity, outbound connections, other GuardDuty findings).
- The owner of the resource cannot account for the file's presence.

### True Negatives

- The file is confirmed to be an approved internal tool or a known false-positive pattern for the scanning engine, documented and safe to allow-list.

### False Negatives

- The file is sufficiently obfuscated or novel that it does not match any current heuristic pattern.
- The suspicious tool is executed directly from memory and never persisted to disk as a scannable file.

## References

- [Runtime Monitoring finding types](https://docs.aws.amazon.com/guardduty/latest/ug/findings-runtime-monitoring.html)
- [Attack sequence finding types](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty-attack-sequence-finding-types.html)
- [Remediating a potentially compromised ECS cluster](https://docs.aws.amazon.com/guardduty/latest/ug/compromised-ecs.html)
- [NIST SP 800-61r3: Incident Response Recommendations](https://csrc.nist.gov/pubs/sp/800/61/r3/final)
- [AWS Security Incident Response Guide (2023)](https://docs.aws.amazon.com/whitepapers/latest/aws-security-incident-response-guide/welcome.html)
