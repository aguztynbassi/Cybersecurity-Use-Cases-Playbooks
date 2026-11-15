# Suspicious Shell Created - Runtime

## Description
Alert generated when AWS GuardDuty identifies the finding type `Execution:Runtime/SuspiciousShellCreated`. Suspicious or unexpected activity associated with the monitored runtime workload has been detected. The alert must be reviewed by the SOC to validate its legitimacy, scope, affected resource, and potential impact.

## Objective
Detect and prioritize potential malicious, anomalous, or unauthorized activities related to workloads monitored by the GuardDuty Runtime Monitoring agent (EC2, ECS, or EKS), enabling the SOC to initiate a structured investigation, reduce operational risk, and activate containment procedures when indicators of compromise are identified.

## Logic
The detection is triggered when an AWS GuardDuty event is received with `finding.type` equal to:

`Execution:Runtime/SuspiciousShellCreated`

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
- **Family or Mechanism:** SuspiciousShellCreated.
- Suspicious or unexpected activity associated with the monitored runtime workload has been detected. The analyst should consider credential compromise, malware infection, cloud service abuse, public exposure, evasion, reconnaissance, impact, or exfiltration depending on the technical context of the finding.
- **Data Sources:** AWS GuardDuty Runtime Monitoring, host/container telemetry, VPC Flow Logs, CloudTrail.

## Investigation Sources
- **AWS GuardDuty Finding Details:** finding ID, type, severity, title, description, firstSeen, lastSeen, count, accountId, region.
- **AWS CloudTrail:** API calls, userIdentity, sourceIPAddress, userAgent, errorCode, requestParameters, responseElements.
- **Network Logs:** VPC Flow Logs, DNS logs, ports, protocols, transferred bytes, remote IP, country, and ASN.
- **Resource Configuration:** tags, owner, policies, public exposure, security groups, ACLs, roles, or effective permissions.
- Operational validation with the resource owner, platform team, cloud team, DevOps team, or application owner.

## Sigma Rule

```yaml
title: 'AWS: Suspicious Shell Created - Runtime'
id: 7443ebe1-87aa-55d8-88d1-25d3375ccefc
status: experimental
description: |
    This GuardDuty Runtime Monitoring finding indicates that an unexpected shell process was created, typically
    spawned by a parent process (such as a web server or application process) that would not normally launch an
    interactive shell. This is a common indicator of successful remote code execution against the application.
references:
    - 'https://docs.aws.amazon.com/guardduty/latest/ug/findings-runtime-monitoring.html'
    - 'https://docs.aws.amazon.com/guardduty/latest/ug/guardduty-remediate-runtime-monitoring.html'
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
            - 'Execution:Runtime/SuspiciousShellCreated'
    condition: selection
falsepositives:
    - 'A legitimate administrator opened an interactive shell via an approved method (SSM Session Manager, approved SSH bastion) for...'
    - 'A CI/CD step or entrypoint script intentionally spawns a shell as part of its normal, approved build/test process.'
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

- A legitimate administrator opened an interactive shell via an approved method (SSM Session Manager, approved SSH bastion) for routine troubleshooting.
- A CI/CD step or entrypoint script intentionally spawns a shell as part of its normal, approved build/test process.

### True Positives

- A shell process was spawned by a parent process that would not normally spawn an interactive shell (e.g., a web server process, a database engine, or a container's main application process), consistent with command injection or a web-shell being triggered.
- The shell session executes reconnaissance or credential-access commands rather than expected application logic.
- The spawning event correlates with a known application vulnerability or a recent suspicious inbound request.

### True Negatives

- The shell is confirmed to be part of an approved operational or CI/CD process.

### False Negatives

- The attacker avoids spawning a traditional interactive shell altogether, instead executing commands directly through an application's own scripting/eval capability (e.g., a web shell that calls OS functions natively rather than forking `/bin/sh`).
- The shell is spawned briefly and exits quickly, limiting the window for detection.

## References

- [Runtime Monitoring finding types](https://docs.aws.amazon.com/guardduty/latest/ug/findings-runtime-monitoring.html)
- [Remediating Runtime Monitoring findings](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty-remediate-runtime-monitoring.html)
- [NIST SP 800-61r3: Incident Response Recommendations](https://csrc.nist.gov/pubs/sp/800/61/r3/final)
- [AWS Security Incident Response Guide (2023)](https://docs.aws.amazon.com/whitepapers/latest/aws-security-incident-response-guide/welcome.html)
