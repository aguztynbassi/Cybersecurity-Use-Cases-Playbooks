# Suspicious Tool - Runtime

## Description
Alert generated when AWS GuardDuty identifies the finding type `Execution:Runtime/SuspiciousTool`. Suspicious or unexpected activity associated with the monitored runtime workload has been detected. The alert must be reviewed by the SOC to validate its legitimacy, scope, affected resource, and potential impact.

## Objective
Detect and prioritize potential malicious, anomalous, or unauthorized activities related to workloads monitored by the GuardDuty Runtime Monitoring agent (EC2, ECS, or EKS), enabling the SOC to initiate a structured investigation, reduce operational risk, and activate containment procedures when indicators of compromise are identified.

## Logic
The detection is triggered when an AWS GuardDuty event is received with `finding.type` equal to:

`Execution:Runtime/SuspiciousTool`

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
- **Family or Mechanism:** SuspiciousTool.
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
title: 'AWS: Suspicious Tool - Runtime'
id: 9d9eeb8b-6773-565f-bc77-7205dce5681b
status: experimental
description: |
    This GuardDuty Runtime Monitoring finding indicates that a known offensive-security or dual-use tool was
    executed on the workload. While such tools are sometimes used legitimately by internal security teams,
    unexpected execution is a strong indicator of attacker tooling.
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
            - 'Execution:Runtime/SuspiciousTool'
    condition: selection
falsepositives:
    - 'An authorized internal security team or approved penetration test deliberately ran a known offensive-security tool (e.g., a...'
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

- An authorized internal security team or approved penetration test deliberately ran a known offensive-security tool (e.g., a network scanner, credential-dumping utility, or exploitation framework) as part of a sanctioned assessment.

### True Positives

- A binary matching a well-known offensive-security or dual-use tool (e.g., Nmap, Mimikatz-like credential dumpers, Metasploit components) was executed with no approved engagement on file.
- The tool's observed usage (arguments, targets) is consistent with reconnaissance, credential theft, or lateral movement rather than benign administration.
- Execution follows another compromise indicator on the same workload.

### True Negatives

- The tool's execution matches an approved, scheduled security assessment with documentation on file.

### False Negatives

- The tool is renamed, recompiled, or run from a wrapper script that avoids matching the known-tool signature.
- A less common or custom-built offensive tool is used that is not yet part of GuardDuty's known-tool catalog.

## References

- [Runtime Monitoring finding types](https://docs.aws.amazon.com/guardduty/latest/ug/findings-runtime-monitoring.html)
- [Remediating Runtime Monitoring findings](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty-remediate-runtime-monitoring.html)
- [NIST SP 800-61r3: Incident Response Recommendations](https://csrc.nist.gov/pubs/sp/800/61/r3/final)
- [AWS Security Incident Response Guide (2023)](https://docs.aws.amazon.com/whitepapers/latest/aws-security-incident-response-guide/welcome.html)
