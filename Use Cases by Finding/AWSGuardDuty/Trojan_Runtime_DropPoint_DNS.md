# Drop Point - DNS-Based - Runtime

## Description
Alert generated when AWS GuardDuty identifies the finding type `Trojan:Runtime/DropPoint!DNS`. Suspicious or unexpected activity associated with the monitored runtime workload has been detected. The alert must be reviewed by the SOC to validate its legitimacy, scope, affected resource, and potential impact.

## Objective
Detect and prioritize potential malicious, anomalous, or unauthorized activities related to workloads monitored by the GuardDuty Runtime Monitoring agent (EC2, ECS, or EKS), enabling the SOC to initiate a structured investigation, reduce operational risk, and activate containment procedures when indicators of compromise are identified.

## Logic
The detection is triggered when an AWS GuardDuty event is received with `finding.type` equal to:

`Trojan:Runtime/DropPoint!DNS`

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

- T1071 - Application Layer Protocol

## Threat
- **Primary Threat:** Trojan.
- **Family or Mechanism:** DropPoint!DNS.
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
title: 'AWS: Drop Point - DNS-Based - Runtime'
id: 4f6c4a57-4382-5bc1-a0eb-512a9c705cd4
status: experimental
description: |
    This GuardDuty finding indicates that a resource is communicating with a known malware drop point -
    infrastructure used by threat actors to stage second-stage payloads, tools, or exfiltrated data. This should
    be investigated as a likely indicator of an active compromise.
references:
    - 'https://docs.aws.amazon.com/guardduty/latest/ug/findings-runtime-monitoring.html'
    - 'https://docs.aws.amazon.com/guardduty/latest/ug/guardduty-remediate-runtime-monitoring.html'
    - 'https://csrc.nist.gov/pubs/sp/800/61/r3/final'
    - 'https://docs.aws.amazon.com/whitepapers/latest/aws-security-incident-response-guide/welcome.html'
date: '2026-10-13'
modified: '2026-10-13'
author: 'https://github.com/aguztynbassi'
tags:
    - attack.t1071
logsource:
    category: cloud
    product: aws
    service: guardduty
detection:
    selection:
        detail.type:
            - 'Trojan:Runtime/DropPoint!DNS'
    condition: selection
falsepositives:
    - 'A file-sharing or backup integration legitimately uploads/downloads content to a cloud storage provider that happens to share...'
    - 'Security research or threat-intel validation intentionally interacted with the known drop-point domain/IP.'
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

- A file-sharing or backup integration legitimately uploads/downloads content to a cloud storage provider that happens to share infrastructure with a known malware drop point.
- Security research or threat-intel validation intentionally interacted with the known drop-point domain/IP.

### True Positives

- The monitored workload is communicating with infrastructure previously identified as a staging point used by threat actors to host second-stage payloads or stolen data.
- The connection is immediately followed by a new file being written to disk or a new process being started on the host.
- Outbound traffic volume toward the drop point spikes in a pattern consistent with data being staged for exfiltration.

### True Negatives

- The destination is confirmed to be a legitimate file-hosting service being used for an approved business purpose unrelated to the historical drop-point activity.

### False Negatives

- The drop point is hosted on a large, reputable cloud storage or CDN provider, so the specific malicious path/bucket is not distinguishable from legitimate traffic to the same provider.
- The threat actor rotates drop-point infrastructure faster than threat-intelligence feeds can be updated.

## References

- [Runtime Monitoring finding types](https://docs.aws.amazon.com/guardduty/latest/ug/findings-runtime-monitoring.html)
- [Remediating Runtime Monitoring findings](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty-remediate-runtime-monitoring.html)
- [NIST SP 800-61r3: Incident Response Recommendations](https://csrc.nist.gov/pubs/sp/800/61/r3/final)
- [AWS Security Incident Response Guide (2023)](https://docs.aws.amazon.com/whitepapers/latest/aws-security-incident-response-guide/welcome.html)
