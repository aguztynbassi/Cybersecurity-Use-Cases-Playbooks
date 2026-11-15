# Malicious File - Kubernetes

## Description
Alert generated when AWS GuardDuty identifies the finding type `Execution:Kubernetes/MaliciousFile`. A malicious or suspicious file associated with the Kubernetes cluster has been identified. The alert must be reviewed by the SOC to validate its legitimacy, scope, affected resource, and potential impact.

## Objective
Detect and prioritize potential malicious, anomalous, or unauthorized activities related to Kubernetes workloads (pods, service accounts, or API callers), enabling the SOC to initiate a structured investigation, reduce operational risk, and activate containment procedures when indicators of compromise are identified.

## Logic
The detection is triggered when an AWS GuardDuty event is received with `finding.type` equal to:

`Execution:Kubernetes/MaliciousFile`

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
- **Family or Mechanism:** MaliciousFile.
- A malicious or suspicious file associated with the Kubernetes cluster has been identified. The analyst should consider credential compromise, malware infection, cloud service abuse, public exposure, evasion, reconnaissance, impact, or exfiltration depending on the technical context of the finding.
- **Data Sources:** AWS GuardDuty findings, EKS Audit Logs, Kubernetes API Server logs, Runtime Monitoring.

## Investigation Sources
- **AWS GuardDuty Finding Details:** finding ID, type, severity, title, description, firstSeen, lastSeen, count, accountId, region.
- **AWS CloudTrail:** API calls, userIdentity, sourceIPAddress, userAgent, errorCode, requestParameters, responseElements.
- **Network Logs:** VPC Flow Logs, DNS logs, ports, protocols, transferred bytes, remote IP, country, and ASN.
- **Resource Configuration:** tags, owner, policies, public exposure, security groups, ACLs, roles, or effective permissions.
- Operational validation with the resource owner, platform team, cloud team, DevOps team, or application owner.

## Sigma Rule

```yaml
title: 'AWS: Malicious File - Kubernetes'
id: 309a6d30-cbb9-53f5-85db-2ab0c3e28aae
status: experimental
description: |
    This GuardDuty Malware Protection finding indicates that a file identified as malicious was found on the
    Kubernetes workload. This is a high-confidence, signature-based detection and should be treated as a confirmed
    malware presence pending containment and full forensic review.
references:
    - 'https://docs.aws.amazon.com/guardduty/latest/ug/guardduty-finding-types-eks-audit-logs.html'
    - 'https://docs.aws.amazon.com/guardduty/latest/ug/guardduty-remediate-kubernetes.html'
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
            - 'Execution:Kubernetes/MaliciousFile'
    condition: selection
falsepositives:
    - 'An extremely rare hash/signature collision incorrectly flags a legitimate, benign file as malicious (uncommon, but possible with...'
    - 'A security-testing file (e.g., the EICAR test string) was intentionally placed on the workload to validate that Malware...'
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

- An extremely rare hash/signature collision incorrectly flags a legitimate, benign file as malicious (uncommon, but possible with any AV-style engine).
- A security-testing file (e.g., the EICAR test string) was intentionally placed on the workload to validate that Malware Protection scanning is working.

### True Positives

- A file identified as malware by GuardDuty Malware Protection's scanning engine was found on the Kubernetes workload, which is a high-confidence, signature-based detection of an actual malicious file present on the resource.
- The file's location and metadata (recent creation time, unexpected path, suspicious name) are inconsistent with an approved software deployment.
- The file is corroborated by other indicators (a corresponding Runtime Monitoring finding, unexpected network activity, or a related GuardDuty finding on the same resource).

### False Negatives

- The malicious file is deleted or modified before the next scheduled scan completes.
- The malware is delivered and executed entirely in memory without ever being written to disk as a scannable file (see the related fileless-execution finding).
- The file is encrypted or packed in a way that defeats the scan engine's current signature/heuristic coverage.

## References

- [EKS Protection finding types](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty-finding-types-eks-audit-logs.html)
- [Remediating EKS Protection findings](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty-remediate-kubernetes.html)
- [NIST SP 800-61r3: Incident Response Recommendations](https://csrc.nist.gov/pubs/sp/800/61/r3/final)
- [AWS Security Incident Response Guide (2023)](https://docs.aws.amazon.com/whitepapers/latest/aws-security-incident-response-guide/welcome.html)
