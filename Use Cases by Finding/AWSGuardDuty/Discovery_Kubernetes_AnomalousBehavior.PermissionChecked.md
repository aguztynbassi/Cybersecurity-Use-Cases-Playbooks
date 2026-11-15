# Anomalous Permission Enumeration - Kubernetes

## Description
Alert generated when AWS GuardDuty identifies the finding type `Discovery:Kubernetes/AnomalousBehavior.PermissionChecked`. Anomalous behavior has been detected affecting the Kubernetes cluster, relative to its expected baseline. The alert must be reviewed by the SOC to validate its legitimacy, scope, affected resource, and potential impact.

## Objective
Detect and prioritize potential malicious, anomalous, or unauthorized activities related to Kubernetes workloads (pods, service accounts, or API callers), enabling the SOC to initiate a structured investigation, reduce operational risk, and activate containment procedures when indicators of compromise are identified.

## Logic
The detection is triggered when an AWS GuardDuty event is received with `finding.type` equal to:

`Discovery:Kubernetes/AnomalousBehavior.PermissionChecked`

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

- T1580 - Cloud Infrastructure Discovery
- T1619 - Cloud Storage Object Discovery

## Threat
- **Primary Threat:** Discovery.
- **Family or Mechanism:** AnomalousBehavior.PermissionChecked.
- Anomalous behavior has been detected affecting the Kubernetes cluster, relative to its expected baseline. The analyst should consider credential compromise, malware infection, cloud service abuse, public exposure, evasion, reconnaissance, impact, or exfiltration depending on the technical context of the finding.
- **Data Sources:** AWS GuardDuty findings, EKS Audit Logs, Kubernetes API Server logs, Runtime Monitoring.

## Investigation Sources
- **AWS GuardDuty Finding Details:** finding ID, type, severity, title, description, firstSeen, lastSeen, count, accountId, region.
- **AWS CloudTrail:** API calls, userIdentity, sourceIPAddress, userAgent, errorCode, requestParameters, responseElements.
- **Network Logs:** VPC Flow Logs, DNS logs, ports, protocols, transferred bytes, remote IP, country, and ASN.
- **Resource Configuration:** tags, owner, policies, public exposure, security groups, ACLs, roles, or effective permissions.
- Operational validation with the resource owner, platform team, cloud team, DevOps team, or application owner.

## Sigma Rule

```yaml
title: 'AWS: Anomalous Permission Enumeration - Kubernetes'
id: 0dc0900b-9b96-5a3c-b49c-9b37639c3d34
status: experimental
description: |
    This GuardDuty finding uses machine-learning behavioral analysis to flag anomalous use of Kubernetes
    permission-checking APIs (such as `SelfSubjectAccessReview`), often indicative of an attacker enumerating what
    they can do with a given identity after obtaining initial access to the cluster.
references:
    - 'https://docs.aws.amazon.com/guardduty/latest/ug/guardduty-finding-types-eks-audit-logs.html'
    - 'https://docs.aws.amazon.com/guardduty/latest/ug/guardduty-remediate-kubernetes.html'
    - 'https://csrc.nist.gov/pubs/sp/800/61/r3/final'
    - 'https://docs.aws.amazon.com/whitepapers/latest/aws-security-incident-response-guide/welcome.html'
date: '2026-10-13'
modified: '2026-10-13'
author: 'https://github.com/aguztynbassi'
tags:
    - attack.t1580
    - attack.t1619
logsource:
    category: cloud
    product: aws
    service: guardduty
detection:
    selection:
        detail.type:
            - 'Discovery:Kubernetes/AnomalousBehavior.PermissionChecked'
    condition: selection
falsepositives:
    - 'A legitimate administrative tool or dashboard performs `SelfSubjectAccessReview`/`can-i`-style permission checks as part of its...'
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

- A legitimate administrative tool or dashboard performs `SelfSubjectAccessReview`/`can-i`-style permission checks as part of its normal UI rendering logic (showing/hiding buttons based on what the user can do).

### True Positives

- An identity performed an unusually broad or systematic series of permission checks across many resources/verbs, consistent with an attacker probing to discover what they can do with a newly obtained or stolen credential.
- The permission-checking activity is followed by the identity actually exercising one of the broader permissions it discovered.
- The checking identity has no legitimate administrative or tooling purpose that would require this kind of enumeration.

### True Negatives

- The activity is explained by a known administrative or auditing tool that legitimately enumerates effective permissions as part of a scheduled access review.

### False Negatives

- The attacker already knows (or guesses accurately) what permissions their stolen credential has, skipping the enumeration step this finding is designed to catch.
- Permission checks are spaced out over a long period to avoid looking like a systematic enumeration.

## References

- [EKS Protection finding types](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty-finding-types-eks-audit-logs.html)
- [Remediating EKS Protection findings](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty-remediate-kubernetes.html)
- [NIST SP 800-61r3: Incident Response Recommendations](https://csrc.nist.gov/pubs/sp/800/61/r3/final)
- [AWS Security Incident Response Guide (2023)](https://docs.aws.amazon.com/whitepapers/latest/aws-security-incident-response-guide/welcome.html)
