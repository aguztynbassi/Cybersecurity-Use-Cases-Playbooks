# Anomalous Role Creation - Kubernetes

## Description
Alert generated when AWS GuardDuty identifies the finding type `PrivilegeEscalation:Kubernetes/AnomalousBehavior.RoleCreated`. Anomalous behavior has been detected affecting the Kubernetes cluster, relative to its expected baseline. The alert must be reviewed by the SOC to validate its legitimacy, scope, affected resource, and potential impact.

## Objective
Detect and prioritize potential malicious, anomalous, or unauthorized activities related to Kubernetes workloads (pods, service accounts, or API callers), enabling the SOC to initiate a structured investigation, reduce operational risk, and activate containment procedures when indicators of compromise are identified.

## Logic
The detection is triggered when an AWS GuardDuty event is received with `finding.type` equal to:

`PrivilegeEscalation:Kubernetes/AnomalousBehavior.RoleCreated`

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

- T1068 - Exploitation for Privilege Escalation
- T1611 - Escape to Host

## Threat
- **Primary Threat:** Privilege Escalation.
- **Family or Mechanism:** AnomalousBehavior.RoleCreated.
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
title: 'AWS: Anomalous Role Creation - Kubernetes'
id: 1444f5ac-108d-5cb7-ac50-befc9092cfd0
status: experimental
description: |
    This GuardDuty finding uses machine-learning behavioral analysis to flag the anomalous creation of a Role or
    ClusterRole within the cluster, a common technique used to escalate privileges once an attacker has obtained
    limited access to the Kubernetes API.
references:
    - 'https://docs.aws.amazon.com/guardduty/latest/ug/guardduty-finding-types-eks-audit-logs.html'
    - 'https://docs.aws.amazon.com/guardduty/latest/ug/guardduty-remediate-kubernetes.html'
    - 'https://csrc.nist.gov/pubs/sp/800/61/r3/final'
    - 'https://docs.aws.amazon.com/whitepapers/latest/aws-security-incident-response-guide/welcome.html'
date: '2026-10-13'
modified: '2026-10-13'
author: 'https://github.com/aguztynbassi'
tags:
    - attack.t1068
    - attack.t1611
logsource:
    category: cloud
    product: aws
    service: guardduty
detection:
    selection:
        detail.type:
            - 'PrivilegeEscalation:Kubernetes/AnomalousBehavior.RoleCreated'
    condition: selection
falsepositives:
    - 'A platform team''s GitOps pipeline (e.g., ArgoCD, Flux) legitimately creates RBAC objects as part of onboarding a new application...'
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

- A platform team's GitOps pipeline (e.g., ArgoCD, Flux) legitimately creates RBAC objects as part of onboarding a new application or team, and the activity simply had not yet been reflected in the baseline.

### True Positives

- An identity with no cluster-administration responsibility created a new Role or ClusterRole that grants itself or another identity broader permissions than it previously had, consistent with privilege escalation.
- The newly granted permissions include sensitive verbs (`*`, `create`, `bind`, `escalate`) or sensitive resources (secrets, pods/exec, RBAC objects themselves).
- The new permissions are exercised almost immediately after creation to perform a sensitive action.

### True Negatives

- The RBAC change is tied to an approved onboarding process or GitOps pull request performed by a known platform identity.

### False Negatives

- The attacker grants only a narrow, specific permission rather than a broad wildcard, making the resulting RBAC object look unremarkable on its own.
- Privilege escalation is achieved by exploiting an existing, already-over-permissioned role rather than creating a new RBAC object, bypassing this specific detection.

## References

- [EKS Protection finding types](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty-finding-types-eks-audit-logs.html)
- [Remediating EKS Protection findings](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty-remediate-kubernetes.html)
- [NIST SP 800-61r3: Incident Response Recommendations](https://csrc.nist.gov/pubs/sp/800/61/r3/final)
- [AWS Security Incident Response Guide (2023)](https://docs.aws.amazon.com/whitepapers/latest/aws-security-incident-response-guide/welcome.html)
