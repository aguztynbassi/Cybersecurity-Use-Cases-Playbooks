# Anomalous Secrets Access - Kubernetes

## Description
Alert generated when AWS GuardDuty identifies the finding type `CredentialAccess:Kubernetes/AnomalousBehavior.SecretsAccessed`. Anomalous behavior has been detected affecting the Kubernetes cluster, relative to its expected baseline. The alert must be reviewed by the SOC to validate its legitimacy, scope, affected resource, and potential impact.

## Objective
Detect and prioritize potential malicious, anomalous, or unauthorized activities related to Kubernetes workloads (pods, service accounts, or API callers), enabling the SOC to initiate a structured investigation, reduce operational risk, and activate containment procedures when indicators of compromise are identified.

## Logic
The detection is triggered when an AWS GuardDuty event is received with `finding.type` equal to:

`CredentialAccess:Kubernetes/AnomalousBehavior.SecretsAccessed`

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

- T1552 - Unsecured Credentials
- T1078 - Valid Accounts (depending on context)

## Threat
- **Primary Threat:** Credential Access.
- **Family or Mechanism:** AnomalousBehavior.SecretsAccessed.
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
title: 'AWS: Anomalous Secrets Access - Kubernetes'
id: 6675fa14-767e-5b14-8351-054612115678
status: experimental
description: |
    This GuardDuty finding uses machine-learning behavioral analysis to flag anomalous access to Kubernetes
    Secrets relative to the calling identity's own baseline - a common technique for harvesting credentials once
    an attacker has a foothold inside a cluster.
references:
    - 'https://docs.aws.amazon.com/guardduty/latest/ug/guardduty-finding-types-eks-audit-logs.html'
    - 'https://docs.aws.amazon.com/guardduty/latest/ug/guardduty-remediate-kubernetes.html'
    - 'https://csrc.nist.gov/pubs/sp/800/61/r3/final'
    - 'https://docs.aws.amazon.com/whitepapers/latest/aws-security-incident-response-guide/welcome.html'
date: '2026-10-13'
modified: '2026-10-13'
author: 'https://github.com/aguztynbassi'
tags:
    - attack.t1552
    - attack.t1078
logsource:
    category: cloud
    product: aws
    service: guardduty
detection:
    selection:
        detail.type:
            - 'CredentialAccess:Kubernetes/AnomalousBehavior.SecretsAccessed'
    condition: selection
falsepositives:
    - 'A legitimate controller, operator, or CI/CD service account reads Secrets as part of its normal reconciliation loop, and its...'
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

- A legitimate controller, operator, or CI/CD service account reads Secrets as part of its normal reconciliation loop, and its usage pattern simply had not yet been reflected in the baseline.

### True Positives

- An identity accessed Kubernetes Secrets (e.g., `kubectl get secret`, or a `get`/`list` call against the Secrets API) at a volume or scope well outside its historical baseline, with no legitimate workload reason to do so.
- The accessed secrets include ones unrelated to the caller's own workload/namespace (e.g., a frontend pod's service account reading database credentials from another namespace).
- The secrets access follows another suspicious indicator (anonymous access, compromised service account token, RBAC privilege escalation) in the same cluster.

### True Negatives

- The owner confirms the identity's access matches an approved, documented operational pattern (e.g., a new secrets-rotation operator).

### False Negatives

- The attacker accesses secrets at a rate and scope that closely mimics the legitimate controller's own pattern, staying within the learned baseline.
- Secrets are read via a mounted volume at pod startup rather than a distinguishable API call, which this behavioral finding may not capture as clearly.

## References

- [EKS Protection finding types](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty-finding-types-eks-audit-logs.html)
- [Remediating EKS Protection findings](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty-remediate-kubernetes.html)
- [NIST SP 800-61r3: Incident Response Recommendations](https://csrc.nist.gov/pubs/sp/800/61/r3/final)
- [AWS Security Incident Response Guide (2023)](https://docs.aws.amazon.com/whitepapers/latest/aws-security-incident-response-guide/welcome.html)
