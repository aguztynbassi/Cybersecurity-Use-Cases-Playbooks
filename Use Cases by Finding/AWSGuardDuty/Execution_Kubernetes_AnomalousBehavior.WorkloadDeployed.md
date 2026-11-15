# Anomalous Workload Deployment - Kubernetes

## Description
Alert generated when AWS GuardDuty identifies the finding type `Execution:Kubernetes/AnomalousBehavior.WorkloadDeployed`. Anomalous behavior has been detected affecting the Kubernetes cluster, relative to its expected baseline. The alert must be reviewed by the SOC to validate its legitimacy, scope, affected resource, and potential impact.

## Objective
Detect and prioritize potential malicious, anomalous, or unauthorized activities related to Kubernetes workloads (pods, service accounts, or API callers), enabling the SOC to initiate a structured investigation, reduce operational risk, and activate containment procedures when indicators of compromise are identified.

## Logic
The detection is triggered when an AWS GuardDuty event is received with `finding.type` equal to:

`Execution:Kubernetes/AnomalousBehavior.WorkloadDeployed`

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
- **Family or Mechanism:** AnomalousBehavior.WorkloadDeployed.
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
title: 'AWS: Anomalous Workload Deployment - Kubernetes'
id: f7f96284-d91e-5507-9140-d5eaeb9811a4
status: experimental
description: |
    This GuardDuty finding uses machine-learning behavioral analysis to flag the deployment of a new workload into
    the cluster that deviates from the identity's or namespace's normal deployment pattern.
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
            - 'Execution:Kubernetes/AnomalousBehavior.WorkloadDeployed'
    condition: selection
falsepositives:
    - 'A new, legitimate application or microservice was deployed for the first time by its normal CI/CD pipeline, and the deployment...'
    - 'A GitOps controller redeployed a large number of workloads at once following an approved cluster-wide upgrade.'
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

- A new, legitimate application or microservice was deployed for the first time by its normal CI/CD pipeline, and the deployment simply had not yet been reflected in GuardDuty's baseline.
- A GitOps controller redeployed a large number of workloads at once following an approved cluster-wide upgrade.

### True Positives

- A workload was deployed by an identity that does not normally deploy to this cluster/namespace, using an image from an unfamiliar or untrusted registry.
- The deployment follows another suspicious cluster indicator (anonymous access, compromised service account, RBAC privilege escalation).
- The deployed workload's behavior at runtime (network connections, process activity) is itself subsequently flagged by other GuardDuty Runtime Monitoring findings.

### True Negatives

- The deployment is confirmed to be a legitimate, approved application rollout performed through the standard CI/CD pipeline.

### False Negatives

- The attacker modifies an existing, already-trusted workload (e.g., via a sidecar injection) rather than deploying a brand-new one, avoiding this specific deployment-anomaly detection.
- The malicious deployment uses an image name and configuration that closely mimics a legitimate internal service.

## References

- [EKS Protection finding types](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty-finding-types-eks-audit-logs.html)
- [Remediating EKS Protection findings](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty-remediate-kubernetes.html)
- [NIST SP 800-61r3: Incident Response Recommendations](https://csrc.nist.gov/pubs/sp/800/61/r3/final)
- [AWS Security Incident Response Guide (2023)](https://docs.aws.amazon.com/whitepapers/latest/aws-security-incident-response-guide/welcome.html)
