# Exec Into a kube-system Pod - Kubernetes

## Description
Alert generated when AWS GuardDuty identifies the finding type `Execution:Kubernetes/ExecInKubeSystemPod`. Suspicious or unexpected activity associated with the Kubernetes cluster has been detected. The alert must be reviewed by the SOC to validate its legitimacy, scope, affected resource, and potential impact.

## Objective
Detect and prioritize potential malicious, anomalous, or unauthorized activities related to Kubernetes workloads (pods, service accounts, or API callers), enabling the SOC to initiate a structured investigation, reduce operational risk, and activate containment procedures when indicators of compromise are identified.

## Logic
The detection is triggered when an AWS GuardDuty event is received with `finding.type` equal to:

`Execution:Kubernetes/ExecInKubeSystemPod`

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
- **Family or Mechanism:** ExecInKubeSystemPod.
- Suspicious or unexpected activity associated with the Kubernetes cluster has been detected. The analyst should consider credential compromise, malware infection, cloud service abuse, public exposure, evasion, reconnaissance, impact, or exfiltration depending on the technical context of the finding.
- **Data Sources:** AWS GuardDuty findings, EKS Audit Logs, Kubernetes API Server logs, Runtime Monitoring.

## Investigation Sources
- **AWS GuardDuty Finding Details:** finding ID, type, severity, title, description, firstSeen, lastSeen, count, accountId, region.
- **AWS CloudTrail:** API calls, userIdentity, sourceIPAddress, userAgent, errorCode, requestParameters, responseElements.
- **Network Logs:** VPC Flow Logs, DNS logs, ports, protocols, transferred bytes, remote IP, country, and ASN.
- **Resource Configuration:** tags, owner, policies, public exposure, security groups, ACLs, roles, or effective permissions.
- Operational validation with the resource owner, platform team, cloud team, DevOps team, or application owner.

## Sigma Rule

```yaml
title: 'AWS: Exec Into a kube-system Pod - Kubernetes'
id: 5fcd576e-76f0-561b-bd60-5cf1c0ee801c
status: experimental
description: |
    This GuardDuty finding indicates that a user executed a command inside a pod running in the `kube-system`
    namespace, which hosts highly privileged cluster-management components. Interactive access to this namespace
    should be tightly restricted and any unexpected exec session treated as a likely privilege-escalation or
    persistence attempt.
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
            - 'Execution:Kubernetes/ExecInKubeSystemPod'
    condition: selection
falsepositives:
    - 'A cluster administrator or the managed EKS control plane itself ran an approved `kubectl exec` into a kube-system pod for...'
    - 'A monitoring or logging DaemonSet''s own health-check mechanism uses exec-like calls against its own pods in kube-system.'
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

- A cluster administrator or the managed EKS control plane itself ran an approved `kubectl exec` into a kube-system pod for legitimate troubleshooting or an add-on upgrade.
- A monitoring or logging DaemonSet's own health-check mechanism uses exec-like calls against its own pods in kube-system.

### True Positives

- An identity with no cluster-administration role executed a command inside a kube-system pod (e.g., CoreDNS, kube-proxy, or the AWS VPC CNI), which is a highly privileged namespace not meant for routine interactive access.
- The executed command attempts to read service account tokens, modify DNS configuration, or access other sensitive cluster-internal data.
- The exec session follows another suspicious indicator (anonymous access, a leaked kubeconfig, or unusual RBAC changes).

### True Negatives

- The exec session is tied to an approved maintenance window and performed by a known cluster administrator.

### False Negatives

- The attacker instead deploys a new pod/job directly in kube-system rather than exec-ing into an existing one, avoiding this specific detection.
- The exec session is very short and limited to a single benign-looking command, blending in with legitimate administrative noise.

## References

- [EKS Protection finding types](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty-finding-types-eks-audit-logs.html)
- [Remediating EKS Protection findings](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty-remediate-kubernetes.html)
- [NIST SP 800-61r3: Incident Response Recommendations](https://csrc.nist.gov/pubs/sp/800/61/r3/final)
- [AWS Security Incident Response Guide (2023)](https://docs.aws.amazon.com/whitepapers/latest/aws-security-incident-response-guide/welcome.html)
