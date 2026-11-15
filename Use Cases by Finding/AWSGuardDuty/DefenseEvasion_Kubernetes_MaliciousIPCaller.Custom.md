# Malicious IP Caller (Custom) - Kubernetes (Defense Evasion)

## Description
Alert generated when AWS GuardDuty identifies the finding type `DefenseEvasion:Kubernetes/MaliciousIPCaller.Custom`. Activity to or from an IP address classified as malicious has been detected involving the Kubernetes cluster. The alert must be reviewed by the SOC to validate its legitimacy, scope, affected resource, and potential impact.

## Objective
Detect and prioritize potential malicious, anomalous, or unauthorized activities related to Kubernetes workloads (pods, service accounts, or API callers), enabling the SOC to initiate a structured investigation, reduce operational risk, and activate containment procedures when indicators of compromise are identified.

## Logic
The detection is triggered when an AWS GuardDuty event is received with `finding.type` equal to:

`DefenseEvasion:Kubernetes/MaliciousIPCaller.Custom`

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

- T1562 - Impair Defenses

## Threat
- **Primary Threat:** Defense Evasion.
- **Family or Mechanism:** MaliciousIPCaller.Custom.
- Activity to or from an IP address classified as malicious has been detected involving the Kubernetes cluster. The analyst should consider credential compromise, malware infection, cloud service abuse, public exposure, evasion, reconnaissance, impact, or exfiltration depending on the technical context of the finding.
- **Data Sources:** AWS GuardDuty findings, EKS Audit Logs, Kubernetes API Server logs, Runtime Monitoring.

## Investigation Sources
- **AWS GuardDuty Finding Details:** finding ID, type, severity, title, description, firstSeen, lastSeen, count, accountId, region.
- **AWS CloudTrail:** API calls, userIdentity, sourceIPAddress, userAgent, errorCode, requestParameters, responseElements.
- **Network Logs:** VPC Flow Logs, DNS logs, ports, protocols, transferred bytes, remote IP, country, and ASN.
- **Resource Configuration:** tags, owner, policies, public exposure, security groups, ACLs, roles, or effective permissions.
- Operational validation with the resource owner, platform team, cloud team, DevOps team, or application owner.

## Sigma Rule

```yaml
title: 'AWS: Malicious IP Caller (Custom) - Kubernetes (Defense Evasion)'
id: 12b6426b-dfce-5852-817b-33ac97ae1cae
status: experimental
description: |
    This GuardDuty finding indicates that an IP address on the organization's own custom threat list attempted to
    modify logging, configuration, or defenses on the Kubernetes workload. This should be treated as a credible
    indicator of malicious activity and investigated for scope and impact.
references:
    - 'https://docs.aws.amazon.com/guardduty/latest/ug/guardduty-finding-types-eks-audit-logs.html'
    - 'https://docs.aws.amazon.com/guardduty/latest/ug/guardduty-remediate-kubernetes.html'
    - 'https://csrc.nist.gov/pubs/sp/800/61/r3/final'
    - 'https://docs.aws.amazon.com/whitepapers/latest/aws-security-incident-response-guide/welcome.html'
date: '2026-10-13'
modified: '2026-10-13'
author: 'https://github.com/aguztynbassi'
tags:
    - attack.t1562
logsource:
    category: cloud
    product: aws
    service: guardduty
detection:
    selection:
        detail.type:
            - 'DefenseEvasion:Kubernetes/MaliciousIPCaller.Custom'
    condition: selection
falsepositives:
    - 'The source IP was recently reassigned (e.g., by a hosting/cloud provider) and no longer belongs to the malicious actor it was...'
    - 'A legitimate partner, scanner, or SaaS integration happens to egress from an IP range that overlaps with a shared/dynamic address...'
    - 'The request is a benign, unauthenticated probe (e.g., a health check or crawler) that failed and generated no meaningful access.'
    - 'The custom list contains a stale or overly broad CIDR range that now also covers unrelated, legitimate traffic.'
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

- The source IP was recently reassigned (e.g., by a hosting/cloud provider) and no longer belongs to the malicious actor it was originally associated with.
- A legitimate partner, scanner, or SaaS integration happens to egress from an IP range that overlaps with a shared/dynamic address previously flagged.
- The request is a benign, unauthenticated probe (e.g., a health check or crawler) that failed and generated no meaningful access.
- The custom list contains a stale or overly broad CIDR range that now also covers unrelated, legitimate traffic.

### True Positives

- An IP address on the organization's own custom threat list attempted to modify logging, configuration, or defenses on the Kubernetes workload, and the call succeeded or returned sensitive information.
- The same source IP has been observed attacking other, unrelated AWS accounts per threat-intelligence sharing.
- The access is followed by further suspicious activity (privilege escalation, data access, configuration changes) from the same identity or session.
- No employee, automation, or partner can account for traffic from this source IP when asked.

### True Negatives

- The call from the flagged IP failed authentication/authorization and no resource access occurred.
- The IP belongs to an approved, documented third-party integration whose address happens to appear on a shared reputation list.

### False Negatives

- The attacker uses a residential proxy, compromised home router, or fresh cloud IP that has not yet been added to any threat-intelligence feed.
- The malicious IP is used for only a single, low-noise request that does not accumulate enough reputation signal to be listed before the damage is done.

## References

- [EKS Protection finding types](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty-finding-types-eks-audit-logs.html)
- [Remediating EKS Protection findings](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty-remediate-kubernetes.html)
- [NIST SP 800-61r3: Incident Response Recommendations](https://csrc.nist.gov/pubs/sp/800/61/r3/final)
- [AWS Security Incident Response Guide (2023)](https://docs.aws.amazon.com/whitepapers/latest/aws-security-incident-response-guide/welcome.html)
