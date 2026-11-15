# Unusual Traffic Volume - EC2

## Description
Alert generated when AWS GuardDuty identifies the finding type `Behavior:EC2/TrafficVolumeUnusual`. Suspicious or unexpected activity associated with the EC2 resource has been detected. The alert must be reviewed by the SOC to validate its legitimacy, scope, affected resource, and potential impact.

## Objective
Detect and prioritize potential malicious, anomalous, or unauthorized activities related to EC2 instances, enabling the SOC to initiate a structured investigation, reduce operational risk, and activate containment procedures when indicators of compromise are identified.

## Logic
The detection is triggered when an AWS GuardDuty event is received with `finding.type` equal to:

`Behavior:EC2/TrafficVolumeUnusual`

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

- T1046 - Network Service Discovery

## Threat
- **Primary Threat:** Behavior.
- **Family or Mechanism:** TrafficVolumeUnusual.
- Suspicious or unexpected activity associated with the EC2 resource has been detected. The analyst should consider credential compromise, malware infection, cloud service abuse, public exposure, evasion, reconnaissance, impact, or exfiltration depending on the technical context of the finding.
- **Data Sources:** AWS GuardDuty findings, VPC Flow Logs, DNS logs, AWS CloudTrail, EC2/SSM/EDR if available.

## Investigation Sources
- **AWS GuardDuty Finding Details:** finding ID, type, severity, title, description, firstSeen, lastSeen, count, accountId, region.
- **AWS CloudTrail:** API calls, userIdentity, sourceIPAddress, userAgent, errorCode, requestParameters, responseElements.
- **Network Logs:** VPC Flow Logs, DNS logs, ports, protocols, transferred bytes, remote IP, country, and ASN.
- **Resource Configuration:** tags, owner, policies, public exposure, security groups, ACLs, roles, or effective permissions.
- Operational validation with the resource owner, platform team, cloud team, DevOps team, or application owner.

## Sigma Rule

```yaml
title: 'AWS: Unusual Traffic Volume - EC2'
id: 6fe7c14a-bb3e-5eed-a28f-9d4b946c3bca
status: experimental
description: |
    This GuardDuty finding uses machine-learning-based behavioral baselining to flag an unusual volume of network
    traffic on an EC2 instance relative to its own historical profile. It is a behavioral indicator rather than a
    signature match, so context from the resource owner is required to determine legitimacy.
references:
    - 'https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-ec2.html'
    - 'https://docs.aws.amazon.com/guardduty/latest/ug/compromised-ec2.html'
    - 'https://csrc.nist.gov/pubs/sp/800/61/r3/final'
    - 'https://docs.aws.amazon.com/whitepapers/latest/aws-security-incident-response-guide/welcome.html'
date: '2026-10-13'
modified: '2026-10-13'
author: 'https://github.com/aguztynbassi'
tags:
    - attack.t1046
logsource:
    category: cloud
    product: aws
    service: guardduty
detection:
    selection:
        detail.type:
            - 'Behavior:EC2/TrafficVolumeUnusual'
    condition: selection
falsepositives:
    - 'A new application, service, or dependency was deployed on the EC2 instance that legitimately listens on or calls a port/volume...'
    - 'A scheduled batch job, backup, or data sync ran at a time or volume that differs from the instance''s normal day-to-day pattern.'
    - 'GuardDuty''s machine-learning baseline has not yet adapted following a recent, approved change to the workload (auto-scaling, new...'
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

- A new application, service, or dependency was deployed on the EC2 instance that legitimately listens on or calls a port/volume outside its historical baseline.
- A scheduled batch job, backup, or data sync ran at a time or volume that differs from the instance's normal day-to-day pattern.
- GuardDuty's machine-learning baseline has not yet adapted following a recent, approved change to the workload (auto-scaling, new feature rollout).

### True Positives

- The an unusual volume of network traffic on the EC2 instance coincides with other indicators of compromise (new processes, outbound beaconing, unexpected logins).
- The anomalous traffic targets or originates from IP ranges, ports, or protocols with no legitimate business justification.
- The pattern recurs and escalates over successive observation windows rather than settling back to baseline.

### True Negatives

- The change in traffic pattern is fully explained by a documented, approved application or infrastructure change (deployment, scaling event, maintenance).
- The owner confirms the new port/volume usage matches a planned feature or integration.

### False Negatives

- A slow, gradual shift in behavior is absorbed into the evolving baseline before GuardDuty's model flags it as anomalous.
- The anomalous activity stays within normal-looking thresholds by blending with legitimate background traffic.

## References

- [EC2 finding types](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-ec2.html)
- [Remediating a potentially compromised Amazon EC2 instance](https://docs.aws.amazon.com/guardduty/latest/ug/compromised-ec2.html)
- [NIST SP 800-61r3: Incident Response Recommendations](https://csrc.nist.gov/pubs/sp/800/61/r3/final)
- [AWS Security Incident Response Guide (2023)](https://docs.aws.amazon.com/whitepapers/latest/aws-security-incident-response-guide/welcome.html)
