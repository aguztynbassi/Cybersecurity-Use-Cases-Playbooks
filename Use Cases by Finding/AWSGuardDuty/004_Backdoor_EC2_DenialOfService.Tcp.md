# Denial of Service - TCP - EC2

## Description
Alert generated when AWS GuardDuty identifies the finding type `Backdoor:EC2/DenialOfService.Tcp`. The EC2 instance could be participating in denial-of-service activity. The alert must be reviewed by the SOC to validate its legitimacy, scope, affected resource, and potential impact.

## Objective
Detect and prioritize potential malicious, anomalous, or unauthorized activities related to EC2 instances, enabling the SOC to initiate a structured investigation, reduce operational risk, and activate containment procedures when indicators of compromise are identified.

## Logic
The detection is triggered when an AWS GuardDuty event is received with `finding.type` equal to:

`Backdoor:EC2/DenialOfService.Tcp`

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
- **Primary Threat:** Backdoor.
- **Family or Mechanism:** DenialOfService.Tcp.
- The EC2 instance could be participating in denial-of-service activity. The analyst should consider credential compromise, malware infection, cloud service abuse, public exposure, evasion, reconnaissance, impact, or exfiltration depending on the technical context of the finding.
- **Data Sources:** AWS GuardDuty findings, VPC Flow Logs, DNS logs, AWS CloudTrail, EC2/SSM/EDR if available.

## Investigation Sources
- **AWS GuardDuty Finding Details:** finding ID, type, severity, title, description, firstSeen, lastSeen, count, accountId, region.
- **AWS CloudTrail:** API calls, userIdentity, sourceIPAddress, userAgent, errorCode, requestParameters, responseElements.
- **Network Logs:** VPC Flow Logs, DNS logs, ports, protocols, transferred bytes, remote IP, country, and ASN.
- **Resource Configuration:** tags, owner, policies, public exposure, security groups, ACLs, roles, or effective permissions.
- Operational validation with the resource owner, platform team, cloud team, DevOps team, or application owner.

## Sigma Rule

```yaml
title: 'AWS: Denial of Service - TCP - EC2'
id: 096d8e30-b9d3-5629-b871-af2531f30496
status: experimental
description: |
    This GuardDuty finding indicates that the EC2 instance is generating a high volume of TCP traffic consistent
    with it being used as a source of a Denial of Service (DoS) attack against an external target. This usually
    signals that the resource has already been compromised and is being used as part of a botnet.
references:
    - 'https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-ec2.html'
    - 'https://docs.aws.amazon.com/guardduty/latest/ug/compromised-ec2.html'
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
            - 'Backdoor:EC2/DenialOfService.Tcp'
    condition: selection
falsepositives:
    - 'A legitimate load test, stress test, or benchmark was being run against or from the EC2 instance without informing the SOC.'
    - 'A misconfigured application, retry loop, or monitoring agent is generating abnormal outbound traffic that resembles a DoS pattern.'
    - 'The EC2 instance is a NAT gateway, proxy, or load balancer that legitimately aggregates high volumes of traffic from many...'
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

- A legitimate load test, stress test, or benchmark was being run against or from the EC2 instance without informing the SOC.
- A misconfigured application, retry loop, or monitoring agent is generating abnormal outbound traffic that resembles a DoS pattern.
- The EC2 instance is a NAT gateway, proxy, or load balancer that legitimately aggregates high volumes of traffic from many downstream clients.

### True Positives

- The EC2 instance is confirmed compromised and is being used as part of a botnet to send a high volume of TCP traffic toward external targets.
- The outbound flood correlates with an unexplained process, cron job, or newly installed package on the host.
- Multiple instances in the same account or VPC begin generating the same traffic pattern simultaneously, indicating a common compromise (e.g., a worm or shared malicious image).
- AWS Trust & Safety or an external party (abuse report) has already flagged this account for outbound DoS activity.

### True Negatives

- The traffic is generated by an approved internal load-testing tool running from an authorized source during a scheduled maintenance/testing window.
- The EC2 instance is a documented high-throughput service (e.g., streaming, bulk transfer) whose traffic profile naturally matches this pattern.

### False Negatives

- The outbound flood is throttled to stay just under GuardDuty's volumetric thresholds, spreading the attack across many small bursts.
- The attacking process uses a protocol or destination not currently modeled by GuardDuty's network intelligence for this finding type.

## References

- [EC2 finding types](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-ec2.html)
- [Remediating a potentially compromised Amazon EC2 instance](https://docs.aws.amazon.com/guardduty/latest/ug/compromised-ec2.html)
- [NIST SP 800-61r3: Incident Response Recommendations](https://csrc.nist.gov/pubs/sp/800/61/r3/final)
- [AWS Security Incident Response Guide (2023)](https://docs.aws.amazon.com/whitepapers/latest/aws-security-incident-response-guide/welcome.html)
