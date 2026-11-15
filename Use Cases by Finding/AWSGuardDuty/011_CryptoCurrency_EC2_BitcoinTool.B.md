# Bitcoin Tool (Variant B) - EC2

## Description
Alert generated when AWS GuardDuty identifies the finding type `CryptoCurrency:EC2/BitcoinTool.B`. The EC2 resource could be being used for unauthorized cryptocurrency mining. The alert must be reviewed by the SOC to validate its legitimacy, scope, affected resource, and potential impact.

## Objective
Detect and prioritize potential malicious, anomalous, or unauthorized activities related to EC2 instances, enabling the SOC to initiate a structured investigation, reduce operational risk, and activate containment procedures when indicators of compromise are identified.

## Logic
The detection is triggered when an AWS GuardDuty event is received with `finding.type` equal to:

`CryptoCurrency:EC2/BitcoinTool.B`

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

- T1496 - Resource Hijacking

## Threat
- **Primary Threat:** CryptoCurrency.
- **Family or Mechanism:** BitcoinTool.B.
- The EC2 resource could be being used for unauthorized cryptocurrency mining. The analyst should consider credential compromise, malware infection, cloud service abuse, public exposure, evasion, reconnaissance, impact, or exfiltration depending on the technical context of the finding.
- **Data Sources:** AWS GuardDuty findings, VPC Flow Logs, DNS logs, AWS CloudTrail, EC2/SSM/EDR if available.

## Investigation Sources
- **AWS GuardDuty Finding Details:** finding ID, type, severity, title, description, firstSeen, lastSeen, count, accountId, region.
- **AWS CloudTrail:** API calls, userIdentity, sourceIPAddress, userAgent, errorCode, requestParameters, responseElements.
- **Network Logs:** VPC Flow Logs, DNS logs, ports, protocols, transferred bytes, remote IP, country, and ASN.
- **Resource Configuration:** tags, owner, policies, public exposure, security groups, ACLs, roles, or effective permissions.
- Operational validation with the resource owner, platform team, cloud team, DevOps team, or application owner.

## Sigma Rule

```yaml
title: 'AWS: Bitcoin Tool (Variant B) - EC2'
id: d21d4bc0-f163-54e2-9254-9c6b7b108930
status: experimental
description: |
    This GuardDuty finding indicates that a resource is communicating with an IP address or domain associated with
    cryptocurrency mining pools or wallets, which typically signals that the resource has been compromised and is
    being used for unauthorized cryptomining, consuming compute resources at the account owner's expense.
references:
    - 'https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-ec2.html'
    - 'https://docs.aws.amazon.com/guardduty/latest/ug/compromised-ec2.html'
    - 'https://csrc.nist.gov/pubs/sp/800/61/r3/final'
    - 'https://docs.aws.amazon.com/whitepapers/latest/aws-security-incident-response-guide/welcome.html'
date: '2026-10-13'
modified: '2026-10-13'
author: 'https://github.com/aguztynbassi'
tags:
    - attack.t1496
logsource:
    category: cloud
    product: aws
    service: guardduty
detection:
    selection:
        detail.type:
            - 'CryptoCurrency:EC2/BitcoinTool.B'
    condition: selection
falsepositives:
    - 'The EC2 instance legitimately runs a blockchain node, wallet service, or crypto-related analytics workload that was not...'
    - 'A developer is testing blockchain/Web3 tooling in a sandbox account and connected to public mining-pool infrastructure for...'
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

- The EC2 instance legitimately runs a blockchain node, wallet service, or crypto-related analytics workload that was not documented to the SOC.
- A developer is testing blockchain/Web3 tooling in a sandbox account and connected to public mining-pool infrastructure for legitimate research.

### True Positives

- The EC2 instance is communicating with a known cryptocurrency mining pool or wallet-related endpoint with no business justification for doing so.
- CPU/GPU utilization on the underlying workload spikes in correlation with the network connection, consistent with unauthorized cryptomining.
- The connection follows a recent compromise indicator (new SSH key, unexplained process, exploited vulnerability) on the same resource.
- Billing or Cost Explorer shows an unexplained spike in compute usage for this account/resource around the same time.

### True Negatives

- The resource is an approved, documented blockchain or crypto-asset workload operating within its expected architecture and owner.

### False Negatives

- The miner connects over a domain-fronted or CDN-hosted mining-pool proxy that does not appear on GuardDuty's reputation lists.
- Mining activity is throttled to a low, inconspicuous resource-utilization level specifically to evade behavioral and network detections.

## References

- [EC2 finding types](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-ec2.html)
- [Remediating a potentially compromised Amazon EC2 instance](https://docs.aws.amazon.com/guardduty/latest/ug/compromised-ec2.html)
- [NIST SP 800-61r3: Incident Response Recommendations](https://csrc.nist.gov/pubs/sp/800/61/r3/final)
- [AWS Security Incident Response Guide (2023)](https://docs.aws.amazon.com/whitepapers/latest/aws-security-incident-response-guide/welcome.html)
