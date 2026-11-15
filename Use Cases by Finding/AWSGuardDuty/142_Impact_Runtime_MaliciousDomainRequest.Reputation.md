# Malicious Domain Request (Reputation) - Runtime

## Description
Alert generated when AWS GuardDuty identifies the finding type `Impact:Runtime/MaliciousDomainRequest.Reputation`. Suspicious or unexpected activity associated with the monitored runtime workload has been detected. The alert must be reviewed by the SOC to validate its legitimacy, scope, affected resource, and potential impact.

## Objective
Detect and prioritize potential malicious, anomalous, or unauthorized activities related to workloads monitored by the GuardDuty Runtime Monitoring agent (EC2, ECS, or EKS), enabling the SOC to initiate a structured investigation, reduce operational risk, and activate containment procedures when indicators of compromise are identified.

## Logic
The detection is triggered when an AWS GuardDuty event is received with `finding.type` equal to:

`Impact:Runtime/MaliciousDomainRequest.Reputation`

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

- T1498 - Network Denial of Service
- T1485 - Data Destruction (depending on context)

## Threat
- **Primary Threat:** Impact.
- **Family or Mechanism:** MaliciousDomainRequest.Reputation.
- Suspicious or unexpected activity associated with the monitored runtime workload has been detected. The analyst should consider credential compromise, malware infection, cloud service abuse, public exposure, evasion, reconnaissance, impact, or exfiltration depending on the technical context of the finding.
- **Data Sources:** AWS GuardDuty Runtime Monitoring, host/container telemetry, VPC Flow Logs, CloudTrail.

## Investigation Sources
- **AWS GuardDuty Finding Details:** finding ID, type, severity, title, description, firstSeen, lastSeen, count, accountId, region.
- **AWS CloudTrail:** API calls, userIdentity, sourceIPAddress, userAgent, errorCode, requestParameters, responseElements.
- **Network Logs:** VPC Flow Logs, DNS logs, ports, protocols, transferred bytes, remote IP, country, and ASN.
- **Resource Configuration:** tags, owner, policies, public exposure, security groups, ACLs, roles, or effective permissions.
- Operational validation with the resource owner, platform team, cloud team, DevOps team, or application owner.

## Sigma Rule

```yaml
title: 'AWS: Malicious Domain Request (Reputation) - Runtime'
id: 6a10df81-46dc-51e3-bb6b-8891277b6123
status: experimental
description: |
    This GuardDuty finding indicates that the monitored workload is querying domains on AWS's curated threat-
    intelligence feed of known-malicious domains (malware distribution, phishing, C2). Such activity may suggest
    compromise, malware execution, unauthorized communications, or interaction with attacker-controlled
    infrastructure.
references:
    - 'https://docs.aws.amazon.com/guardduty/latest/ug/findings-runtime-monitoring.html'
    - 'https://docs.aws.amazon.com/guardduty/latest/ug/guardduty-remediate-runtime-monitoring.html'
    - 'https://csrc.nist.gov/pubs/sp/800/61/r3/final'
    - 'https://docs.aws.amazon.com/whitepapers/latest/aws-security-incident-response-guide/welcome.html'
date: '2026-10-13'
modified: '2026-10-13'
author: 'https://github.com/aguztynbassi'
tags:
    - attack.t1498
    - attack.t1485
logsource:
    category: cloud
    product: aws
    service: guardduty
detection:
    selection:
        detail.type:
            - 'Impact:Runtime/MaliciousDomainRequest.Reputation'
    condition: selection
falsepositives:
    - 'Queries to expired domains that currently resolve to registrar parking IP addresses.'
    - 'Security research activity, malware analysis, or threat intelligence validation performed by an authorized team.'
    - 'A legitimate application accessing a domain incorrectly classified by the reputation feed.'
    - 'Authorized administrative testing involving dynamic DNS (DDNS) services or free hosting providers.'
    - 'A threat-intelligence or security-research tool intentionally resolved the domain as part of its normal operation.'
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

- Queries to expired domains that currently resolve to registrar parking IP addresses.
- Security research activity, malware analysis, or threat intelligence validation performed by an authorized team.
- A legitimate application accessing a domain incorrectly classified by the reputation feed.
- Authorized administrative testing involving dynamic DNS (DDNS) services or free hosting providers.
- A threat-intelligence or security-research tool intentionally resolved the domain as part of its normal operation.

### True Positives

- A compromised the monitored workload is communicating with attacker-controlled infrastructure hosted on domains on AWS's curated threat-intelligence feed of known-malicious domains (malware distribution, phishing, C2).
- An infected workload is resolving domains used for malware delivery or malware updates.
- Cryptocurrency-mining malware is connecting to infrastructure hosted on a low-reputation domain.
- The domain is tied to a known malware family's C2 or payload-hosting infrastructure per threat intel.
- The lookup is immediately followed by a connection attempt to the resolved IP.

### True Negatives

- The monitored workload communicates exclusively with approved and trusted corporate domains.
- DNS activity is generated by a validated business application using a reputable service provider.
- The workload's DNS queries are limited to internal resolvers and explicitly authorized external services.

### False Negatives

- Malicious communication is performed directly through IP addresses without using DNS resolution.
- Threat-actor infrastructure is hosted on newly registered domains not yet classified as low reputation.
- DNS-over-HTTPS (DoH) or DNS-over-TLS (DoT) communications are not visible to monitored DNS telemetry.
- Compromised instances route traffic exclusively through legitimate cloud providers to blend in and evade detection.

## References

- [Runtime Monitoring finding types](https://docs.aws.amazon.com/guardduty/latest/ug/findings-runtime-monitoring.html)
- [Remediating Runtime Monitoring findings](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty-remediate-runtime-monitoring.html)
- [NIST SP 800-61r3: Incident Response Recommendations](https://csrc.nist.gov/pubs/sp/800/61/r3/final)
- [AWS Security Incident Response Guide (2023)](https://docs.aws.amazon.com/whitepapers/latest/aws-security-incident-response-guide/welcome.html)
