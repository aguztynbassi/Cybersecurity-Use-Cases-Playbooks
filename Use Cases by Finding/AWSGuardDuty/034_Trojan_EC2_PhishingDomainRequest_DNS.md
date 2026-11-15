# Phishing Domain Request - DNS-Based - EC2

## Description
Alert generated when AWS GuardDuty identifies the finding type `Trojan:EC2/PhishingDomainRequest!DNS`. The EC2 resource shows suspicious DNS queries that may indicate malware, phishing, a domain generation algorithm (DGA), or exfiltration. The alert must be reviewed by the SOC to validate its legitimacy, scope, affected resource, and potential impact.

## Objective
Detect and prioritize potential malicious, anomalous, or unauthorized activities related to EC2 instances, enabling the SOC to initiate a structured investigation, reduce operational risk, and activate containment procedures when indicators of compromise are identified.

## Logic
The detection is triggered when an AWS GuardDuty event is received with `finding.type` equal to:

`Trojan:EC2/PhishingDomainRequest!DNS`

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
- **Primary Threat:** Trojan.
- **Family or Mechanism:** PhishingDomainRequest!DNS.
- The EC2 resource shows suspicious DNS queries that may indicate malware, phishing, a domain generation algorithm (DGA), or exfiltration. The analyst should consider credential compromise, malware infection, cloud service abuse, public exposure, evasion, reconnaissance, impact, or exfiltration depending on the technical context of the finding.
- **Data Sources:** AWS GuardDuty findings, VPC Flow Logs, DNS logs, AWS CloudTrail, EC2/SSM/EDR if available.

## Investigation Sources
- **AWS GuardDuty Finding Details:** finding ID, type, severity, title, description, firstSeen, lastSeen, count, accountId, region.
- **AWS CloudTrail:** API calls, userIdentity, sourceIPAddress, userAgent, errorCode, requestParameters, responseElements.
- **Network Logs:** VPC Flow Logs, DNS logs, ports, protocols, transferred bytes, remote IP, country, and ASN.
- **Resource Configuration:** tags, owner, policies, public exposure, security groups, ACLs, roles, or effective permissions.
- Operational validation with the resource owner, platform team, cloud team, DevOps team, or application owner.

## Sigma Rule

```yaml
title: 'AWS: Phishing Domain Request - DNS-Based - EC2'
id: c3713726-1ee1-5d55-8ec4-b97cc7c36f8b
status: experimental
description: |
    This GuardDuty finding indicates that a resource has queried a domain identified as actively hosting a
    phishing kit. It may represent a user or automated process reaching a credential-harvesting page, or a
    compromised resource retrieving further phishing infrastructure.
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
            - 'Trojan:EC2/PhishingDomainRequest!DNS'
    condition: selection
falsepositives:
    - 'An email-security or anti-phishing testing/training platform intentionally resolved the phishing domain to validate detection...'
    - 'A user or automated process accessed a URL shortener or redirect service that happens to currently point at a flagged phishing...'
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

- An email-security or anti-phishing testing/training platform intentionally resolved the phishing domain to validate detection coverage.
- A user or automated process accessed a URL shortener or redirect service that happens to currently point at a flagged phishing domain, unrelated to the resource itself being compromised.

### True Positives

- The EC2 instance resolved a domain actively hosting a phishing kit, and the connection correlates with a user-reported suspicious email or link around the same time.
- The resource has no legitimate reason to resolve general consumer-facing domains (e.g., it is a backend/API server).
- Credential-related activity (new logins, password resets, MFA changes) follows shortly after the phishing-domain lookup.

### True Negatives

- The lookup is confirmed to be part of an approved phishing-simulation exercise run by the security awareness team.

### False Negatives

- The phishing kit is taken down and the domain repurposed before GuardDuty's feed is updated, so a user who was actually phished earlier is not flagged retroactively.
- The phishing page is served from a compromised but otherwise reputable domain that has not yet accumulated enough abuse signal to be listed.

## References

- [EC2 finding types](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-ec2.html)
- [Remediating a potentially compromised Amazon EC2 instance](https://docs.aws.amazon.com/guardduty/latest/ug/compromised-ec2.html)
- [NIST SP 800-61r3: Incident Response Recommendations](https://csrc.nist.gov/pubs/sp/800/61/r3/final)
- [AWS Security Incident Response Guide (2023)](https://docs.aws.amazon.com/whitepapers/latest/aws-security-incident-response-guide/welcome.html)
