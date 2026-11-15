# Unusual DNS Resolver - EC2

## Description
Alert generated when AWS GuardDuty identifies the finding type `DefenseEvasion:EC2/UnusualDNSResolver`. Suspicious or unexpected activity associated with the EC2 resource has been detected. The alert must be reviewed by the SOC to validate its legitimacy, scope, affected resource, and potential impact.

## Objective
Detect and prioritize potential malicious, anomalous, or unauthorized activities related to EC2 instances, enabling the SOC to initiate a structured investigation, reduce operational risk, and activate containment procedures when indicators of compromise are identified.

## Logic
The detection is triggered when an AWS GuardDuty event is received with `finding.type` equal to:

`DefenseEvasion:EC2/UnusualDNSResolver`

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
- **Family or Mechanism:** UnusualDNSResolver.
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
title: 'AWS: Unusual DNS Resolver - EC2'
id: 4692a2b6-8fc8-5cab-8507-8fb7e069a553
status: experimental
description: |
    This GuardDuty finding indicates that an EC2 instance is using a DNS resolver outside the VPC's
    configured/expected resolver, which can be a technique used by malware to evade traditional DNS-based security
    monitoring and filtering. It should be correlated with the resource's expected DNS configuration.
references:
    - 'https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-ec2.html'
    - 'https://docs.aws.amazon.com/guardduty/latest/ug/compromised-ec2.html'
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
            - 'DefenseEvasion:EC2/UnusualDNSResolver'
    condition: selection
falsepositives:
    - 'A browser, OS component, or application on the instance defaults to public a DNS resolver outside the VPC''s configured/expected...'
    - 'A VPN client, privacy tool, or corporate endpoint agent legitimately redirects DNS through an external encrypted resolver.'
    - 'A recently onboarded workload has not yet been configured to use the VPC''s internal/Route 53 resolver.'
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

- A browser, OS component, or application on the instance defaults to public a DNS resolver outside the VPC's configured/expected resolver for privacy reasons, unrelated to any malicious intent.
- A VPN client, privacy tool, or corporate endpoint agent legitimately redirects DNS through an external encrypted resolver.
- A recently onboarded workload has not yet been configured to use the VPC's internal/Route 53 resolver.

### True Positives

- Malware or an implant on the instance is deliberately using a DNS resolver outside the VPC's configured/expected resolver to hide DNS lookups to C2 or exfiltration infrastructure from network-layer DNS monitoring.
- The encrypted DNS traffic began immediately following another suspicious event (new binary, suspicious login, outbound beacon) on the same host.
- The destination resolver is not one used anywhere else in the environment and has no approved business purpose.

### True Negatives

- The resolver is a documented, approved encrypted-DNS provider used consistently across the fleet as part of a privacy or compliance initiative.

### False Negatives

- The malicious DNS-over-HTTPS traffic is routed through a widely-used, reputable public DoH provider that blends in with legitimate traffic and is not separately flagged.
- Resolution volume is kept low and infrequent enough to avoid tripping the behavioral baseline for this finding.

## References

- [EC2 finding types](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-ec2.html)
- [Remediating a potentially compromised Amazon EC2 instance](https://docs.aws.amazon.com/guardduty/latest/ug/compromised-ec2.html)
- [NIST SP 800-61r3: Incident Response Recommendations](https://csrc.nist.gov/pubs/sp/800/61/r3/final)
- [AWS Security Incident Response Guide (2023)](https://docs.aws.amazon.com/whitepapers/latest/aws-security-incident-response-guide/welcome.html)
