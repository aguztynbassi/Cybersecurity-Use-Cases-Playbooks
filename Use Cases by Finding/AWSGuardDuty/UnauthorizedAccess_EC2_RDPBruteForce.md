# RDP Brute Force - EC2

## Description
Alert generated when AWS GuardDuty identifies the finding type `UnauthorizedAccess:EC2/RDPBruteForce`. Brute-force attempts have been observed against services associated with the EC2 resource. The alert must be reviewed by the SOC to validate its legitimacy, scope, affected resource, and potential impact.

## Objective
Detect and prioritize potential malicious, anomalous, or unauthorized activities related to EC2 instances, enabling the SOC to initiate a structured investigation, reduce operational risk, and activate containment procedures when indicators of compromise are identified.

## Logic
The detection is triggered when an AWS GuardDuty event is received with `finding.type` equal to:

`UnauthorizedAccess:EC2/RDPBruteForce`

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

- T1078.004 - Valid Accounts: Cloud Accounts

## Threat
- **Primary Threat:** Unauthorized Access.
- **Family or Mechanism:** RDPBruteForce.
- Brute-force attempts have been observed against services associated with the EC2 resource. The analyst should consider credential compromise, malware infection, cloud service abuse, public exposure, evasion, reconnaissance, impact, or exfiltration depending on the technical context of the finding.
- **Data Sources:** AWS GuardDuty findings, VPC Flow Logs, DNS logs, AWS CloudTrail, EC2/SSM/EDR if available.

## Investigation Sources
- **AWS GuardDuty Finding Details:** finding ID, type, severity, title, description, firstSeen, lastSeen, count, accountId, region.
- **AWS CloudTrail:** API calls, userIdentity, sourceIPAddress, userAgent, errorCode, requestParameters, responseElements.
- **Network Logs:** VPC Flow Logs, DNS logs, ports, protocols, transferred bytes, remote IP, country, and ASN.
- **Resource Configuration:** tags, owner, policies, public exposure, security groups, ACLs, roles, or effective permissions.
- Operational validation with the resource owner, platform team, cloud team, DevOps team, or application owner.

## Sigma Rule

```yaml
title: 'AWS: RDP Brute Force - EC2'
id: 672ac9f6-33e3-55c0-aace-8a97f954efac
status: experimental
description: |
    This GuardDuty finding indicates that an external source is attempting to brute-force RDP credentials against
    an EC2 instance. A successful brute-force would grant the attacker direct interactive access to the instance.
references:
    - 'https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-ec2.html'
    - 'https://docs.aws.amazon.com/guardduty/latest/ug/compromised-ec2.html'
    - 'https://csrc.nist.gov/pubs/sp/800/61/r3/final'
    - 'https://docs.aws.amazon.com/whitepapers/latest/aws-security-incident-response-guide/welcome.html'
date: '2026-10-13'
modified: '2026-10-13'
author: 'https://github.com/aguztynbassi'
tags:
    - attack.t1078.004
logsource:
    category: cloud
    product: aws
    service: guardduty
detection:
    selection:
        detail.type:
            - 'UnauthorizedAccess:EC2/RDPBruteForce'
    condition: selection
falsepositives:
    - 'An internal vulnerability scanner or authorized penetration test attempted RDP logins against the instance as part of an approved...'
    - 'A misconfigured automation or monitoring script is retrying failed credentials repeatedly against its own target by mistake.'
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

- An internal vulnerability scanner or authorized penetration test attempted RDP logins against the instance as part of an approved assessment.
- A misconfigured automation or monitoring script is retrying failed credentials repeatedly against its own target by mistake.

### True Positives

- An external IP with no legitimate relationship to the organization is attempting a high volume of RDP logins against the EC2 instance in a short window, consistent with credential brute-forcing.
- One or more of the brute-force attempts succeeds, and a new session, process, or outbound connection follows shortly after.
- The source IP has a documented history of brute-force activity against unrelated AWS accounts per threat intelligence.

### True Negatives

- RDP access to the instance is restricted via security group to a known, approved set of source IPs, and the attempts were blocked at the network layer before reaching the service.
- All attempts failed and no successful authentication occurred.

### False Negatives

- The attacker paces login attempts slowly (low-and-slow) across a long time window to stay under the volumetric threshold.
- RDP access is exposed on a non-standard port that is outside the scope of what GuardDuty's signature covers for this finding.

## References

- [EC2 finding types](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-ec2.html)
- [Remediating a potentially compromised Amazon EC2 instance](https://docs.aws.amazon.com/guardduty/latest/ug/compromised-ec2.html)
- [NIST SP 800-61r3: Incident Response Recommendations](https://csrc.nist.gov/pubs/sp/800/61/r3/final)
- [AWS Security Incident Response Guide (2023)](https://docs.aws.amazon.com/whitepapers/latest/aws-security-incident-response-guide/welcome.html)
