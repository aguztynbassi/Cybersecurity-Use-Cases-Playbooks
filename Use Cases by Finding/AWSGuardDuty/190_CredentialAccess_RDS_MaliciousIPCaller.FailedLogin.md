# Failed Login From a Known-Malicious IP - RDS

## Description
Alert generated when AWS GuardDuty identifies the finding type `CredentialAccess:RDS/MaliciousIPCaller.FailedLogin`. Activity to or from an IP address classified as malicious has been detected involving the RDS database. The alert must be reviewed by the SOC to validate its legitimacy, scope, affected resource, and potential impact.

## Objective
Detect and prioritize potential malicious, anomalous, or unauthorized activities related to RDS database instances, enabling the SOC to initiate a structured investigation, reduce operational risk, and activate containment procedures when indicators of compromise are identified.

## Logic
The detection is triggered when an AWS GuardDuty event is received with `finding.type` equal to:

`CredentialAccess:RDS/MaliciousIPCaller.FailedLogin`

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

- T1552 - Unsecured Credentials
- T1078 - Valid Accounts (depending on context)

## Threat
- **Primary Threat:** Credential Access.
- **Family or Mechanism:** MaliciousIPCaller.FailedLogin.
- Activity to or from an IP address classified as malicious has been detected involving the RDS database. The analyst should consider credential compromise, malware infection, cloud service abuse, public exposure, evasion, reconnaissance, impact, or exfiltration depending on the technical context of the finding.
- **Data Sources:** AWS GuardDuty findings, RDS database logs, CloudTrail, VPC Flow Logs.

## Investigation Sources
- **AWS GuardDuty Finding Details:** finding ID, type, severity, title, description, firstSeen, lastSeen, count, accountId, region.
- **AWS CloudTrail:** API calls, userIdentity, sourceIPAddress, userAgent, errorCode, requestParameters, responseElements.
- **Network Logs:** VPC Flow Logs, DNS logs, ports, protocols, transferred bytes, remote IP, country, and ASN.
- **Resource Configuration:** tags, owner, policies, public exposure, security groups, ACLs, roles, or effective permissions.
- Operational validation with the resource owner, platform team, cloud team, DevOps team, or application owner.

## Sigma Rule

```yaml
title: 'AWS: Failed Login From a Known-Malicious IP - RDS'
id: 55cd3022-4445-5287-be8c-d6382f74d509
status: experimental
description: |
    This GuardDuty RDS Protection finding indicates that a login attempt to the database from an IP address on
    AWS's threat-intelligence feed of known-malicious IPs failed. This should be investigated immediately given
    the direct exposure of the database to a known-malicious source.
references:
    - 'https://docs.aws.amazon.com/guardduty/latest/ug/findings-rds-protection.html'
    - 'https://docs.aws.amazon.com/guardduty/latest/ug/guardduty-remediate-compromised-database-rds.html'
    - 'https://csrc.nist.gov/pubs/sp/800/61/r3/final'
    - 'https://docs.aws.amazon.com/whitepapers/latest/aws-security-incident-response-guide/welcome.html'
date: '2026-10-13'
modified: '2026-10-13'
author: 'https://github.com/aguztynbassi'
tags:
    - attack.t1552
    - attack.t1078
logsource:
    category: cloud
    product: aws
    service: guardduty
detection:
    selection:
        detail.type:
            - 'CredentialAccess:RDS/MaliciousIPCaller.FailedLogin'
    condition: selection
falsepositives:
    - 'The source IP was recently reassigned and no longer belongs to the malicious actor originally associated with it.'
    - 'A legitimate partner or integration egresses from an IP range that overlaps with a shared/dynamic address previously flagged on a...'
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

- The source IP was recently reassigned and no longer belongs to the malicious actor originally associated with it.
- A legitimate partner or integration egresses from an IP range that overlaps with a shared/dynamic address previously flagged on a threat-intelligence feed.

### True Positives

- A login attempt to the RDS database from an IP address on AWS's threat-intelligence feed of known-malicious IPs failed, which at minimum confirms the database is directly reachable by a known-malicious actor and should prompt an immediate review of network exposure and credential strength.
- The same source IP has a documented history of attacking unrelated AWS accounts or databases per threat intelligence.

### True Negatives

- The login attempt failed and the database is confirmed not reachable from the public internet, limiting the practical risk of the exposure.

### False Negatives

- The attacker uses a fresh or residential-proxy IP not yet present on any threat-intelligence feed.
- A successful login from a malicious IP is followed by very limited, quiet activity that does not generate a secondary anomaly signal.

## References

- [RDS Protection finding types](https://docs.aws.amazon.com/guardduty/latest/ug/findings-rds-protection.html)
- [Remediating a potentially compromised database](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty-remediate-compromised-database-rds.html)
- [NIST SP 800-61r3: Incident Response Recommendations](https://csrc.nist.gov/pubs/sp/800/61/r3/final)
- [AWS Security Incident Response Guide (2023)](https://docs.aws.amazon.com/whitepapers/latest/aws-security-incident-response-guide/welcome.html)
