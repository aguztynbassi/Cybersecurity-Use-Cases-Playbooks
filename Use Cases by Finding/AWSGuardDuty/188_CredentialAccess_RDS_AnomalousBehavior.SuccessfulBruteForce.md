# Anomalous Successful Brute Force - RDS

## Description
Alert generated when AWS GuardDuty identifies the finding type `CredentialAccess:RDS/AnomalousBehavior.SuccessfulBruteForce`. Brute-force attempts have been observed against services associated with the RDS database. The alert must be reviewed by the SOC to validate its legitimacy, scope, affected resource, and potential impact.

## Objective
Detect and prioritize potential malicious, anomalous, or unauthorized activities related to RDS database instances, enabling the SOC to initiate a structured investigation, reduce operational risk, and activate containment procedures when indicators of compromise are identified.

## Logic
The detection is triggered when an AWS GuardDuty event is received with `finding.type` equal to:

`CredentialAccess:RDS/AnomalousBehavior.SuccessfulBruteForce`

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
- **Family or Mechanism:** AnomalousBehavior.SuccessfulBruteForce.
- Brute-force attempts have been observed against services associated with the RDS database. The analyst should consider credential compromise, malware infection, cloud service abuse, public exposure, evasion, reconnaissance, impact, or exfiltration depending on the technical context of the finding.
- **Data Sources:** AWS GuardDuty findings, RDS database logs, CloudTrail, VPC Flow Logs.

## Investigation Sources
- **AWS GuardDuty Finding Details:** finding ID, type, severity, title, description, firstSeen, lastSeen, count, accountId, region.
- **AWS CloudTrail:** API calls, userIdentity, sourceIPAddress, userAgent, errorCode, requestParameters, responseElements.
- **Network Logs:** VPC Flow Logs, DNS logs, ports, protocols, transferred bytes, remote IP, country, and ASN.
- **Resource Configuration:** tags, owner, policies, public exposure, security groups, ACLs, roles, or effective permissions.
- Operational validation with the resource owner, platform team, cloud team, DevOps team, or application owner.

## Sigma Rule

```yaml
title: 'AWS: Anomalous Successful Brute Force - RDS'
id: 66feeb83-1163-5533-add1-6d22d4b0493c
status: experimental
description: |
    This GuardDuty RDS Protection finding uses machine-learning behavioral analysis on database login activity to
    flag that a successful login followed a pattern of failed attempts consistent with a successful brute-
    force/credential-guessing attack against the database.
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
            - 'CredentialAccess:RDS/AnomalousBehavior.SuccessfulBruteForce'
    condition: selection
falsepositives:
    - 'A new application server, migration job, or database client was deployed and is connecting for the first time, and its usage...'
    - 'A database administrator performed legitimate, approved maintenance (patching, failover testing) that generated an unusual login...'
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

- A new application server, migration job, or database client was deployed and is connecting for the first time, and its usage simply had not yet been reflected in the baseline.
- A database administrator performed legitimate, approved maintenance (patching, failover testing) that generated an unusual login pattern.

### True Positives

- A successful login followed a pattern of failed attempts consistent with a successful brute-force/credential-guessing attack against the database, with no corresponding change ticket or administrator acknowledgment.
- The connecting identity, source IP, or client application has no legitimate relationship to this database.
- The login is followed by unusual queries (bulk SELECTs, schema changes, new user creation) inconsistent with the application's normal workload.

### True Negatives

- The owner confirms the login pattern matches an approved, documented change (new app server, migration, maintenance).

### False Negatives

- The attacker successfully guesses or obtains valid credentials on the first or second attempt, producing too few failed logins to stand out from baseline noise.
- Login activity closely mimics an existing, legitimate application's pattern (same source IP range, similar timing), staying within the learned baseline.

## References

- [RDS Protection finding types](https://docs.aws.amazon.com/guardduty/latest/ug/findings-rds-protection.html)
- [Remediating a potentially compromised database](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty-remediate-compromised-database-rds.html)
- [NIST SP 800-61r3: Incident Response Recommendations](https://csrc.nist.gov/pubs/sp/800/61/r3/final)
- [AWS Security Incident Response Guide (2023)](https://docs.aws.amazon.com/whitepapers/latest/aws-security-incident-response-guide/welcome.html)
