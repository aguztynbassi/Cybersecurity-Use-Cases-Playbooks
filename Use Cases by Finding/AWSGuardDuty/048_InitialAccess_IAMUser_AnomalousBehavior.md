# Anomalous Behavior - IAM User (Initial Access)

## Description
Alert generated when AWS GuardDuty identifies the finding type `InitialAccess:IAMUser/AnomalousBehavior`. Anomalous behavior has been detected affecting the IAM user or role, relative to its expected baseline. The alert must be reviewed by the SOC to validate its legitimacy, scope, affected resource, and potential impact.

## Objective
Detect and prioritize potential malicious, anomalous, or unauthorized activities related to IAM users and roles, enabling the SOC to initiate a structured investigation, reduce operational risk, and activate containment procedures when indicators of compromise are identified.

## Logic
The detection is triggered when an AWS GuardDuty event is received with `finding.type` equal to:

`InitialAccess:IAMUser/AnomalousBehavior`

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
- **Primary Threat:** Initial Access.
- **Family or Mechanism:** AnomalousBehavior.
- Anomalous behavior has been detected affecting the IAM user or role, relative to its expected baseline. The analyst should consider credential compromise, malware infection, cloud service abuse, public exposure, evasion, reconnaissance, impact, or exfiltration depending on the technical context of the finding.
- **Data Sources:** AWS GuardDuty findings, AWS CloudTrail Management Events, IAM Credential Report, AWS IAM Access Analyzer.

## Investigation Sources
- **AWS GuardDuty Finding Details:** finding ID, type, severity, title, description, firstSeen, lastSeen, count, accountId, region.
- **AWS CloudTrail:** API calls, userIdentity, sourceIPAddress, userAgent, errorCode, requestParameters, responseElements.
- **Network Logs:** VPC Flow Logs, DNS logs, ports, protocols, transferred bytes, remote IP, country, and ASN.
- **Resource Configuration:** tags, owner, policies, public exposure, security groups, ACLs, roles, or effective permissions.
- Operational validation with the resource owner, platform team, cloud team, DevOps team, or application owner.

## Sigma Rule

```yaml
title: 'AWS: Anomalous Behavior - IAM User (Initial Access)'
id: 2e508c7c-4aaf-55cc-9f5c-9ad252bcc3f4
status: experimental
description: |
    This GuardDuty finding uses machine-learning behavioral analysis to flag an IAM identity the identity to gain
    an initial foothold, often from an unusual entry point relative to its own historical baseline.
references:
    - 'https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-iam.html'
    - 'https://docs.aws.amazon.com/guardduty/latest/ug/compromised-creds.html'
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
            - 'InitialAccess:IAMUser/AnomalousBehavior'
    condition: selection
falsepositives:
    - 'The IAM user or role recently changed job function, team, or automation purpose, and is now legitimately calling APIs it has...'
    - 'A new CI/CD pipeline, migration, or one-time administrative task causes a legitimate but unusual burst of activity for this...'
    - 'GuardDuty''s behavioral model has not yet adapted to a recent, approved change in how this identity is used.'
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

- The IAM user or role recently changed job function, team, or automation purpose, and is now legitimately calling APIs it has never used before.
- A new CI/CD pipeline, migration, or one-time administrative task causes a legitimate but unusual burst of activity for this identity.
- GuardDuty's behavioral model has not yet adapted to a recent, approved change in how this identity is used.

### True Positives

- The identity is using the identity to gain an initial foothold, often from an unusual entry point, and the specific API calls observed have no legitimate business justification when confirmed with the owner.
- The anomalous activity coincides with other indicators of compromise (new access key, unfamiliar source IP, MFA changes) for the same identity.
- The owner of the identity cannot explain the activity when contacted.
- The behavior escalates over successive observations (broader scope, more sensitive APIs) rather than returning to baseline.

### True Negatives

- The owner confirms the activity matches a planned, approved change to how the identity is used.

### False Negatives

- The attacker mimics the identity's normal usage pattern closely enough (same services, similar call volume) to stay within the learned baseline.
- The compromise is so recent that insufficient baseline history exists for GuardDuty's model to flag the deviation with confidence.

## References

- [IAM finding types](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-iam.html)
- [Remediating potentially compromised AWS credentials](https://docs.aws.amazon.com/guardduty/latest/ug/compromised-creds.html)
- [NIST SP 800-61r3: Incident Response Recommendations](https://csrc.nist.gov/pubs/sp/800/61/r3/final)
- [AWS Security Incident Response Guide (2023)](https://docs.aws.amazon.com/whitepapers/latest/aws-security-incident-response-guide/welcome.html)
