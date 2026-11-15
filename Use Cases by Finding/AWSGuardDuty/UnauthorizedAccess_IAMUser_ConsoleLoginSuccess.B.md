# Anomalous Console Login Success - IAM User

## Description
Alert generated when AWS GuardDuty identifies the finding type `UnauthorizedAccess:IAMUser/ConsoleLoginSuccess.B`. Suspicious or unexpected activity associated with the IAM user or role has been detected. The alert must be reviewed by the SOC to validate its legitimacy, scope, affected resource, and potential impact.

## Objective
Detect and prioritize potential malicious, anomalous, or unauthorized activities related to IAM users and roles, enabling the SOC to initiate a structured investigation, reduce operational risk, and activate containment procedures when indicators of compromise are identified.

## Logic
The detection is triggered when an AWS GuardDuty event is received with `finding.type` equal to:

`UnauthorizedAccess:IAMUser/ConsoleLoginSuccess.B`

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
- **Family or Mechanism:** ConsoleLoginSuccess.B.
- Suspicious or unexpected activity associated with the IAM user or role has been detected. The analyst should consider credential compromise, malware infection, cloud service abuse, public exposure, evasion, reconnaissance, impact, or exfiltration depending on the technical context of the finding.
- **Data Sources:** AWS GuardDuty findings, AWS CloudTrail Management Events, IAM Credential Report, AWS IAM Access Analyzer.

## Investigation Sources
- **AWS GuardDuty Finding Details:** finding ID, type, severity, title, description, firstSeen, lastSeen, count, accountId, region.
- **AWS CloudTrail:** API calls, userIdentity, sourceIPAddress, userAgent, errorCode, requestParameters, responseElements.
- **Network Logs:** VPC Flow Logs, DNS logs, ports, protocols, transferred bytes, remote IP, country, and ASN.
- **Resource Configuration:** tags, owner, policies, public exposure, security groups, ACLs, roles, or effective permissions.
- Operational validation with the resource owner, platform team, cloud team, DevOps team, or application owner.

## Sigma Rule

```yaml
title: 'AWS: Anomalous Console Login Success - IAM User'
id: 5205736f-376b-554e-8434-43dd131f0d96
status: experimental
description: |
    This GuardDuty finding uses machine-learning behavioral analysis to flag a console login that deviates from
    the IAM user's established baseline (location, device, ASN, timing). It should be correlated directly with the
    account owner to confirm legitimacy.
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
            - 'UnauthorizedAccess:IAMUser/ConsoleLoginSuccess.B'
    condition: selection
falsepositives:
    - 'The user is traveling, or recently switched ISP/VPN endpoint, and the new login location/device is legitimate but unfamiliar to...'
    - 'The organization rolled out a new corporate VPN or proxy egress point that shifts the apparent source location for many users at...'
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

- The user is traveling, or recently switched ISP/VPN endpoint, and the new login location/device is legitimate but unfamiliar to the baseline.
- The organization rolled out a new corporate VPN or proxy egress point that shifts the apparent source location for many users at once.

### True Positives

- A successful console login occurs from a geolocation, ASN, or device fingerprint with no plausible relationship to the user's normal pattern (e.g., impossible travel between two logins).
- The login is followed by unusual console activity: new access keys, new users, policy changes, or access to services the user has never touched before.
- The user denies initiating the login when contacted by the SOC.
- MFA was bypassed, not required, or satisfied via a method the legitimate user does not recognize (e.g., MFA fatigue approval).

### True Negatives

- The user confirms the login as their own, explaining the new location/device (travel, new laptop, new network).

### False Negatives

- The attacker logs in from an IP in the same geographic region and ASN as the legitimate user (e.g., using a local residential proxy), defeating geolocation-based anomaly detection.
- The compromised session is short-lived and performs only read-level reconnaissance that does not trigger a secondary behavioral alert.

## References

- [IAM finding types](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-iam.html)
- [Remediating potentially compromised AWS credentials](https://docs.aws.amazon.com/guardduty/latest/ug/compromised-creds.html)
- [NIST SP 800-61r3: Incident Response Recommendations](https://csrc.nist.gov/pubs/sp/800/61/r3/final)
- [AWS Security Incident Response Guide (2023)](https://docs.aws.amazon.com/whitepapers/latest/aws-security-incident-response-guide/welcome.html)
