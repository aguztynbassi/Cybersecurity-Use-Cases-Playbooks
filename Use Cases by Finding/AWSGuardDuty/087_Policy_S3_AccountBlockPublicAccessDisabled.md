# Account-Level S3 Block Public Access Disabled

## Description
Alert generated when AWS GuardDuty identifies the finding type `Policy:S3/AccountBlockPublicAccessDisabled`. There is possible public exposure or anonymous access affecting the S3 bucket. The alert must be reviewed by the SOC to validate its legitimacy, scope, affected resource, and potential impact.

## Objective
Detect and prioritize potential malicious, anomalous, or unauthorized activities related to S3 buckets, enabling the SOC to initiate a structured investigation, reduce operational risk, and activate containment procedures when indicators of compromise are identified.

## Logic
The detection is triggered when an AWS GuardDuty event is received with `finding.type` equal to:

`Policy:S3/AccountBlockPublicAccessDisabled`

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

- T1098 - Account Manipulation
- T1562 - Impair Defenses

## Threat
- **Primary Threat:** Policy.
- **Family or Mechanism:** AccountBlockPublicAccessDisabled.
- There is possible public exposure or anonymous access affecting the S3 bucket. The analyst should consider credential compromise, malware infection, cloud service abuse, public exposure, evasion, reconnaissance, impact, or exfiltration depending on the technical context of the finding.
- **Data Sources:** AWS GuardDuty findings, CloudTrail S3 Data Events, S3 Server Access Logs, bucket policy/ACL configuration.

## Investigation Sources
- **AWS GuardDuty Finding Details:** finding ID, type, severity, title, description, firstSeen, lastSeen, count, accountId, region.
- **AWS CloudTrail:** API calls, userIdentity, sourceIPAddress, userAgent, errorCode, requestParameters, responseElements.
- **Network Logs:** VPC Flow Logs, DNS logs, ports, protocols, transferred bytes, remote IP, country, and ASN.
- **Resource Configuration:** tags, owner, policies, public exposure, security groups, ACLs, roles, or effective permissions.
- Operational validation with the resource owner, platform team, cloud team, DevOps team, or application owner.

## Sigma Rule

```yaml
title: 'AWS: Account-Level S3 Block Public Access Disabled'
id: cb278672-b4f7-57f3-ae8a-e7d9e9384405
status: experimental
description: |
    This GuardDuty finding indicates that the account-level S3 Block Public Access setting was disabled, removing
    a safety control that applies across every bucket in the account. Unintended public exposure of S3 data is one
    of the most common and highest-impact cloud misconfigurations, and should be remediated immediately if not
    explicitly intended.
references:
    - 'https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-s3.html'
    - 'https://docs.aws.amazon.com/guardduty/latest/ug/compromised-s3.html'
    - 'https://csrc.nist.gov/pubs/sp/800/61/r3/final'
    - 'https://docs.aws.amazon.com/whitepapers/latest/aws-security-incident-response-guide/welcome.html'
date: '2026-10-13'
modified: '2026-10-13'
author: 'https://github.com/aguztynbassi'
tags:
    - attack.t1098
    - attack.t1562
logsource:
    category: cloud
    product: aws
    service: guardduty
detection:
    selection:
        detail.type:
            - 'Policy:S3/AccountBlockPublicAccessDisabled'
    condition: selection
falsepositives:
    - 'A developer or platform team intentionally configured the bucket for a legitimate public-hosting use case (e.g., static website...'
    - 'An infrastructure-as-code deployment briefly toggled the setting as part of a larger, approved change that re-secures the bucket...'
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

- A developer or platform team intentionally configured the bucket for a legitimate public-hosting use case (e.g., static website hosting, public open-data distribution) following an approved architecture review.
- An infrastructure-as-code deployment briefly toggled the setting as part of a larger, approved change that re-secures the bucket immediately afterward.

### True Positives

- An identity with no documented reason to manage bucket security made a change where the account-level S3 Block Public Access setting was disabled, removing a safety control that applies across every bucket in the account, and the bucket contains sensitive or non-public data.
- The change was made outside of change management, with no corresponding ticket, pull request, or administrator acknowledgment.
- External scanning tools (Shodan, GrayNoise, or similar) or unexpected GET requests from unknown IPs are observed against the bucket shortly after the change.
- The owner confirms the bucket should never be publicly accessible given its contents.

### True Negatives

- The bucket is intentionally public by design (e.g., it hosts public website assets, open datasets, or public release artifacts) and the configuration matches its documented purpose.

### False Negatives

- The bucket is made public very briefly (a short configuration window) and reverted before any external scanner discovers and reports on it, though data may still have been accessed during the window.
- Public access is granted through a mechanism not covered by this specific finding (e.g., a pre-signed URL shared externally, or a CloudFront OAI misconfiguration).

## References

- [S3 Protection finding types](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-s3.html)
- [Remediating a potentially compromised S3 bucket](https://docs.aws.amazon.com/guardduty/latest/ug/compromised-s3.html)
- [NIST SP 800-61r3: Incident Response Recommendations](https://csrc.nist.gov/pubs/sp/800/61/r3/final)
- [AWS Security Incident Response Guide (2023)](https://docs.aws.amazon.com/whitepapers/latest/aws-security-incident-response-guide/welcome.html)
