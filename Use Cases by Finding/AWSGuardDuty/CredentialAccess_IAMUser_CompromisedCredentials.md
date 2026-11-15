# Compromised Credentials - IAM User

## Description
Alert generated when AWS GuardDuty identifies the finding type `CredentialAccess:IAMUser/CompromisedCredentials`. GuardDuty has correlated multiple signals consistent with a compromise affecting the IAM user or role. The alert must be reviewed by the SOC to validate its legitimacy, scope, affected resource, and potential impact.

## Objective
Detect and prioritize potential malicious, anomalous, or unauthorized activities related to IAM users and roles, enabling the SOC to initiate a structured investigation, reduce operational risk, and activate containment procedures when indicators of compromise are identified.

## Logic
The detection is triggered when an AWS GuardDuty event is received with `finding.type` equal to:

`CredentialAccess:IAMUser/CompromisedCredentials`

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
- **Family or Mechanism:** CompromisedCredentials.
- GuardDuty has correlated multiple signals consistent with a compromise affecting the IAM user or role. The analyst should consider credential compromise, malware infection, cloud service abuse, public exposure, evasion, reconnaissance, impact, or exfiltration depending on the technical context of the finding.
- **Data Sources:** AWS GuardDuty findings, AWS CloudTrail Management Events, IAM Credential Report, AWS IAM Access Analyzer.

## Investigation Sources
- **AWS GuardDuty Finding Details:** finding ID, type, severity, title, description, firstSeen, lastSeen, count, accountId, region.
- **AWS CloudTrail:** API calls, userIdentity, sourceIPAddress, userAgent, errorCode, requestParameters, responseElements.
- **Network Logs:** VPC Flow Logs, DNS logs, ports, protocols, transferred bytes, remote IP, country, and ASN.
- **Resource Configuration:** tags, owner, policies, public exposure, security groups, ACLs, roles, or effective permissions.
- Operational validation with the resource owner, platform team, cloud team, DevOps team, or application owner.

## Sigma Rule

```yaml
title: 'AWS: Compromised Credentials - IAM User'
id: ec63a446-d581-54ad-8a9a-a698a60a203d
status: experimental
description: |
    This GuardDuty finding indicates that an IAM credential has been identified by AWS threat intelligence as
    exposed/compromised (for example, found in a public code repository), and is being actively used. This should
    be treated as a near-certain compromise requiring immediate key rotation and scoped review of everything the
    credential touched.
references:
    - 'https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-iam.html'
    - 'https://docs.aws.amazon.com/guardduty/latest/ug/compromised-creds.html'
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
            - 'CredentialAccess:IAMUser/CompromisedCredentials'
    condition: selection
falsepositives:
    - 'The credential was rotated or deactivated immediately after being flagged elsewhere (e.g., by a secret-scanning tool) and the...'
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

- The credential was rotated or deactivated immediately after being flagged elsewhere (e.g., by a secret-scanning tool) and the usage GuardDuty observed was the organization's own remediation/validation activity.

### True Positives

- The access key or secret was found exposed in a public location (GitHub repository, paste site, container image) per AWS's threat intelligence, and it is actively being used.
- API calls made with the credential originate from IP ranges or ASNs with no relationship to the organization.
- Usage includes reconnaissance or privilege-escalation calls inconsistent with the credential's normal workload.
- The credential is used to create new access keys or users shortly after the leak is detected, a common attacker persistence move.

### True Negatives

- The credential was already deactivated/rotated before any unauthorized usage occurred.

### False Negatives

- The credential is leaked and exploited in a private channel not covered by AWS's public-exposure scanning (e.g., a private forum, a sold credential dump).
- The attacker uses the credential briefly and sparingly, avoiding the volume or pattern needed to generate a secondary anomaly signal.

## References

- [IAM finding types](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-iam.html)
- [Remediating potentially compromised AWS credentials](https://docs.aws.amazon.com/guardduty/latest/ug/compromised-creds.html)
- [NIST SP 800-61r3: Incident Response Recommendations](https://csrc.nist.gov/pubs/sp/800/61/r3/final)
- [AWS Security Incident Response Guide (2023)](https://docs.aws.amazon.com/whitepapers/latest/aws-security-incident-response-guide/welcome.html)
