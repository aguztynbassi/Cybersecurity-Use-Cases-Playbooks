# Tor IP Caller - IAM User (Unauthorized Access)

## Description
Alert generated when AWS GuardDuty identifies the finding type `UnauthorizedAccess:IAMUser/TorIPCaller`. Activity associated with Tor infrastructure has been detected involving the IAM user or role. The alert must be reviewed by the SOC to validate its legitimacy, scope, affected resource, and potential impact.

## Objective
Detect and prioritize potential malicious, anomalous, or unauthorized activities related to IAM users and roles, enabling the SOC to initiate a structured investigation, reduce operational risk, and activate containment procedures when indicators of compromise are identified.

## Logic
The detection is triggered when an AWS GuardDuty event is received with `finding.type` equal to:

`UnauthorizedAccess:IAMUser/TorIPCaller`

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
- **Family or Mechanism:** TorIPCaller.
- Activity associated with Tor infrastructure has been detected involving the IAM user or role. The analyst should consider credential compromise, malware infection, cloud service abuse, public exposure, evasion, reconnaissance, impact, or exfiltration depending on the technical context of the finding.
- **Data Sources:** AWS GuardDuty findings, AWS CloudTrail Management Events, IAM Credential Report, AWS IAM Access Analyzer.

## Investigation Sources
- **AWS GuardDuty Finding Details:** finding ID, type, severity, title, description, firstSeen, lastSeen, count, accountId, region.
- **AWS CloudTrail:** API calls, userIdentity, sourceIPAddress, userAgent, errorCode, requestParameters, responseElements.
- **Network Logs:** VPC Flow Logs, DNS logs, ports, protocols, transferred bytes, remote IP, country, and ASN.
- **Resource Configuration:** tags, owner, policies, public exposure, security groups, ACLs, roles, or effective permissions.
- Operational validation with the resource owner, platform team, cloud team, DevOps team, or application owner.

## Sigma Rule

```yaml
title: 'AWS: Tor IP Caller - IAM User (Unauthorized Access)'
id: 94895734-dc46-5764-badf-e19aa39fe423
status: experimental
description: |
    This GuardDuty finding indicates that a request originating from a known Tor exit node made an API call or
    established a connection against the IAM identity. Since most organizations have no legitimate reason to
    access their AWS resources over the Tor anonymization network, this is a strong indicator of an attempt to
    hide the true source of potentially malicious activity.
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
            - 'UnauthorizedAccess:IAMUser/TorIPCaller'
    condition: selection
falsepositives:
    - 'A privacy-conscious employee or authorized researcher intentionally used the Tor network to access the resource for a legitimate...'
    - 'A security assessment or bug-bounty researcher is using Tor as part of an approved external testing engagement.'
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

- A privacy-conscious employee or authorized researcher intentionally used the Tor network to access the resource for a legitimate reason (should be rare and explicitly policy-approved).
- A security assessment or bug-bounty researcher is using Tor as part of an approved external testing engagement.

### True Positives

- A request originating from a Tor exit node made an API call or established a connection against the IAM identity with no approved business reason to use an anonymization network.
- The Tor-sourced request succeeds in authenticating or retrieving data, rather than merely failing/bouncing off access controls.
- The Tor access coincides with other suspicious activity on the same account or credentials from non-Tor sources, suggesting an attacker probing from multiple vantage points.

### True Negatives

- Organizational policy explicitly permits Tor usage for this use case (e.g., a documented whistleblower or research intake channel) and the access matches that approved pattern.
- The request failed authentication and no resource access occurred.

### False Negatives

- The attacker uses a Tor bridge or pluggable transport not yet classified as a Tor exit node by GuardDuty's intelligence feed.
- The same session later pivots off Tor onto a clean residential or cloud IP, so only the initial access shows the Tor indicator.

## References

- [IAM finding types](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-iam.html)
- [Remediating potentially compromised AWS credentials](https://docs.aws.amazon.com/guardduty/latest/ug/compromised-creds.html)
- [NIST SP 800-61r3: Incident Response Recommendations](https://csrc.nist.gov/pubs/sp/800/61/r3/final)
- [AWS Security Incident Response Guide (2023)](https://docs.aws.amazon.com/whitepapers/latest/aws-security-incident-response-guide/welcome.html)
