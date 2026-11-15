# Instance Credential Exfiltration (Inside AWS) - IAM User

## Description
Alert generated when AWS GuardDuty identifies the finding type `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.InsideAWS`. Suspicious or unexpected activity associated with the IAM user or role has been detected. The alert must be reviewed by the SOC to validate its legitimacy, scope, affected resource, and potential impact.

## Objective
Detect and prioritize potential malicious, anomalous, or unauthorized activities related to IAM users and roles, enabling the SOC to initiate a structured investigation, reduce operational risk, and activate containment procedures when indicators of compromise are identified.

## Logic
The detection is triggered when an AWS GuardDuty event is received with `finding.type` equal to:

`UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.InsideAWS`

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
- **Family or Mechanism:** InstanceCredentialExfiltration.InsideAWS.
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
title: 'AWS: Instance Credential Exfiltration (Inside AWS) - IAM User'
id: 4504d827-4737-5a9f-9fc1-36f95d12e3fb
status: experimental
description: |
    This GuardDuty finding indicates that temporary credentials belonging to an EC2 instance's IAM role were used
    from outside the instance that obtained them, which typically means the credentials were stolen (often via
    SSRF against the instance metadata service) and are now being used by an attacker.
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
            - 'UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.InsideAWS'
    condition: selection
falsepositives:
    - 'A legitimate automation or CI/CD pipeline retrieves the instance''s temporary credentials and relays them through an internal...'
    - 'An approved multi-account architecture intentionally passes assumed-role credentials between resources for orchestration purposes.'
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

- A legitimate automation or CI/CD pipeline retrieves the instance's temporary credentials and relays them through an internal proxy or jump host, resulting in usage from a different internal IP than the instance itself.
- An approved multi-account architecture intentionally passes assumed-role credentials between resources for orchestration purposes.

### True Positives

- The instance's temporary IAM role credentials, obtained via the metadata service, were used from a location other than the instance itself - the credentials were used from another resource inside AWS (e.g., a different EC2 instance or account), which can still indicate lateral movement even though it stayed within AWS's network.
- The credential usage includes calls unrelated to the instance's normal workload (e.g., enumerating IAM, creating new users, accessing unrelated S3 buckets).
- The exfiltration follows a known vulnerability exploitation or SSRF event on the same instance.

### True Negatives

- The usage pattern is fully explained by an approved automation workflow that legitimately forwards the instance's credentials through a documented internal hop.

### False Negatives

- The attacker uses the stolen credentials from an egress IP that overlaps with a legitimate, high-reputation cloud provider, blending in with expected traffic.
- Stolen credentials are used sparingly and only for actions that match the instance's normal behavior, avoiding a clear deviation.

## References

- [IAM finding types](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-iam.html)
- [Remediating potentially compromised AWS credentials](https://docs.aws.amazon.com/guardduty/latest/ug/compromised-creds.html)
- [NIST SP 800-61r3: Incident Response Recommendations](https://csrc.nist.gov/pubs/sp/800/61/r3/final)
- [AWS Security Incident Response Guide (2023)](https://docs.aws.amazon.com/whitepapers/latest/aws-security-incident-response-guide/welcome.html)
