# C&C Activity (Variant B) - Lambda

## Description
Alert generated when AWS GuardDuty identifies the finding type `Backdoor:Lambda/C&CActivity.B`. The Lambda function could be communicating with infrastructure associated with command and control. The alert must be reviewed by the SOC to validate its legitimacy, scope, affected resource, and potential impact.

## Objective
Detect and prioritize potential malicious, anomalous, or unauthorized activities related to Lambda functions, enabling the SOC to initiate a structured investigation, reduce operational risk, and activate containment procedures when indicators of compromise are identified.

## Logic
The detection is triggered when an AWS GuardDuty event is received with `finding.type` equal to:

`Backdoor:Lambda/C&CActivity.B`

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

- T1071 - Application Layer Protocol

## Threat
- **Primary Threat:** Backdoor.
- **Family or Mechanism:** C&CActivity.B.
- The Lambda function could be communicating with infrastructure associated with command and control. The analyst should consider credential compromise, malware infection, cloud service abuse, public exposure, evasion, reconnaissance, impact, or exfiltration depending on the technical context of the finding.
- **Data Sources:** AWS GuardDuty findings, CloudTrail, CloudWatch Logs, VPC Flow Logs if applicable.

## Investigation Sources
- **AWS GuardDuty Finding Details:** finding ID, type, severity, title, description, firstSeen, lastSeen, count, accountId, region.
- **AWS CloudTrail:** API calls, userIdentity, sourceIPAddress, userAgent, errorCode, requestParameters, responseElements.
- **Network Logs:** VPC Flow Logs, DNS logs, ports, protocols, transferred bytes, remote IP, country, and ASN.
- **Resource Configuration:** tags, owner, policies, public exposure, security groups, ACLs, roles, or effective permissions.
- Operational validation with the resource owner, platform team, cloud team, DevOps team, or application owner.

## Sigma Rule

```yaml
title: 'AWS: C&C Activity (Variant B) - Lambda'
id: 17aa2a42-b943-57d2-a397-7bc985b110db
status: experimental
description: |
    This GuardDuty finding indicates that an AWS resource is communicating with an IP address or domain known to
    be associated with command-and-control (C2) infrastructure. The connection may reflect an active backdoor or
    implant checking in to its operator, and should be investigated as a likely indicator of compromise.
references:
    - 'https://docs.aws.amazon.com/guardduty/latest/ug/lambda-protection-finding-types.html'
    - 'https://docs.aws.amazon.com/guardduty/latest/ug/remediate-lambda-protection-finding-types.html'
    - 'https://csrc.nist.gov/pubs/sp/800/61/r3/final'
    - 'https://docs.aws.amazon.com/whitepapers/latest/aws-security-incident-response-guide/welcome.html'
date: '2026-10-13'
modified: '2026-10-13'
author: 'https://github.com/aguztynbassi'
tags:
    - attack.t1071
logsource:
    category: cloud
    product: aws
    service: guardduty
detection:
    selection:
        detail.type:
            - 'Backdoor:Lambda/C&CActivity.B'
    condition: selection
falsepositives:
    - 'A security tool, EDR agent, or threat-intel sandbox running on the Lambda function intentionally connected to a known...'
    - 'The destination IP was recently reassigned by a hosting provider and no longer hosts C2 infrastructure, but the GuardDuty threat...'
    - 'A misconfigured proxy or DNS forwarder on the Lambda function is relaying unrelated traffic through an address that overlaps with...'
    - 'Authorized red-team or purple-team C2 emulation (e.g. Cobalt Strike, Sliver) was run against this asset during an approved...'
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

- A security tool, EDR agent, or threat-intel sandbox running on the Lambda function intentionally connected to a known bad-reputation IP/domain as part of detonation or signature testing.
- The destination IP was recently reassigned by a hosting provider and no longer hosts C2 infrastructure, but the GuardDuty threat intel list has not yet been refreshed.
- A misconfigured proxy or DNS forwarder on the Lambda function is relaying unrelated traffic through an address that overlaps with a previously flagged C2 node.
- Authorized red-team or purple-team C2 emulation (e.g. Cobalt Strike, Sliver) was run against this asset during an approved engagement window.

### True Positives

- The Lambda function is beaconing at a regular interval to an IP/domain on active threat-intelligence lists associated with known C2 infrastructure.
- The beacon coincides with an unexplained process, scheduled task, or newly created binary on the host, consistent with an implant checking in to its operator.
- Outbound connections continue after the owner confirms no legitimate service should be communicating with that destination.
- CloudTrail shows credential or token usage from the Lambda function shortly after the beacon started, suggesting the implant is pivoting to abuse AWS APIs.
- Multiple internal hosts begin beaconing to the same external destination in a short window, indicating lateral spread of the same implant.

### True Negatives

- The Lambda function only communicates with the flagged destination over a well-documented, owner-confirmed integration (e.g., a SaaS vendor sharing IP space with a previously abused host).
- The connection was a single, one-off DNS lookup with no follow-up traffic and no process-level indicators of compromise.
- Vulnerability scanning or threat-intelligence research tooling operated by the security team generated the flagged traffic by design.

### False Negatives

- The implant uses domain fronting or a legitimate CDN/cloud provider as a front-end, so the apparent destination is a trusted service and GuardDuty does not flag it.
- C2 traffic is encrypted and routed through a channel GuardDuty does not inspect (e.g., a protocol or port not covered by its network intelligence).
- The beacon interval is deliberately randomized and infrequent (low-and-slow) to stay below GuardDuty's detection threshold.

## References

- [Lambda Protection finding types](https://docs.aws.amazon.com/guardduty/latest/ug/lambda-protection-finding-types.html)
- [Remediating a potentially compromised Lambda function](https://docs.aws.amazon.com/guardduty/latest/ug/remediate-lambda-protection-finding-types.html)
- [NIST SP 800-61r3: Incident Response Recommendations](https://csrc.nist.gov/pubs/sp/800/61/r3/final)
- [AWS Security Incident Response Guide (2023)](https://docs.aws.amazon.com/whitepapers/latest/aws-security-incident-response-guide/welcome.html)
