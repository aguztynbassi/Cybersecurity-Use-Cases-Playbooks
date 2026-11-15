# Malicious File Uploaded to S3

## Description
Alert generated when AWS GuardDuty identifies the finding type `Object:S3/MaliciousFile`. A malicious or suspicious file associated with the S3 bucket has been identified. The alert must be reviewed by the SOC to validate its legitimacy, scope, affected resource, and potential impact.

## Objective
Detect and prioritize potential malicious, anomalous, or unauthorized activities related to S3 buckets, enabling the SOC to initiate a structured investigation, reduce operational risk, and activate containment procedures when indicators of compromise are identified.

## Logic
The detection is triggered when an AWS GuardDuty event is received with `finding.type` equal to:

`Object:S3/MaliciousFile`

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

- Technique to be confirmed based on the specific object and action observed (Execution / Impact tactics)

## Threat
- **Primary Threat:** Object.
- **Family or Mechanism:** MaliciousFile.
- A malicious or suspicious file associated with the S3 bucket has been identified. The analyst should consider credential compromise, malware infection, cloud service abuse, public exposure, evasion, reconnaissance, impact, or exfiltration depending on the technical context of the finding.
- **Data Sources:** AWS GuardDuty findings, CloudTrail S3 Data Events, S3 Server Access Logs, bucket policy/ACL configuration.

## Investigation Sources
- **AWS GuardDuty Finding Details:** finding ID, type, severity, title, description, firstSeen, lastSeen, count, accountId, region.
- **AWS CloudTrail:** API calls, userIdentity, sourceIPAddress, userAgent, errorCode, requestParameters, responseElements.
- **Network Logs:** VPC Flow Logs, DNS logs, ports, protocols, transferred bytes, remote IP, country, and ASN.
- **Resource Configuration:** tags, owner, policies, public exposure, security groups, ACLs, roles, or effective permissions.
- Operational validation with the resource owner, platform team, cloud team, DevOps team, or application owner.

## Sigma Rule

```yaml
title: 'AWS: Malicious File Uploaded to S3'
id: 6acd101d-91a4-5bfe-9687-af40b222e74f
status: experimental
description: |
    This GuardDuty Malware Protection for S3 finding indicates that an object uploaded to the bucket was
    identified as malicious. If the bucket serves content to users or other systems, this represents a risk of
    further malware distribution and should be quarantined immediately.
references:
    - 'https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-s3.html'
    - 'https://docs.aws.amazon.com/guardduty/latest/ug/compromised-s3.html'
    - 'https://docs.aws.amazon.com/guardduty/latest/ug/gdu-malware-protection-s3-finding-types.html'
    - 'https://docs.aws.amazon.com/guardduty/latest/ug/compromised-s3object-malware-protection-gdu.html'
    - 'https://csrc.nist.gov/pubs/sp/800/61/r3/final'
    - 'https://docs.aws.amazon.com/whitepapers/latest/aws-security-incident-response-guide/welcome.html'
date: '2026-10-13'
modified: '2026-10-13'
author: 'https://github.com/aguztynbassi'
logsource:
    category: cloud
    product: aws
    service: guardduty
detection:
    selection:
        detail.type:
            - 'Object:S3/MaliciousFile'
    condition: selection
falsepositives:
    - 'An extremely rare hash/signature collision incorrectly flags a legitimate, benign object as malicious.'
    - 'A security-testing file (e.g., the EICAR test string) was intentionally uploaded to validate that Malware Protection for S3 is...'
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

- An extremely rare hash/signature collision incorrectly flags a legitimate, benign object as malicious.
- A security-testing file (e.g., the EICAR test string) was intentionally uploaded to validate that Malware Protection for S3 is working.

### True Positives

- An object uploaded to the bucket was identified as malware by GuardDuty's scanning engine, meaning the bucket is currently hosting a malicious file - potentially one that will be downloaded and executed by other systems or users, or distributed further if the bucket is public-facing.
- The uploading identity/IP has no legitimate relationship to the application that normally populates this bucket.
- The object is part of a user-generated-content pipeline (uploads, attachments) where an external party could intentionally plant malicious content.

### False Negatives

- The malicious object is removed or overwritten before the scheduled/triggered scan completes.
- The payload is embedded inside a container format (e.g., a macro in an otherwise-benign-looking document, or a zip within a zip) in a way that evades the current scan engine's unpacking depth.

## References

- [S3 Protection finding types](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-s3.html)
- [Remediating a potentially compromised S3 bucket](https://docs.aws.amazon.com/guardduty/latest/ug/compromised-s3.html)
- [Malware Protection for S3 finding type](https://docs.aws.amazon.com/guardduty/latest/ug/gdu-malware-protection-s3-finding-types.html)
- [Remediating a potentially malicious S3 object](https://docs.aws.amazon.com/guardduty/latest/ug/compromised-s3object-malware-protection-gdu.html)
- [NIST SP 800-61r3: Incident Response Recommendations](https://csrc.nist.gov/pubs/sp/800/61/r3/final)
- [AWS Security Incident Response Guide (2023)](https://docs.aws.amazon.com/whitepapers/latest/aws-security-incident-response-guide/welcome.html)
