# Malicious File - Backup Recovery Point - S3

## Description
Alert generated when AWS GuardDuty identifies the finding type `Execution:S3/MaliciousFile!RecoveryPoint`. A malicious or suspicious file associated with the S3 bucket has been identified. The alert must be reviewed by the SOC to validate its legitimacy, scope, affected resource, and potential impact.

## Objective
Detect and prioritize potential malicious, anomalous, or unauthorized activities related to S3 buckets, enabling the SOC to initiate a structured investigation, reduce operational risk, and activate containment procedures when indicators of compromise are identified.

## Logic
The detection is triggered when an AWS GuardDuty event is received with `finding.type` equal to:

`Execution:S3/MaliciousFile!RecoveryPoint`

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

- T1059 - Command and Scripting Interpreter

## Threat
- **Primary Threat:** Execution.
- **Family or Mechanism:** MaliciousFile!RecoveryPoint.
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
title: 'AWS: Malicious File - Backup Recovery Point - S3'
id: d16eeb67-7302-5969-98e4-a645141916c1
status: experimental
description: |
    This GuardDuty Malware Protection finding indicates that an AWS Backup recovery point for an S3 bucket was
    scanned and found to contain malicious content. This confirms the underlying resource was infected at the
    point the backup was taken, and any restoration or new resource built from this artifact will reintroduce the
    infection unless remediated first.
references:
    - 'https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-s3.html'
    - 'https://docs.aws.amazon.com/guardduty/latest/ug/compromised-s3.html'
    - 'https://docs.aws.amazon.com/guardduty/latest/ug/findings-malware-protection-backup.html'
    - 'https://docs.aws.amazon.com/guardduty/latest/ug/compromised-s3-recoverypoint.html'
    - 'https://csrc.nist.gov/pubs/sp/800/61/r3/final'
    - 'https://docs.aws.amazon.com/whitepapers/latest/aws-security-incident-response-guide/welcome.html'
date: '2026-10-13'
modified: '2026-10-13'
author: 'https://github.com/aguztynbassi'
tags:
    - attack.t1059
logsource:
    category: cloud
    product: aws
    service: guardduty
detection:
    selection:
        detail.type:
            - 'Execution:S3/MaliciousFile!RecoveryPoint'
    condition: selection
falsepositives:
    - 'An extremely rare hash/signature collision incorrectly flags a legitimate, benign file within the backup artifact as malicious.'
    - 'A security-testing file (e.g., the EICAR test string) was intentionally included as part of validating malware scanning for...'
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

- An extremely rare hash/signature collision incorrectly flags a legitimate, benign file within the backup artifact as malicious.
- A security-testing file (e.g., the EICAR test string) was intentionally included as part of validating malware scanning for backups.

### True Positives

- GuardDuty's on-demand malware scan of an AWS Backup recovery point for an S3 bucket identified malicious content, meaning the source resource was already infected at the time the backup/image was captured - the malware has effectively been 'frozen' into every backup taken since the infection.
- The same malware signature is found across multiple successive backups/snapshots, confirming the infection predates the backup retention window and has not yet been remediated at the source.
- The backup/image is a candidate for restoration or for building new instances, which would propagate the infection to any newly launched resource.

### False Negatives

- The malware was introduced after the specific backup/snapshot being scanned was taken, so older backups remain clean while the live resource is already compromised.
- The malicious file is encrypted or packed in a way the scan engine cannot currently unpack and inspect.

## References

- [S3 Protection finding types](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-s3.html)
- [Remediating a potentially compromised S3 bucket](https://docs.aws.amazon.com/guardduty/latest/ug/compromised-s3.html)
- [Malware Protection for Backup finding types](https://docs.aws.amazon.com/guardduty/latest/ug/findings-malware-protection-backup.html)
- [Remediating a potentially compromised S3 Recovery Point](https://docs.aws.amazon.com/guardduty/latest/ug/compromised-s3-recoverypoint.html)
- [NIST SP 800-61r3: Incident Response Recommendations](https://csrc.nist.gov/pubs/sp/800/61/r3/final)
- [AWS Security Incident Response Guide (2023)](https://docs.aws.amazon.com/whitepapers/latest/aws-security-incident-response-guide/welcome.html)
