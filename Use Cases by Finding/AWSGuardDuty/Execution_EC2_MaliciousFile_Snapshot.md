# Malicious File - EBS Snapshot - EC2

## Description
Alert generated when AWS GuardDuty identifies the finding type `Execution:EC2/MaliciousFile!Snapshot`. A malicious or suspicious file associated with the EC2 resource has been identified. The alert must be reviewed by the SOC to validate its legitimacy, scope, affected resource, and potential impact.

## Objective
Detect and prioritize potential malicious, anomalous, or unauthorized activities related to EC2 instances, enabling the SOC to initiate a structured investigation, reduce operational risk, and activate containment procedures when indicators of compromise are identified.

## Logic
The detection is triggered when an AWS GuardDuty event is received with `finding.type` equal to:

`Execution:EC2/MaliciousFile!Snapshot`

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
- **Family or Mechanism:** MaliciousFile!Snapshot.
- A malicious or suspicious file associated with the EC2 resource has been identified. The analyst should consider credential compromise, malware infection, cloud service abuse, public exposure, evasion, reconnaissance, impact, or exfiltration depending on the technical context of the finding.
- **Data Sources:** AWS GuardDuty findings, VPC Flow Logs, DNS logs, AWS CloudTrail, EC2/SSM/EDR if available.

## Investigation Sources
- **AWS GuardDuty Finding Details:** finding ID, type, severity, title, description, firstSeen, lastSeen, count, accountId, region.
- **AWS CloudTrail:** API calls, userIdentity, sourceIPAddress, userAgent, errorCode, requestParameters, responseElements.
- **Network Logs:** VPC Flow Logs, DNS logs, ports, protocols, transferred bytes, remote IP, country, and ASN.
- **Resource Configuration:** tags, owner, policies, public exposure, security groups, ACLs, roles, or effective permissions.
- Operational validation with the resource owner, platform team, cloud team, DevOps team, or application owner.

## Sigma Rule

```yaml
title: 'AWS: Malicious File - EBS Snapshot - EC2'
id: 14bce31c-9ecb-5ec1-a721-9d78cb250aa8
status: experimental
description: |
    This GuardDuty Malware Protection finding indicates that an EBS snapshot was scanned and found to contain
    malicious content. This confirms the underlying resource was infected at the point the backup was taken, and
    any restoration or new resource built from this artifact will reintroduce the infection unless remediated
    first.
references:
    - 'https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-ec2.html'
    - 'https://docs.aws.amazon.com/guardduty/latest/ug/compromised-ec2.html'
    - 'https://docs.aws.amazon.com/guardduty/latest/ug/findings-malware-protection-backup.html'
    - 'https://docs.aws.amazon.com/guardduty/latest/ug/compromised-snapshot.html'
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
            - 'Execution:EC2/MaliciousFile!Snapshot'
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

- GuardDuty's on-demand malware scan of an EBS snapshot identified malicious content, meaning the source resource was already infected at the time the backup/image was captured - the malware has effectively been 'frozen' into every backup taken since the infection.
- The same malware signature is found across multiple successive backups/snapshots, confirming the infection predates the backup retention window and has not yet been remediated at the source.
- The backup/image is a candidate for restoration or for building new instances, which would propagate the infection to any newly launched resource.

### False Negatives

- The malware was introduced after the specific backup/snapshot being scanned was taken, so older backups remain clean while the live resource is already compromised.
- The malicious file is encrypted or packed in a way the scan engine cannot currently unpack and inspect.

## References

- [EC2 finding types](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-ec2.html)
- [Remediating a potentially compromised Amazon EC2 instance](https://docs.aws.amazon.com/guardduty/latest/ug/compromised-ec2.html)
- [Malware Protection for Backup finding types](https://docs.aws.amazon.com/guardduty/latest/ug/findings-malware-protection-backup.html)
- [Remediating a potentially compromised EBS Snapshot](https://docs.aws.amazon.com/guardduty/latest/ug/compromised-snapshot.html)
- [NIST SP 800-61r3: Incident Response Recommendations](https://csrc.nist.gov/pubs/sp/800/61/r3/final)
- [AWS Security Incident Response Guide (2023)](https://docs.aws.amazon.com/whitepapers/latest/aws-security-incident-response-guide/welcome.html)
