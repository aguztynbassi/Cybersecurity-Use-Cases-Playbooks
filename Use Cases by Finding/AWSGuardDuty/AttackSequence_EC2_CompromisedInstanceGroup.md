# Attack Sequence - Compromised EC2 Instance Group

## Description
Alert generated when AWS GuardDuty identifies the finding type `AttackSequence:EC2/CompromisedInstanceGroup`. GuardDuty has correlated multiple signals consistent with a compromise affecting the EC2 resource. The alert must be reviewed by the SOC to validate its legitimacy, scope, affected resource, and potential impact.

## Objective
Detect and prioritize potential malicious, anomalous, or unauthorized activities related to EC2 instances, enabling the SOC to initiate a structured investigation, reduce operational risk, and activate containment procedures when indicators of compromise are identified.

## Logic
The detection is triggered when an AWS GuardDuty event is received with `finding.type` equal to:

`AttackSequence:EC2/CompromisedInstanceGroup`

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
| **P1** | Critical | Immediate (< 15 min) | Active data exfiltration, production outage, confirmed breach with customer impact, or regulatory notification required |

## MITRE ATT&CK

- Multiple ATT&CK tactics and techniques apply - correlate with the individual GuardDuty findings that make up this attack sequence to identify the specific techniques observed

## Threat
- **Primary Threat:** Attack Sequence.
- **Family or Mechanism:** CompromisedInstanceGroup.
- GuardDuty has correlated multiple signals consistent with a compromise affecting the EC2 resource. The analyst should consider credential compromise, malware infection, cloud service abuse, public exposure, evasion, reconnaissance, impact, or exfiltration depending on the technical context of the finding.
- **Data Sources:** AWS GuardDuty findings, VPC Flow Logs, DNS logs, AWS CloudTrail, EC2/SSM/EDR if available.

## Investigation Sources
- **AWS GuardDuty Finding Details:** finding ID, type, severity, title, description, firstSeen, lastSeen, count, accountId, region.
- **AWS CloudTrail:** API calls, userIdentity, sourceIPAddress, userAgent, errorCode, requestParameters, responseElements.
- **Network Logs:** VPC Flow Logs, DNS logs, ports, protocols, transferred bytes, remote IP, country, and ASN.
- **Resource Configuration:** tags, owner, policies, public exposure, security groups, ACLs, roles, or effective permissions.
- Operational validation with the resource owner, platform team, cloud team, DevOps team, or application owner.

## Sigma Rule

```yaml
title: 'AWS: Attack Sequence - Compromised EC2 Instance Group'
id: 7a04a0d8-c1ef-52be-8b7b-cd0322d2cc9e
status: experimental
description: |
    This GuardDuty Attack Sequence finding indicates that GuardDuty's Extended Threat Detection has correlated
    multiple individual findings into a probable multi-stage attack affecting a group of related EC2 instances.
    Because this represents an aggregation of several already-suspicious signals, it should be treated as critical
    and investigated immediately, starting from the individual findings that make up the sequence.
references:
    - 'https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-ec2.html'
    - 'https://docs.aws.amazon.com/guardduty/latest/ug/compromised-ec2.html'
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
            - 'AttackSequence:EC2/CompromisedInstanceGroup'
    condition: selection
falsepositives:
    - 'An approved penetration test or red-team exercise performed a realistic, multi-stage attack simulation that happened to trigger...'
    - 'A legitimate but unusual sequence of administrative actions (migration, large-scale remediation, disaster-recovery drill) was...'
level: critical
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

- An approved penetration test or red-team exercise performed a realistic, multi-stage attack simulation that happened to trigger enough correlated signals to be grouped as a sequence.
- A legitimate but unusual sequence of administrative actions (migration, large-scale remediation, disaster-recovery drill) was performed in a way that superficially resembles an attack chain.

### True Positives

- GuardDuty has correlated multiple individual findings into a single attack sequence affecting a group of related EC2 instances, indicating a probable multi-stage compromise (e.g., initial access, followed by discovery, privilege escalation, and impact/exfiltration).
- The individual findings that make up the sequence each have their own supporting evidence (unfamiliar source IPs, anomalous behavior, credential misuse) that corroborates the correlation.
- The sequence spans multiple tactics (e.g., Initial Access through Impact), consistent with an attacker progressing through the cyber kill chain rather than a single isolated event.
- No business or operational explanation accounts for the full chain of events when checked with the resource owner(s).

### True Negatives

- Every finding in the sequence is independently confirmed to be expected, approved activity (e.g., a scheduled DR test covering the same resources).

### False Negatives

- The attacker deliberately paces each stage of the intrusion far enough apart in time, or across different accounts/resources, that GuardDuty's correlation engine does not group them into a single sequence.
- One or more stages of the real attack use techniques outside GuardDuty's current detection coverage, so the correlated sequence underrepresents the true scope of the compromise.

## References

- [EC2 finding types](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-ec2.html)
- [Remediating a potentially compromised Amazon EC2 instance](https://docs.aws.amazon.com/guardduty/latest/ug/compromised-ec2.html)
- [NIST SP 800-61r3: Incident Response Recommendations](https://csrc.nist.gov/pubs/sp/800/61/r3/final)
- [AWS Security Incident Response Guide (2023)](https://docs.aws.amazon.com/whitepapers/latest/aws-security-incident-response-guide/welcome.html)
