# Anomalous Model Invocation - AI Protection

## Description

Alert generated when AWS GuardDuty identifies the finding type `Impact:IAMUser/AnomalousModelInvocation`. An IAM identity invoked an Amazon Bedrock or Amazon SageMaker AI model in a way that deviates from the established baseline for the identity or account. The alert must be reviewed by the SOC to validate its legitimacy, scope, affected AI resource, and potential impact.

## Objective

Detect and prioritize potential unauthorized, anomalous, or suspicious interactions with generative AI workloads, enabling the SOC to initiate a structured investigation, reduce operational risk, and activate containment procedures when compromised credentials or model abuse are identified.

## Logic

The detection is triggered when an AWS GuardDuty event is received with `finding.type` equal to:

`Impact:IAMUser/AnomalousModelInvocation`

The prioritization logic should consider severity, asset criticality, event recurrence, model invocation API, source IP/ASN, user agent, involved IAM identity, AWS region, and AWS account.

Patterns or conditions to validate:

* Exact match of `finding.type` with the use case.
* GuardDuty severity equal to or above the SOC-defined threshold.
* Access to sensitive, proprietary, or production-grade foundation models.
* Invocation API called (`bedrock:InvokeModel`, `bedrock:Converse`, `sagemaker:InvokeEndpoint`, etc.) not recognized as standard behavior for the principal.
* Source IP address, ASN organization, or user agent deviating significantly from historical baselines.
* Subsequent suspicious activities following the event, such as privilege escalation, resource creation, or mass data access.

## Severity Matrix

| Priority | Label | Response Time | Description |
| --- | --- | --- | --- |
| **P3** | Medium | < 4 hours | Anomalous AI model invocation detected from an unrecognized network location or user agent using potentially compromised credentials |

## MITRE ATT&CK / ATLAS

* AML.T0040 - ML Model Inference API Abuse

## Threat

* **Primary Threat:** AI Model Abuse / Credential Compromise.
* **Family or Mechanism:** AnomalousModelInvocation.
* An IAM identity is interacting with AI models using parameters that deviate from historical baselines. The analyst should consider credential theft, unauthorized data querying, data exfiltration via model prompts, or policy evasion.
* **Data Sources:** AWS GuardDuty findings, AWS CloudTrail, Amazon Bedrock / SageMaker audit logs.

## Investigation Sources

* **AWS GuardDuty Finding Details:** finding ID, type, severity, accountId, region, modelDetails list.
* **AWS CloudTrail:** API calls (`InvokeModel`, `Converse`, etc.), `userIdentity`, `sourceIPAddress`, `userAgent`, request parameters.
* **AI Service Configuration:** permissions, trust policies, model access controls, and guardrail attachments.
* Operational validation with the AI engineering team, data science team, or application owner.

## Sigma Rule

```yaml
title: 'AWS: Anomalous Model Invocation - AI Protection'
id: 5a7b8c9d-1e2f-3a4b-5c6d-7e8f9a0b1c2d
status: experimental
description: |
    This GuardDuty finding indicates that an IAM identity invoked an Amazon Bedrock or Amazon SageMaker AI model
    in a way that deviates from the established baseline for the identity or account, suggesting potential credential compromise or abuse.
references:
    - 'https://docs.aws.amazon.com/guardduty/latest/ug/findings-ai-protection.html'
date: '2026-10-13'
modified: '2026-10-13'
author: 'https://github.com/aguztynbassi'
tags:
    - attack.t0040
logsource:
    category: cloud
    product: aws
    service: guardduty
detection:
    selection:
        detail.type:
            - 'Impact:IAMUser/AnomalousModelInvocation'
    condition: selection
falsepositives:
    - 'An authorized developer or data scientist testing a new model or running automated scripts from a new corporate network location.'
    - 'A newly onboarded application service account starting legitimate query patterns that have not yet been fully baselined.'
level: medium

```

## Investigation

Mandatory 5W Questions:

* **Who:** Which IAM user, role, or service account invoked the model?
* **What:** Which specific model and invocation API (`InvokeModel`, `Converse`, `InvokeEndpoint`) were used?
* **When:** When did the anomaly occur relative to normal working hours?
* **Where:** From which source IP address, country, ASN, and AWS region did the request originate?
* **Why:** Is there an operational justification, recent deployment, or authorized testing activity explaining the deviation?

## Detailed Checklist for Analysts Reviewing the Alert

* `Finding ID`, `finding type`, `severity`, `account`, `region`, and model details (`modelDetails`).
* Involved identity (`userName`, `role`, session context).
* Source IP address, ASN organization, and user agent.
* Frequency and volume of invocations compared to the baseline.
* Verification with the asset/application owner.

## Evidence for Determination

### False Positives

* Authorized data science team performing legitimate model evaluation or benchmarking from a new or remote location.
* Automated CI/CD pipelines executing integration tests against foundation models.

### True Positives

* Compromised developer or service account credentials being leveraged to query proprietary foundation models for data extraction or intellectual property harvesting.
* Unauthorized scripts systematically abusing model endpoints.

### True Negatives

* Temporary baseline fluctuation due to a scheduled business expansion or legitimate batch job.

### False Negatives

* Slow and low invocation patterns designed to stay underneath the automated baseline deviation threshold.

## References

* [GuardDuty AI Protection finding types](https://docs.aws.amazon.com/guardduty/latest/ug/findings-ai-protection.html)

