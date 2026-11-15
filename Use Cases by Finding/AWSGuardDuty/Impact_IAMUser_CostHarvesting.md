# Cost Harvesting - AI Protection

## Description

Alert generated when AWS GuardDuty identifies the finding type `Impact:IAMUser/CostHarvesting`. An IAM identity invoked an Amazon Bedrock or Amazon SageMaker AI model with anomalous token volumes that might indicate a cost harvesting attack. The alert must be reviewed by the SOC to validate its legitimacy, scope, and potential financial impact.

## Objective

Detect and prioritize potential malicious or abusive activities designed to exhaust financial resources or drive up infrastructure costs through excessive token consumption in AI workloads, enabling the SOC to take rapid containment action.

## Logic

The detection is triggered when an AWS GuardDuty event is received with `finding.type` equal to:

`Impact:IAMUser/CostHarvesting`

The prioritization logic should consider severity, volume of tokens consumed, model pricing tier, asset criticality, involved identity, AWS region, and AWS account.

Patterns or conditions to validate:

* Exact match of `finding.type` with the use case.
* GuardDuty severity equal to or above the SOC-defined threshold.
* Unusually high input/output token counts exceeding historical usage bounds.
* Continuous, automated, high-frequency calls targeting expensive foundation models.
* Correlation with compromised credentials or leaked API keys.

## Severity Matrix

| Priority | Label | Response Time | Description |
| --- | --- | --- | --- |
| **P2** | High | < 1 hour | Confirmed abnormal token volume consumption risking massive financial impact or indicating malicious resource exhaustion |

## MITRE ATT&CK / ATLAS

* AML.T0034 - Cost Harvesting

## Threat

* **Primary Threat:** Resource Exhaustion / Financial Denial of Wallet.
* **Family or Mechanism:** CostHarvesting.
* An attacker is abusing valid credentials to generate massive computational and financial overhead by overloading LLM APIs with giant prompts or infinite loops.
* **Data Sources:** AWS GuardDuty findings, AWS CloudTrail, Amazon Bedrock / SageMaker metrics.

## Investigation Sources

* **AWS GuardDuty Finding Details:** finding ID, type, severity, token metrics, observed invocation volumes, modelDetails.
* **AWS CloudTrail:** API logs indicating who executed the high-volume requests.
* **Cost Explorer / Billing:** Real-time cost anomalies associated with Bedrock or SageMaker services.

## Sigma Rule

```yaml
title: 'AWS: Cost Harvesting - AI Protection'
id: 6b8c9d0e-2f3a-4b5c-6d7e-8f9a0b1c2d3e
status: experimental
description: |
    This GuardDuty finding indicates that an IAM identity invoked an Amazon Bedrock or Amazon SageMaker AI model
    with anomalous token volumes that might indicate a cost harvesting attack or resource exhaustion.
references:
    - 'https://docs.aws.amazon.com/guardduty/latest/ug/findings-ai-protection.html'
date: '2026-10-13'
modified: '2026-10-13'
author: 'https://github.com/aguztynbassi'
tags:
    - attack.t0034
logsource:
    category: cloud
    product: aws
    service: guardduty
detection:
    selection:
        detail.type:
            - 'Impact:IAMUser/CostHarvesting'
    condition: selection
falsepositives:
    - 'A legitimate, large-scale batch processing job or enterprise document summarization task run without prior notification to security.'
level: high

```

## Investigation

Mandatory 5W Questions:

* **Who:** Which IAM principal is driving the excessive token usage?
* **What:** What model was targeted and what was the magnitude of the token consumption?
* **When:** When did the spike begin and how long did it last?
* **Where:** From which source IP address and AWS region did the requests originate?
* **Why:** Is there an authorized bulk processing task or system migration accounting for the load?

## Detailed Checklist for Analysts Reviewing the Alert

* `Finding ID`, `severity`, `account`, and `region`.
* Observed invocation and token volume details (`service.detection`).
* Target models listed in `modelDetails`.
* Check AWS Cost Explorer for immediate financial impact.
* Contact resource owner to confirm or deny operational intent.

## Evidence for Determination

### False Positives

* Large authorized ETL pipelines or enterprise knowledge-base indexing jobs processing large corpuses of text.

### True Positives

* Stolen credentials used maliciously to flood AI endpoints with oversized inputs to run up cloud bills.
* Misconfigured automated applications looping infinitely against model endpoints.

### True Negatives

* Planned load tests or stress tests executed in a staging environment.

### False Negatives

* Incremental token inflation distributed slowly across multiple identities to stay below detection thresholds.

## References

* [GuardDuty AI Protection finding types](https://docs.aws.amazon.com/guardduty/latest/ug/findings-ai-protection.html)