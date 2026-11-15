# Prompt Injection Direct - AI Protection

## Description

Alert generated when AWS GuardDuty identifies the finding type `Impact:IAMUser/PromptInjection.Direct`. Amazon Bedrock Guardrails evaluated a prompt and detected a prompt attack, resulting in a guardrail intervention (`GUARDRAIL_INTERVENED`). The alert must be reviewed by the SOC to validate the attack nature, intent, and source.

## Objective

Detect and prioritize attempts to compromise Large Language Model guardrails through direct prompt injection attacks, enabling the SOC to identify malicious user intent, assess input payloads, and protect generative AI applications from jailbreaking or malicious instruction override.

## Logic

The detection is triggered when an AWS GuardDuty event is received with `finding.type` equal to:

`Impact:IAMUser/PromptInjection.Direct`

The prioritization logic should consider severity, guardrail action, content policy filter confidence, involved identity, AWS region, and AWS account.

Patterns or conditions to validate:

* Exact match of `finding.type` with the use case.
* GuardDuty severity equal to or above the SOC-defined threshold.
* `bedrockGuardrailDetails` present with `guardrailAction` equal to `GUARDRAIL_INTERVENED`.
* Content policy filters indicating `PROMPT_ATTACK` with high confidence.
* Repeated injection attempts from the same IAM identity or external user context.

## Severity Matrix

| Priority | Label | Response Time | Description |
| --- | --- | --- | --- |
| **P2** | High | < 1 hour | Direct prompt injection attack detected and blocked by Guardrails, indicating malicious user attempt to bypass AI safety controls |

## MITRE ATT&CK / ATLAS

* AML.T0051 - LLM Prompt Injection

## Threat

* **Primary Threat:** Adversarial AI Attack / Jailbreak.
* **Family or Mechanism:** PromptInjection.Direct.
* An actor is attempting to force a model to ignore safety guidelines or system instructions by injecting malicious phrasing into the input prompt.
* **Data Sources:** AWS GuardDuty findings, Amazon Bedrock Guardrails logs, AWS CloudTrail.

## Investigation Sources

* **AWS GuardDuty Finding Details:** finding ID, type, severity, `bedrockGuardrailDetails` (arn, version, guardrailAction, guardrailSource, contentPolicyFilters).
* **AWS CloudTrail & Bedrock Logs:** Associated API requests, user identity, and prompt context.

## Sigma Rule

```yaml
title: 'AWS: Prompt Injection Direct - AI Protection'
id: 7c9d0e1f-3a4b-5c6d-7e8f-9a0b1c2d3e4f
status: experimental
description: |
    This GuardDuty finding indicates that Amazon Bedrock Guardrails evaluated a prompt and detected a direct prompt attack,
    triggering a guardrail intervention.
references:
    - 'https://docs.aws.amazon.com/guardduty/latest/ug/findings-ai-protection.html'
date: '2026-10-13'
modified: '2026-10-13'
author: 'https://github.com/aguztynbassi'
tags:
    - attack.aml.t0051
logsource:
    category: cloud
    product: aws
    service: guardduty
detection:
    selection:
        detail.type:
            - 'Impact:IAMUser/PromptInjection.Direct'
    condition: selection
falsepositives:
    - 'A user or researcher intentionally testing application robustness or guardrail boundaries with red-teaming prompts.'
    - 'False positive trigger by content policy filters on benign text with ambiguous phrasing.'
level: high

```

## Investigation

Mandatory 5W Questions:

* **Who:** Which IAM identity or user submitted the malicious prompt?
* **What:** What specific content policy filter was tripped and what was the confidence level?
* **When:** When did the prompt submission occur?
* **Where:** From which source IP address or application interface did the request originate?
* **Why:** Was this part of authorized red-teaming/safety testing, or a malicious user jailbreak attempt?

## Detailed Checklist for Analysts Reviewing the Alert

* `Finding ID`, `severity`, `account`, and `region`.
* `bedrockGuardrailDetails`: review the guardrail ARN, version, and action (`GUARDRAIL_INTERVENED`).
* Content policy filters list (`contentPolicyFilters`) to inspect prompt attack confidence (`HIGH`).
* Investigate user session behavior for subsequent malicious requests.

## Evidence for Determination

### False Positives

* Security testing, red teaming, or developers checking the effectiveness of Amazon Bedrock Guardrails.
* Complex benign input text mistakenly classified as a prompt attack due to overlapping keywords.

### True Positives

* Malicious external users attempting to bypass application guardrails to extract sensitive data, trigger unsafe code execution, or force toxic outputs.

### True Negatives

* Blocked test vectors run as part of pre-deployment validation pipelines by the engineering team.

### False Negatives

* Sophisticated encoded or obfuscated prompt injections that slip past basic filters without triggering guardrail intervention.

## References

* [GuardDuty AI Protection finding types](https://docs.aws.amazon.com/guardduty/latest/ug/findings-ai-protection.html)