# CYSE Lab — Learning Architecture

## Purpose

CYSE Lab is a white-hat, evidence-driven cybersecurity learning repository. Its purpose is to turn security concepts into independently built, explainable and verifiable learning artifacts.

The repository is not an exploit collection and is not a mirror of external curricula or implementations.

## Core learning loop

Each learning unit should make the following chain explicit:

`objective -> prerequisites -> controlled environment -> exercise -> evidence -> verification -> lesson learned -> next prerequisite`

A unit is not considered complete merely because commands were executed or code exists. Completion requires traceable evidence and a verification criterion.

## Learning before automation

CYSE automation must follow demonstrated understanding rather than substitute for it.

Canonical progression:

`understand -> implement -> test manually -> verify -> automate`

Automation may compress already-understood work, improve repeatability or add an independent observation channel. It must not be used to skip the manual learning and evidence needed to understand what the automation is claiming.

This rule applies to scripts, scanners, security platforms and agentic/AI security-testing tools alike.

### Agentic-tool epistemic boundary

An automated finding is evidence, not an automatically accepted vulnerability.

CYSE preserves a conceptual validation chain:

`observation -> hypothesis -> candidate vulnerability -> reproduction -> evidence -> validated vulnerability -> human review`

Not every tool exposes every intermediate state, but CYSE review must preserve their meaning. In particular:

- `no finding != no vulnerability`;
- successful tool execution does not establish complete security coverage;
- a reported severity remains evidence/assessment to review, not unquestioned truth;
- generated proof-of-concept material must be reproduced and interpreted inside the authorized lab boundary;
- human review remains the acceptance boundary for a vulnerability finding;
- remediation must be followed by manual regression before automated regression is treated as supporting evidence.

### Authorization is independent of sandboxing

`sandbox boundary != authorization boundary`

A container, VM, restricted network or agent sandbox can reduce technical impact. It does not prove that the target may legally or ethically be tested.

Any active or agentic security test still requires an owned target or explicit documented authorization and a bounded scope/rules-of-engagement contract.

### Gate for broad agentic security verification

A broad agentic security-testing tool may be evaluated only after CYSE has sufficient manual evidence across the capabilities that the tool would otherwise abstract away.

The gate is capability-based rather than a fixed number of labs. At minimum, evidence should cover the applicable portions of:

- HTTP request/response behavior;
- cookies and sessions;
- authentication and authorization;
- interception proxy workflow;
- recon/enumeration;
- OWASP Top 10 reasoning;
- injection and command injection;
- XSS and CSRF;
- SSRF;
- IDOR/BOLA;
- path traversal;
- security headers/CSP;
- static and dynamic analysis;
- basic threat modelling;
- severity/risk reasoning;
- finding reproduction and evidence;
- remediation and regression testing;
- rules of engagement, authorization and scope.

Existing CYSE historical/canonical evidence already covers parts of HTTP behavior, recon/enumeration, SQL injection, XSS, CSP/security headers, authentication/login reasoning, finding evidence, remediation/regression-style verification and isolated lab scope.

Material gaps before a broad Strix-style PoV currently include more systematic evidence for cookies/sessions, authorization and IDOR/BOLA, interception proxy use, CSRF, SSRF, command injection, traversal, structured static/dynamic analysis, threat modelling, explicit severity/risk methodology and a formal rules-of-engagement artifact.

These gaps are a prerequisite map, not an instruction to create one lab per bullet. Future learning units should consolidate related capabilities where that produces better evidence.

### Deferred agentic verification PoV

After the capability gate is satisfied, CYSE may design a minimal **Known Vulnerability Verification** PoV using an intentionally vulnerable CYSE-owned target whose vulnerability has already been manually understood and reproduced.

The intended sequence is:

```text
CYSE-owned intentionally vulnerable target
    -> documented scope + authorization
    -> known security model and expected tests
    -> manual discovery and PoC/evidence
    -> traditional tooling
    -> isolated agentic-tool verification
    -> compare findings + evidence + coverage
    -> human review
    -> remediation
    -> manual regression
    -> optional automated retest/regression
```

The PoV question is:

> What incremental value does the agentic tool provide compared with manual verification and traditional tooling?

Useful metrics may include detected/not detected, false positives, known false negatives, evidence quality, severity correctness, explanation quality, coverage evidence, elapsed time, cost, requests/actions performed, run-to-run reproducibility and unexpected behavior.

A PoV must be designed and approved separately. CI/security automation remains downstream of a successful PoV and is not implied by architectural study.

## Learning phases

### 1. Observe

Goal: learn to inspect systems and security-relevant signals without attempting exploitation.

Typical topics:

- HTTP response inspection;
- service discovery in owned/authorized environments;
- security headers;
- metadata/privacy inspection;
- log observation.

Default safety posture: passive, low-impact, bounded requests.

### 2. Assess

Goal: classify observed evidence into meaningful security findings.

Typical topics:

- dependency vulnerability assessment;
- configuration assessment;
- offline packet/PCAP analysis;
- severity and evidence modeling;
- false-positive handling.

Default safety posture: prefer local files, fixtures and offline datasets; active network interaction remains explicitly scoped.

### 3. Protect

Goal: implement defensive controls and verify the security property they provide.

Typical topics:

- secure configuration;
- rate limiting;
- authentication/session hardening;
- least privilege;
- secure logging.

Default safety posture: operate on CYSE-owned applications or local lab infrastructure.

### 4. Test security properties

Goal: verify that a defensive property holds by exercising a controlled negative case.

Typical topics:

- SQL injection prevention;
- XSS prevention;
- authentication/authorization checks;
- API security properties.

Default safety posture: intentionally vulnerable behavior is permitted only inside owned, isolated or explicitly authorized targets.

### 5. Detect and correlate

Goal: learn how attacks and failures appear from the defender's perspective.

Typical topics:

- normalized events;
- correlation rules;
- alert lifecycle;
- incident investigation;
- timeline reconstruction.

Default safety posture: use generated, replayed or lab-owned event data whenever possible.

### 6. Advanced controlled adversarial labs

Goal: study higher-risk attack classes only when the environment and learning objective justify them.

Examples may include token abuse or software supply-chain attack simulations.

These labs require an explicit safety contract and must avoid real targets, real credentials, real registries or uncontrolled propagation.

## Definition of Done for a learning unit

A unit is complete only when all applicable items are present:

1. explicit learning objective;
2. prerequisites;
3. owned/authorized scope;
4. reproducible setup;
5. exercise or implementation;
6. captured evidence;
7. verification criteria with observed result;
8. explanation of why the result matters;
9. limitations and false-positive/false-negative considerations where relevant;
10. Lessons Learned or equivalent summary;
11. next recommended prerequisite or learning unit.

## Evidence classes

Evidence may include:

- source code authored in CYSE;
- tests;
- command output;
- scan output from authorized lab targets;
- configuration diffs;
- screenshots only when text evidence is insufficient;
- structured reports;
- Lessons Learned.

Evidence should be reproducible where practical and should never include real secrets or personal data.

## Existing material mapping

The current repository contains historical and canonical evidence for several security topics, including:

- web recon and enumeration;
- Apache discovery and hardening;
- network/firewall logging;
- SQL injection exploit/fix learning in a controlled environment;
- prepared statements and password hashing;
- reflected XSS and contextual escaping;
- Content Security Policy and HTTP security-header assessment;
- isolated Kali/Ubuntu host-only networking;
- non-destructive metadata/privacy inspection and verification.

Historical topics should be normalized when they become formal prerequisites, but the existence of historical evidence must not be confused with completion of every modern capability gate.

## Progression rule

CYSE does not adopt external difficulty labels automatically. A topic advances from beginner to intermediate or advanced based on its actual prerequisites, system complexity, safety requirements and verification burden inside CYSE.

External project catalogs may provide candidate problems and references, but CYSE owns its progression and implementation decisions.

## Current next step

Lab 04 — Dependency Vulnerability Auditor is the first canonical **Assess** unit. Its design is defined in `docs/labs/04-dependency-vulnerability-auditor.md`; implementation must be tracked separately and preserve its bounded evidence semantics.

Agentic security tooling is not the next implementation step. Architectural study may proceed, but runtime evaluation remains gated by the manual capabilities defined above.