# CYSE Lab — Learning Architecture

## Purpose

CYSE Lab is a white-hat, evidence-driven cybersecurity learning repository. Its purpose is to turn security concepts into independently built, explainable and verifiable learning artifacts.

The repository is not an exploit collection and is not a mirror of external curricula or implementations.

## Core learning loop

Each learning unit should make the following chain explicit:

`objective -> prerequisites -> controlled environment -> exercise -> evidence -> verification -> lesson learned -> next prerequisite`

A unit is not considered complete merely because commands were executed or code exists. Completion requires traceable evidence and a verification criterion.

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

The current repository already contains evidence for several topics beyond the single formal README lab:

- web recon and enumeration;
- Apache discovery and hardening;
- network/firewall logging;
- SQL injection exploit/fix learning in a controlled environment;
- prepared statements and password hashing;
- reflected XSS and contextual escaping;
- Content Security Policy;
- isolated Kali/Ubuntu host-only networking.

These topics must be normalized into canonical learning units before they are treated as prerequisites for new work.

## Progression rule

CYSE does not adopt external difficulty labels automatically. A topic advances from beginner to intermediate or advanced based on its actual prerequisites, system complexity, safety requirements and verification burden inside CYSE.

External project catalogs may provide candidate problems and references, but CYSE owns its progression and implementation decisions.

## Current next step

The first proposed new project is **Lab 02 — HTTP Security Headers Auditor**, because it consolidates knowledge already present in CYSE while introducing a more rigorous rule/finding/test model with a very low-impact safety profile.

Implementation remains blocked until the Lab 02 design issue is complete.