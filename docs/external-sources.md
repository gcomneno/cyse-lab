# CYSE Lab — External Sources and Clean-Room Adaptation

## Purpose

CYSE Lab may use external repositories, articles, standards and tools as learning/reference sources. External material supplies problems, concepts, comparisons and evidence; CYSE remains the place where knowledge is independently understood, implemented and verified.

## Default source roles

An external source must be assigned an explicit role before it influences implementation:

- **REFERENCE ONLY** — study concepts, terminology, architecture, behavior or documentation; do not derive implementation code.
- **ADAPT** — adopt the problem or learning objective while independently designing CYSE architecture, naming, tests and implementation.
- **ADOPT** — intentionally adopt an external artifact, implementation, or explicitly scoped reference role. The adopted dimension must be named and requires the review appropriate to that dimension.
- **REJECT** — unsuitable for CYSE because of safety, educational value, overlap, licensing, cost or scope.

`ADOPT` is never the default.

### Role-aware decisions

A single external project may legitimately have different decisions for different roles. Record the dimension explicitly rather than collapsing the project into one label.

For example, `ADOPT` as an **architectural study reference** means CYSE deliberately treats the source as a useful architecture case study. It does **not** imply adoption of source code, dependencies, runtime, execution model or security conclusions.

When code or another distributed artifact is actually reused, that reuse remains subject to the full license/provenance boundary below regardless of any non-code `ADOPT` decision.

Recommended dimensions when relevant:

- educational/reference role;
- architectural-reference role;
- code/artifact reuse;
- runtime/tool execution;
- CI/security automation.

## Clean-room boundary

When an external source is used as a reference for a CYSE implementation:

1. define the CYSE problem and acceptance criteria independently;
2. record the source and license;
3. avoid copy/paste, close translation or mechanical restructuring of upstream implementation code;
4. derive architecture, interfaces, rule models and tests from CYSE requirements;
5. use upstream implementation only for comparison or post-design review when necessary;
6. record any deliberate reused fragment separately and perform license review before inclusion.

Studying behavior or public concepts does not by itself authorize code reuse.

## License boundary

If external code may influence distributed CYSE code, review at least:

- upstream license;
- whether the intended use constitutes copying, modification or derivation;
- attribution/notice obligations;
- source-distribution obligations;
- compatibility with the CYSE repository license;
- network-service obligations where applicable.

When this boundary is unclear, the safe default is `REFERENCE ONLY`.

## Source registry

### CarterPerez-dev/Cybersecurity-Projects

- Repository: `https://github.com/CarterPerez-dev/Cybersecurity-Projects`
- License: AGPL-3.0
- CYSE role: **external learning/reference source**
- Upstream code default: **REFERENCE ONLY**
- Curriculum as a whole: **REJECT as an adopted curriculum**
- Candidate project concepts: individually evaluated for `ADAPT / REFERENCE ONLY / REJECT`

### Current candidate decisions

| Candidate | CYSE decision | Notes |
| --- | --- | --- |
| HTTP Security Headers Auditor | ADAPT | Strong fit with existing CYSE HTTP/CSP knowledge; low-impact passive assessment. |
| Metadata Scrubber | ADAPT | Defensive privacy tooling; low safety risk; independent implementation feasible. |
| Dependency Vulnerability Auditor | ADAPT | Strong software-engineering + security value; local manifest/advisory workflow. |
| Network Traffic Analyzer | ADAPT | High networking value; begin with offline PCAP, then controlled live capture. |
| API Rate Limiter | ADAPT | Defensive security engineering; useful later after API/state prerequisites. |
| API Security Scanner | ADAPT later | Valuable but requires controlled target contract and stronger prerequisites. |
| SIEM Dashboard | ADAPT later | High value but large scope; better as later capstone. |
| Token Abuse Playground | REFERENCE ONLY now | Intentionally vulnerable and higher-risk; requires explicit vulnerable-lab contract. |
| Supply Chain Attack Simulator | REFERENCE ONLY now | Useful advanced concept; requires isolated local registry and stronger supply-chain prerequisites. |

### usestrix/strix

- Repository: `https://github.com/usestrix/strix`
- License observed during the 2026-08-25 reconnaissance: Apache-2.0; re-check upstream before any future code/runtime adoption decision.
- Educational/reference role: **REFERENCE ONLY**.
- Architectural-reference role: **ADOPT**.
- Code/artifact reuse: **NONE** by the current decision.
- Runtime/tool verification role: **DEFER**.
- CI/security-automation role: **DEFER**.

The architectural `ADOPT` decision is deliberately narrow. CYSE treats Strix as a real-world case study for agentic security-testing architecture, including concepts such as orchestration, scope decomposition, tool coordination, finding/validation lifecycle, structured evidence/reporting, sandboxing, coverage accounting, cost signals and human review boundaries. This does not make Strix a CYSE curriculum, implementation template, runtime dependency or authority over vulnerability truth.

Strix must not be installed or executed merely because it is registered here. A future runtime evaluation requires the learning/prerequisite gate in `docs/architecture.md` and a separately approved PoV.

Any future Strix execution is limited to CYSE-owned/learner-owned systems, intentionally vulnerable applications, controlled staging/lab environments, or targets with explicit documented authorization. Technical sandboxing does not establish target authorization.

The future candidate PoV is **Known Vulnerability Verification**. Its question is not whether Strix can find vulnerabilities, but:

> What incremental value does Strix provide compared with manual verification and traditional tooling?

That PoV remains deferred. No CI integration is authorized before a successful PoV and a separate downstream decision.

## Provenance expectation

When a CYSE issue or document materially originates from an external candidate, record:

- source repository/document;
- upstream license;
- concept being referenced;
- CYSE decision (`ADOPT / ADAPT / REFERENCE ONLY / REJECT`) and the role/dimension when decisions differ;
- whether upstream implementation code was inspected before CYSE design;
- any deliberate reuse and the license decision covering it.

## Safety boundary

An external project being offensive or dual-use is not evidence that it belongs in CYSE.

CYSE prioritizes defensive learning, controlled environments and systems owned by the learner or explicitly authorized. Higher-risk material must earn inclusion through educational value, explicit containment and verifiable safety boundaries.