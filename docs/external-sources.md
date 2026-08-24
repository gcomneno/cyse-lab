# CYSE Lab — External Sources and Clean-Room Adaptation

## Purpose

CYSE Lab may use external repositories, articles, standards and tools as learning/reference sources. External material supplies problems, concepts, comparisons and evidence; CYSE remains the place where knowledge is independently understood, implemented and verified.

## Default source roles

An external source must be assigned an explicit role before it influences implementation:

- **REFERENCE ONLY** — study concepts, terminology, architecture, behavior or documentation; do not derive implementation code.
- **ADAPT** — adopt the problem or learning objective while independently designing CYSE architecture, naming, tests and implementation.
- **ADOPT** — intentionally reuse an external artifact or implementation under terms compatible with CYSE; requires explicit license and provenance review.
- **REJECT** — unsuitable for CYSE because of safety, educational value, overlap, licensing, cost or scope.

`ADOPT` is never the default.

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

## Provenance expectation

When a CYSE issue or document materially originates from an external candidate, record:

- source repository/document;
- upstream license;
- concept being referenced;
- CYSE decision (`ADOPT / ADAPT / REFERENCE ONLY / REJECT`);
- whether upstream implementation code was inspected before CYSE design;
- any deliberate reuse and the license decision covering it.

## Safety boundary

An external project being offensive or dual-use is not evidence that it belongs in CYSE.

CYSE prioritizes defensive learning, controlled environments and systems owned by the learner or explicitly authorized. Higher-risk material must earn inclusion through educational value, explicit containment and verifiable safety boundaries.