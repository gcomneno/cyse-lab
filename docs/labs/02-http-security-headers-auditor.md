# Lab 02 — HTTP Security Headers Auditor

Status: **design specification**  
Issue: #6  
Implementation status: **not started**

## Purpose

This lab converts CYSE's existing manual HTTP/header knowledge into an independently designed, passive security assessment tool.

The learner should move from:

`curl -I + manual interpretation`

to:

`bounded HTTP observation -> normalized evidence -> deterministic rule evaluation -> explainable finding -> machine-usable result`

The lab is intentionally narrow. It is not a web crawler, vulnerability scanner, TLS scanner, CSP parser, exploit tool or general-purpose reconnaissance framework.

## Provenance / clean-room declaration

External candidate source:

- repository: `CarterPerez-dev/Cybersecurity-Projects`;
- upstream license: AGPL-3.0;
- referenced concept: HTTP security-header assessment;
- CYSE decision: **ADAPT**;
- upstream implementation code used for this design: **no**.

This specification is derived from CYSE requirements and existing CYSE evidence. The upstream implementation remains `REFERENCE ONLY` and must not be consulted to derive architecture, naming, rule logic, tests or implementation details.

## Learning objectives

By completing this lab, the learner should be able to:

1. explain why HTTP response headers can encode security controls;
2. distinguish header **presence** from header **semantic strength**;
3. model security findings as data rather than prose-only output;
4. separate network I/O from deterministic evaluation logic;
5. design rules that are testable without network access;
6. express uncertainty and non-applicability explicitly;
7. define stable CLI and exit-code contracts;
8. explain limitations, false positives and false negatives;
9. verify the same rule behavior against fixtures and a controlled live target.

## Prerequisites

Required CYSE knowledge:

- Unit A — web recon and HTTP response inspection;
- Unit B — Apache hardening and response-header verification;
- Unit F — Content Security Policy;
- basic shell usage and exit-code semantics.

Useful supporting evidence already present in CYSE:

- `reports/lessons_learned_1.md`;
- `docs/CSP.md`;
- historical `curl -I` verification notes;
- Apache security-header configuration notes.

## Safety boundary

The auditor must remain passive and low-impact by default.

Allowed behavior:

- one bounded HTTP request per resolved target attempt;
- follow redirects only according to the explicit redirect policy below;
- inspect response metadata and headers;
- report findings locally.

Out of scope:

- crawling;
- endpoint discovery;
- payload injection;
- authentication bypass attempts;
- brute force;
- concurrent scanning of arbitrary targets;
- content fuzzing;
- JavaScript execution;
- browser automation;
- certificate/TLS vulnerability scanning;
- modification of the target.

Live use is permitted only against systems owned by the learner or explicitly authorized. Automated tests should not require Internet access.

## Functional boundary

### Input

The primary input is a single absolute HTTP(S) URL.

Examples of valid input shapes:

- `https://example.test/`
- `http://127.0.0.1:8080/`

The tool must not silently invent a scheme for a bare hostname. Ambiguous input should fail validation before any network request.

### Observation

The network layer should collect at least:

- requested URL;
- final URL after redirects;
- HTTP status;
- response headers;
- redirect chain metadata;
- request/response error category when observation fails.

The evaluator must consume a normalized observation object rather than a live HTTP client.

### Output

The tool should support two output modes:

1. human-readable terminal report;
2. structured machine-readable JSON.

Both output modes must represent the same semantic result.

## Architecture

The preferred architecture is a small functional-core / imperative-shell pipeline:

`CLI -> input validation -> HTTP observation -> normalization -> rule evaluation -> aggregate result -> renderer -> exit code`

### Boundary 1 — CLI/input validation

Responsibilities:

- parse arguments;
- require an explicit `http://` or `https://` scheme;
- validate timeout and other numeric options;
- reject unsupported input before network I/O.

No security policy belongs in this layer.

### Boundary 2 — HTTP observation

Responsibilities:

- execute the bounded request;
- apply timeout policy;
- apply redirect policy;
- capture the final response metadata;
- convert transport failures into typed observation errors.

This layer must not decide whether a header is secure.

### Boundary 3 — normalization

Responsibilities:

- normalize header names case-insensitively;
- preserve original values for evidence;
- expose deterministic lookup behavior;
- represent duplicate/multi-value headers without accidental loss of evidence.

### Boundary 4 — rule evaluation

Each rule consumes normalized evidence and produces one finding.

Rules must be pure/deterministic where practical: the same normalized observation must produce the same finding.

### Boundary 5 — rendering

Renderers consume the same aggregate result. Human and JSON output must not implement different policy semantics.

## Finding model

Each finding must contain at least:

- `rule_id` — stable machine identifier;
- `header` — relevant response header;
- `status` — semantic result;
- `severity` — impact category for the missing/weak control;
- `observed` — normalized observed value or explicit absence;
- `evidence` — concise factual observation;
- `rationale` — why the result matters;
- `recommendation` — bounded remediation guidance;
- `limitations` — optional rule-specific caveat.

### Finding statuses

Use exactly these initial statuses:

- `PASS` — observed evidence satisfies the rule;
- `WEAK` — the header exists but its value materially weakens or disables the expected control;
- `FAIL` — the expected header/control is absent or clearly fails the rule;
- `NOT_APPLICABLE` — the rule is not meaningful for the observed context;
- `UNKNOWN` — evidence is insufficient to make a defensible determination.

`UNKNOWN` is intentionally distinct from `FAIL`: transport ambiguity or unsupported syntax must not be converted into a security failure without evidence.

## Severity model

Initial severity vocabulary:

- `HIGH`;
- `MEDIUM`;
- `LOW`;
- `INFO`.

Severity describes the importance of the control represented by the rule, not an asserted exploitability score for the target.

CYSE must not claim CVSS equivalence unless a future issue explicitly introduces and justifies it.

## Initial rule set

The first implementation should remain intentionally small.

### HSTS

Header: `Strict-Transport-Security`

Context:

- meaningful only on an HTTPS final response;
- on plain HTTP, return `NOT_APPLICABLE` rather than pretending an HSTS header in that response would establish protection.

Minimum semantics:

- absent on HTTPS -> `FAIL`;
- `max-age=0` -> `WEAK` because the policy is explicitly disabled;
- positive valid `max-age` -> candidate `PASS`;
- malformed/ambiguous value -> `UNKNOWN` or `WEAK` according to a documented deterministic parser decision.

The first version should not award extra security claims merely because `includeSubDomains` or `preload` is present. Those may be exposed as evidence and considered in later rule revisions.

Severity: `HIGH`.

### Content Security Policy

Header: `Content-Security-Policy`

Minimum semantics:

- absent -> `FAIL`;
- present and non-empty -> not automatically `PASS` unless the first implementation defines a bounded semantic check;
- malformed/obviously empty value -> `WEAK` or `UNKNOWN` according to deterministic parsing rules.

Important limitation:

A complete CSP security analysis is explicitly out of scope for Lab 02 v1. Presence of a CSP does not prove that XSS is prevented.

The preferred v1 decision is therefore conservative:

- missing -> `FAIL`;
- empty -> `WEAK`;
- non-empty syntactically observable policy -> `PASS` **with an explicit limitation that policy strength is not fully evaluated**.

Severity: `HIGH`.

### X-Content-Type-Options

Header: `X-Content-Type-Options`

Semantics:

- absent -> `FAIL`;
- case-insensitive value `nosniff` -> `PASS`;
- any other non-empty value -> `WEAK`.

Severity: `MEDIUM`.

### Frame embedding protection

Headers considered:

- `Content-Security-Policy` via `frame-ancestors` when detectable by the bounded parser;
- `X-Frame-Options` as legacy defense-in-depth evidence.

For v1, avoid pretending to implement a full CSP parser. The initial rule may evaluate `X-Frame-Options` independently:

- absent -> `FAIL`;
- `DENY` or `SAMEORIGIN` -> `PASS`;
- obsolete/unsupported/other values -> `WEAK` or `UNKNOWN` according to explicit parser rules.

The report must explain that CSP `frame-ancestors` is the modern policy mechanism and that the v1 rule is intentionally limited.

Severity: `MEDIUM`.

### Referrer Policy

Header: `Referrer-Policy`

Initial semantics should use a small explicit allow/weak set rather than assuming every recognized value has equal privacy properties.

At minimum:

- absent -> `FAIL`;
- empty/invalid -> `WEAK`;
- recognized value -> deterministic `PASS` or `WEAK` according to a documented policy table.

Severity: `LOW`.

### Permissions Policy

Header: `Permissions-Policy`

For v1 this rule is intentionally shallow:

- absent -> `FAIL`;
- empty -> `WEAK`;
- non-empty -> `PASS` with a limitation that individual feature directives are not fully audited.

Severity: `LOW`.

## Scoring decision

**Decision for Lab 02 v1: do not implement a numeric score or letter grade.**

Rationale:

- a single number can imply more certainty than the bounded rules justify;
- not all controls are equally applicable to all applications;
- CSP and Permissions-Policy receive intentionally shallow analysis in v1;
- the main learning objective is explainable rule evaluation, not gamification.

The aggregate result should instead expose counts by finding status and severity.

Example conceptual summary:

`2 PASS, 1 WEAK, 3 FAIL, 0 UNKNOWN, 0 NOT_APPLICABLE`

A future issue may introduce a scoring model only if its semantics and limitations are explicitly justified.

## Aggregate result

The aggregate result should include:

- requested URL;
- final URL;
- HTTP status;
- redirect count;
- ordered findings;
- counts by finding status;
- counts by severity;
- observation warnings;
- tool/schema version.

Rule order must be stable so output and fixtures remain deterministic.

## CLI contract

Proposed command shape:

```text
cyse-headers audit <URL> [--timeout SECONDS] [--no-follow] [--json]
```

Final executable/package naming may change during implementation, but semantics should remain stable.

### Default behavior

- exactly one input URL;
- redirects followed according to bounded policy;
- finite timeout;
- human-readable output;
- no retries unless explicitly introduced later;
- no parallelism.

### Validation errors

Invalid CLI input must fail before network access.

Examples:

- missing scheme;
- unsupported scheme;
- invalid timeout;
- malformed URL.

## Redirect policy

Default:

- follow redirects;
- enforce a small finite redirect limit;
- audit the **final** response;
- preserve the redirect chain as evidence;
- report a warning when the scheme changes, especially HTTPS -> HTTP.

`--no-follow` should audit the first response only.

Redirect loops or limit exhaustion are observation failures, not header `FAIL` findings.

## Timeout and transport errors

Every request must have a finite timeout.

Transport failures should be categorized, for example:

- timeout;
- DNS resolution failure;
- connection refused;
- TLS/connection error;
- redirect limit exceeded;
- unsupported response condition.

If no usable response is available, the tool should return an observation error and must not fabricate per-header `FAIL` findings.

## Exit-code contract

Initial proposal:

- `0` — observation succeeded and no `FAIL` findings exist;
- `1` — observation succeeded and one or more `FAIL` findings exist;
- `2` — CLI/input error;
- `3` — network/observation error;
- `4` — internal/unexpected error.

`WEAK` findings alone do not make the command exit `1` in v1. They remain visible and machine-readable. This keeps exit semantics simple and prevents a weak-value policy debate from silently breaking CI.

If future requirements need stricter gating, introduce an explicit option such as a policy threshold rather than changing the default contract silently.

## Human-readable report requirements

The terminal report should show:

- requested/final URL;
- HTTP status and redirect count;
- one row or block per rule;
- finding status;
- observed evidence;
- concise rationale;
- concise recommendation;
- limitations when relevant;
- final status summary.

Presentation may use color, but meaning must not depend on color alone.

## JSON contract

JSON output should be stable enough for tests and later CI integration.

Requirements:

- explicit schema/tool version;
- stable machine identifiers;
- no ANSI/color sequences;
- deterministic key/value semantics;
- observed header values preserved as evidence;
- typed error representation;
- same statuses and severities as human output.

A formal JSON Schema may be added during implementation if it improves verification.

## Testing strategy

### Unit tests — pure rule logic

No network access.

Each rule should have fixtures covering at least:

- header absent;
- strong/expected value;
- weak value;
- malformed/unrecognized value;
- case-insensitive header names;
- case normalization where semantics permit it;
- duplicate/multi-value behavior where relevant;
- applicable/non-applicable contexts.

### Observation tests

Use a local HTTP fixture server or mocked HTTP transport.

Cover:

- direct 200 response;
- redirect to final response;
- redirect loop/limit;
- timeout;
- connection failure;
- HTTP -> HTTPS;
- HTTPS -> HTTP warning path where fixture tooling permits it.

### CLI tests

Cover:

- missing URL;
- bare hostname rejection;
- unsupported scheme;
- human output invocation;
- JSON output invocation;
- exit-code mapping.

### Determinism tests

The same normalized observation fixture must produce byte-for-byte stable semantic JSON after excluding intentionally variable metadata, if any.

## Verification plan

The implementation issue should require evidence from both:

1. offline/mocked fixtures proving rule semantics;
2. one learner-owned local HTTP service configured with known headers.

Verification should demonstrate at least one transition such as:

`FAIL -> configuration change -> PASS`

for a control already studied in CYSE, preferably `X-Content-Type-Options` or CSP presence.

This connects the auditor back to the existing hardening knowledge instead of turning it into a detached scanner project.

## Limitations to document

The completed lab must state explicitly that:

- response headers alone do not prove that an application is secure;
- CSP presence is not equivalent to a strong CSP;
- no TLS configuration analysis is performed;
- no cookie security analysis is performed in v1;
- no HTML/body/JavaScript analysis is performed;
- no authentication state is modeled;
- application-specific requirements may make some recommendations inappropriate;
- findings are evidence-driven heuristics within the documented rule contract, not vulnerability guarantees.

## Implementation constraints

The implementation should prefer:

- a small dependency surface;
- explicit typed/domain models where supported by the chosen language;
- pure rule functions;
- mocked/local tests;
- deterministic output;
- no telemetry;
- no hidden network calls beyond the requested target.

Language choice is deliberately **not decided by this design issue**. It should be selected in the implementation issue based on CYSE learning value and repository/tooling fit, not by mirroring the external source.

## Definition of Done for the design issue

Issue #6 can be considered complete when:

- this specification is merged;
- the safety boundary is explicit;
- finding/status/severity semantics are fixed for v1;
- the no-score decision is recorded;
- CLI and exit-code contracts are defined;
- redirect/error behavior is defined;
- test and verification strategy are defined;
- provenance explicitly states that upstream implementation code was not used for the design;
- implementation remains unstarted until a separate implementation issue is opened.

## Next step after design

Open a separate implementation issue that references this specification and requires the implementation to be produced independently from CYSE requirements.
