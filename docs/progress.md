# CYSE Lab — Current Learning State

## Status

CYSE Lab is active again and now has a canonical progression from historical controlled-learning evidence into independently designed, testable security-engineering labs.

The current phase transition is:

```text
Observe -> Assess
```

Labs 02, 03 and 04 are complete. Lab 04 is the first canonical **Assess** unit.

## Historical learning inventory

The repository predates the current numbered-lab architecture. The following material remains valid historical evidence and must be preserved while canonical packaging is improved.

### Unit A — Web recon and service discovery

Status: **completed historical evidence; canonical packaging still incomplete**

Evidence includes:

- `reports/lessons_learned_1.md`;
- `scans/scan_basic_local.nmap`;
- `scans/gobuster_127.0.0.1.txt`;
- `scans/nikto_127.0.0.1.txt`;
- `tools/enumerate.sh`.

### Unit B — Apache hardening

Status: **completed historical evidence**

Topics include response headers, `/server-status`, ETags, TRACE, ServerName, firewall/interface restrictions and post-change verification.

### Unit C — Controlled lab networking and logging

Status: **completed historical evidence; documentation normalization still desirable**

Topics include isolated Kali/Ubuntu lab networking, interface/address reasoning and kernel/firewall logging.

### Unit D — SQL injection: exploit to fix

Status: **completed controlled learning evidence**

Evidence includes `docs/IGIENIC_LOGIN.md`, explained PHP examples and controlled local exploit-to-fix reasoning.

### Unit E — Reflected XSS and contextual escaping

Status: **completed controlled learning evidence**

Evidence includes `src/search.php` and historical CSP/escaping notes.

### Unit F — Content Security Policy

Status: **completed historical evidence; duplicate documentation remains**

`docs/CSP.md` and `docs/02. CSP.md` represent duplicate historical paths and should not be silently deleted without an explicit cleanup decision.

### Unit G — Secure login implementation notes

Status: **completed historical evidence; duplicate documentation remains**

`docs/IGIENIC_LOGIN.md` and `docs/01 .IGIENIC_LOGIN.md` represent duplicate historical paths pending canonical cleanup.

## Canonical numbered labs

### Lab 01 — Recon Web essenziale

Status: **historical/bootstrap canonical lab**

Role: foundational controlled reconnaissance and observation.

### Lab 02 — HTTP Security Headers Auditor

Status: **COMPLETE**

Phase: **Observe**

Canonical design:

- `docs/labs/02-http-security-headers-auditor.md`

Implementation/evidence:

- passive single-target HTTP(S) assessment;
- deterministic header findings;
- human/JSON semantic parity;
- offline tests in CI;
- learner-owned loopback `FAIL -> hardening -> PASS` evidence;
- `reports/lab-02-local-verification.md`.

Key boundary: findings describe observed response-header properties and do not certify an application as secure.

### Lab 03 — Metadata Privacy Scrubber

Status: **COMPLETE**

Phase: **Observe**

Canonical design:

- `docs/labs/03-metadata-privacy-scrubber.md`

Implementation/evidence:

- JPEG-only v1;
- structured JPEG marker traversal;
- recognized EXIF APP1 inspection/removal;
- non-destructive distinct-output contract;
- independent post-scrub verification;
- synthetic offline test fixtures;
- original immutability evidence;
- `reports/lab-03-verification.md`;
- `reports/lab-03-lessons-learned.md`.

Key boundary: `recognized EXIF absent` does not mean anonymous or free of all identifying information.

### Lab 04 — Dependency Vulnerability Auditor

Status: **COMPLETE by PR #21 when merged**

Phase: **Assess**

Canonical design:

- `docs/labs/04-dependency-vulnerability-auditor.md`

Implementation/evidence:

- Composer/PHP-only v1;
- resolved dependency evidence from `composer.lock`;
- optional root `composer.json` for direct/transitive classification only;
- normalized local advisory snapshots;
- explicit `AFFECTED`, `NOT_KNOWN_AFFECTED`, `UNKNOWN`, `NOT_ASSESSABLE` semantics;
- deterministic offline tests;
- fixed-snapshot learning transition;
- `reports/lab-04-verification.md`;
- `reports/lab-04-lessons-learned.md`.

Key boundary: `NOT_KNOWN_AFFECTED` is a bounded advisory statement, not proof that a dependency is safe.

## External-source provenance

New external sources are governed by `docs/external-sources.md` and repository `AGENTS.md`.

For `CarterPerez-dev/Cybersecurity-Projects`:

- role: external learning/reference source and candidate-problem source;
- license: AGPL-3.0;
- current CYSE pattern: adapt the problem/learning objective while independently designing and implementing CYSE artifacts;
- upstream implementation code remains `REFERENCE ONLY` unless an explicit later reuse/license decision says otherwise.

For `usestrix/strix`:

- educational/reference role: `REFERENCE ONLY`;
- architectural reference role: `ADOPT`;
- runtime verification and CI/security automation: `DEFER`;
- any future PoV remains behind the learning-before-automation prerequisite gate.

## Current structural gaps

The restart baseline is complete, but historical cleanup remains intentionally separate from new lab delivery:

1. historical units are not all packaged as numbered labs;
2. CSP and secure-login duplicate paths remain;
3. some Lessons Learned material is embedded in broad historical documents;
4. historical navigation can be improved without rewriting or deleting evidence.

These gaps do not invalidate the current canonical labs.

## Current learning direction

The canonical sequence is now:

```text
historical controlled foundations
    -> Lab 02: observe HTTP security properties
    -> Lab 03: observe and safely transform privacy metadata
    -> Lab 04: assess resolved software dependencies against advisory evidence
```

Lab 04 establishes the first canonical **Assess** pattern: local evidence plus bounded external intelligence produces explainable assessment states with uncertainty preserved explicitly.

The next unit should consolidate remaining Assess/prerequisite gaps. Offline network-traffic analysis is a strong candidate because it adds evidence classification without prematurely escalating to broad agentic automation.

## Historical preservation rule

Existing scans, notes and examples are learning evidence. They must not be deleted merely because a new canonical structure exists. Cleanup must distinguish:

- canonical current documentation;
- historical evidence;
- genuine duplicates;
- obsolete or unsafe material.

Deletion requires an explicit evidence-based decision.