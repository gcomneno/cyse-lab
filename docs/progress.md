# CYSE Lab — Current Learning State

## Status

CYSE Lab is active again and now has a canonical progression from historical controlled-learning evidence into independently designed, testable security-engineering labs.

The current phase transition is:

```text
Observe -> Assess
```

Labs 02 and 03 are complete. Lab 04 is the first canonical **Assess** unit and is currently in design.

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
- `reports/lessons-learned-lab-03.md`.

Key boundary: `recognized EXIF absent` does not mean anonymous or free of all identifying information.

### Lab 04 — Dependency Vulnerability Auditor

Status: **DESIGN IN PROGRESS — issue #16**

Phase: **Assess**

Design authority under review:

- `docs/labs/04-dependency-vulnerability-auditor.md`

Proposed v1 boundary:

- Composer/PHP only;
- resolved `composer.lock` dependency evidence;
- optional root `composer.json` for direct/transitive classification;
- normalized advisory fixtures for deterministic offline assessment;
- explicit `AFFECTED`, `NOT_KNOWN_AFFECTED`, `UNKNOWN`, `NOT_ASSESSABLE` semantics;
- no automatic remediation;
- no `SAFE` state.

Implementation must remain out of scope until the design is reviewed and merged.

## External-source provenance

New external sources are governed by `docs/external-sources.md` and repository `AGENTS.md`.

For `CarterPerez-dev/Cybersecurity-Projects`:

- role: external learning/reference source and candidate-problem source;
- license: AGPL-3.0;
- current CYSE pattern: adapt the problem/learning objective while independently designing and implementing CYSE artifacts;
- upstream implementation code remains `REFERENCE ONLY` unless an explicit later reuse/license decision says otherwise.

## Current structural gaps

The restart baseline is complete, but historical cleanup remains intentionally separate from new lab delivery:

1. historical units are not all packaged as numbered labs;
2. CSP and secure-login duplicate paths remain;
3. some Lessons Learned material is embedded in broad historical documents;
4. historical navigation can be improved without rewriting or deleting evidence.

These gaps do not block Lab 04.

## Current learning direction

The canonical sequence is now:

```text
historical controlled foundations
    -> Lab 02: observe HTTP security properties
    -> Lab 03: observe and safely transform privacy metadata
    -> Lab 04: assess resolved software dependencies against advisory evidence
```

Lab 04 deliberately introduces software-supply-chain assessment while preserving CYSE's defensive, explainable and evidence-driven boundary.

## Historical preservation rule

Existing scans, notes and examples are learning evidence. They must not be deleted merely because a new canonical structure exists. Cleanup must distinguish:

- canonical current documentation;
- historical evidence;
- genuine duplicates;
- obsolete or unsafe material.

Deletion requires an explicit evidence-based decision.