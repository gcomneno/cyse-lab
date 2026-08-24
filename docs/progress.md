# CYSE Lab — Current Learning State

## Status

CYSE Lab has more completed learning evidence than the current README suggests. The repository bootstrap formalized only **Lab 01 — Recon Web essenziale**, while later material documents additional security learning that must now be normalized.

This file records the current evidence-based state before new labs are implemented.

## Canonical inventory

### Unit A — Web recon and service discovery

Status: **completed evidence, needs canonical packaging**

Observed topics:

- `nmap -sC -sV` service discovery;
- HTTP probing;
- directory/content discovery with gobuster;
- Nikto as an automated input source;
- interpretation of HTTP methods and response behavior;
- recording scan output.

Evidence:

- `reports/lessons_learned_1.md`
- `scans/scan_basic_local.nmap`
- `scans/gobuster_127.0.0.1.txt`
- `scans/nikto_127.0.0.1.txt`
- `tools/enumerate.sh`

Gap:

- README/navigation does not fully expose the evidence and Definition of Done.

### Unit B — Apache hardening

Status: **completed evidence, needs canonical packaging**

Observed topics:

- `/server-status` restriction/removal;
- security response headers;
- ETag reduction;
- ServerName configuration;
- TRACE handling;
- firewall/interface restrictions;
- verification after changes.

Evidence:

- `reports/lessons_learned_1.md`
- `docs/CSP.md`
- historical scan output.

### Unit C — Controlled lab networking and logging

Status: **completed evidence, needs canonical packaging**

Observed topics:

- Kali attacker / Ubuntu defender VM model;
- host-only isolation;
- interface/address reasoning;
- kernel/firewall logging for ICMP and new TCP connections;
- distinction between application logs and network-level events.

Evidence:

- `docs/CSP.md`
- Lessons Learned content embedded there.

Gap:

- this material is mixed into a CSP document and should eventually be separated canonically.

### Unit D — SQL injection: exploit to fix

Status: **completed controlled learning evidence**

Observed topics:

- vulnerable SQL concatenation;
- controlled SQL injection demonstration;
- prepared statements;
- native vs emulated prepares;
- password hashing and verification;
- input validation;
- multi-statement considerations;
- second-order SQL injection reasoning.

Evidence:

- `docs/IGIENIC_LOGIN.md`
- `src/login_explained.php`
- `src/setup_db_explained.php`
- Lessons Learned content in `docs/CSP.md`.

Safety note:

- the exploit evidence belongs to an owned local lab and must remain framed as controlled verification of a security property.

### Unit E — Reflected XSS and contextual escaping

Status: **completed controlled learning evidence**

Observed topics:

- reflected XSS;
- HTML escaping;
- context-specific escaping for HTML, attributes, URLs and JavaScript;
- DOM `textContent` vs unsafe `innerHTML`;
- CSP as defense in depth rather than an escaping replacement.

Evidence:

- `src/search.php`
- `docs/CSP.md`.

### Unit F — Content Security Policy

Status: **completed evidence, duplicated documentation**

Observed topics:

- server-wide CSP;
- nonce-based CSP;
- `strict-dynamic`;
- CSP report-only mode;
- interaction with escaping;
- operational verification through response headers/browser behavior.

Evidence:

- `docs/CSP.md`
- `docs/02. CSP.md`.

Duplication:

- `docs/CSP.md` and `docs/02. CSP.md` currently share the same blob/content and should be treated as duplicate paths until a canonical naming decision is made.

### Unit G — Secure login implementation notes

Status: **completed evidence, duplicated documentation**

Evidence:

- `docs/IGIENIC_LOGIN.md`
- `docs/01 .IGIENIC_LOGIN.md`.

Duplication:

- both paths currently share the same blob/content and should be treated as duplicate paths until canonicalized.

## Current gaps

The primary gaps are structural rather than conceptual:

1. only one lab is formally advertised;
2. learning units are mixed across documents;
3. duplicate paths obscure canonical sources;
4. prerequisites and completion criteria are implicit;
5. external-source provenance was not previously formalized;
6. CI currently permits PHP lint failure without failing the workflow;
7. no repository-specific `AGENTS.md` currently governs future work.

## Proposed next learning unit

**Lab 02 — HTTP Security Headers Auditor**

Rationale:

- builds directly on Units A, B and F;
- remains passive and low-impact;
- converts manual HTTP/header knowledge into an explainable rule engine;
- introduces deterministic findings, tests, CLI semantics and CI-friendly behavior;
- can be independently designed without copying the external AGPL implementation.

Status: **design only; implementation not started**.

## Historical preservation rule

Existing scans, notes and examples are learning evidence. They must not be deleted merely because a new canonical structure is introduced. Cleanup should distinguish:

- canonical current documentation;
- historical evidence;
- genuine duplicates;
- obsolete or unsafe material.

Deletion requires an explicit evidence-based decision.