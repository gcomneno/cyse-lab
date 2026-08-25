# CYSE Lab — Canonical Labs

This directory is the canonical entry point for formal CYSE learning units.

## Completed

### Lab 02 — HTTP Security Headers Auditor

Status: **completed**

- Design: [`02-http-security-headers-auditor.md`](02-http-security-headers-auditor.md)
- Implementation: `src/cyse_headers.php`
- Tests: `tests/headers_auditor_test.php`
- Verification evidence: `reports/lab-02-local-verification.md`

Learning phase: **Observe**

Core transition:

`manual HTTP/header inspection -> deterministic finding model -> controlled hardening verification`

### Lab 03 — Metadata Privacy Scrubber

Status: **completed**

- Design: [`03-metadata-privacy-scrubber.md`](03-metadata-privacy-scrubber.md)
- Implementation: `src/cyse_metadata.php`
- Tests: `tests/metadata_scrubber_test.php`
- End-to-end verifier: `tools/verify_lab03.php`
- Verification evidence: `reports/lab-03-verification.md`
- Lessons Learned: `reports/lab-03-lessons-learned.md`

Learning phase: **Observe**

Scope: JPEG-only v1, recognized EXIF APP1 metadata only.

Core transition:

`inspect original -> recognized EXIF present -> scrub distinct output -> verify PASS -> original remains unchanged`

### Lab 04 — Dependency Vulnerability Auditor

Status: **completed by PR #21 when merged**

- Design: [`04-dependency-vulnerability-auditor.md`](04-dependency-vulnerability-auditor.md)
- Implementation: `src/cyse_deps.php`
- Tests: `tests/dependency_auditor_test.php`
- Learning-transition verifier: `tools/verify_lab04.php`
- Verification evidence: `reports/lab-04-verification.md`
- Lessons Learned: `reports/lab-04-lessons-learned.md`

Learning phase: **Assess**

Scope: Composer/PHP resolved lockfile evidence with local normalized advisory snapshots.

Core transition:

`resolved version A -> AFFECTED -> learner-controlled version B -> NOT_KNOWN_AFFECTED`

Key boundary: `NOT_KNOWN_AFFECTED` is not `SAFE`; it is bounded to the supplied advisory snapshot and supported matching semantics.

## Next direction

The next canonical unit should be chosen from the remaining **Assess** prerequisites and candidate projects rather than automatically escalating to agentic tooling.

Strong candidates include offline network-traffic analysis or another bounded assessment unit that consolidates prerequisite gaps. Any Strix runtime/PoV remains deferred behind the learning-before-automation capability gate in `docs/architecture.md`.
