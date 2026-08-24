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

Status: **completed by PR #15 when merged**

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

## Next candidate

### Dependency Vulnerability Auditor

Provisional status: **candidate for design issue**

Learning phase: **Assess**

Rationale:

- moves CYSE from passive observation into explicit evidence classification;
- combines software-engineering and cybersecurity value;
- can operate on local dependency manifests and structured advisory data;
- keeps the default safety boundary low-impact and non-exploitative.

No implementation is authorized until a dedicated design issue defines scope, advisory-source behavior, offline fixtures, false-positive handling and verification criteria.
