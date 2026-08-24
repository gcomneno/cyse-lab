# AGENTS.md

## Scope

These rules apply to the whole `cyse-lab` repository.

## Mission

CYSE Lab is a white-hat, evidence-driven cybersecurity learning repository. Changes must strengthen independently demonstrated knowledge, reproducibility, safety and traceability.

## Safety boundary

- Work only with systems owned by the learner or explicitly authorized targets.
- Prefer local, isolated, offline or fixture-based exercises when they teach the same concept.
- Do not broaden a lab from defensive/controlled behavior into arbitrary-target offensive capability without an explicit design decision and safety review.
- Intentionally vulnerable applications, exploit demonstrations and active scanners must be isolated and clearly documented as lab-only.
- Never include real secrets, credentials, personal data or uncontrolled exfiltration behavior in examples or fixtures.

## External sources and provenance

- External repositories are references unless a more specific decision states otherwise.
- Record upstream source, license and the CYSE decision (`ADOPT`, `ADAPT`, `REFERENCE ONLY`, `REJECT`) when an external project materially influences a lab.
- Do not copy, closely translate or mechanically restructure upstream implementation code marked `REFERENCE ONLY`.
- For AGPL/GPL or otherwise strongly copyleft sources, default to conceptual study and independent implementation unless license consequences have been explicitly reviewed.

## Learning-unit requirements

A new or materially changed lab should state:

- learning objective;
- prerequisites;
- controlled environment/scope;
- expected evidence;
- verification criteria;
- limitations;
- Lessons Learned or equivalent conclusion.

Implementation alone is not evidence of learning completion.

## Repository workflow

- Before modifying the repository, inspect applicable `AGENTS.md`, branch/state, relevant docs, issues and PRs.
- Prefer issue/specification before implementing a new lab.
- Keep changes reviewable and tied to a clear learning or repository-readiness objective.
- Verify CI and resulting repository state before declaring work complete.
- Preserve historical learning evidence unless an explicit archival/deletion decision exists.

## Security tooling

- Passive inspection tools should remain passive by default.
- Active tests require explicit scope and safe defaults.
- Avoid arbitrary-target concurrency, crawling, brute force or destructive behavior unless the specific lab requires it and containment is documented.
- Prefer mocked/offline test fixtures for network behavior when practical.
