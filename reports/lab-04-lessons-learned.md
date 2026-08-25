# Lab 04 — Lessons Learned

## What this lab teaches

Lab 04 moves CYSE from observation into bounded software-supply-chain assessment.

The central lesson is that a dependency vulnerability result is not a property of a package name alone. It depends on a concrete assessment identity and on bounded advisory evidence.

## Declared intent vs resolved reality

`composer.json` expresses dependency intent and constraints. `composer.lock` records the versions actually resolved for a project state.

For vulnerability assessment, the resolved version is the relevant local evidence. A constraint such as `^2.0` does not tell us which exact version is present.

## Dependency identity

The v1 assessment identity is deliberately narrow:

```text
ecosystem + canonical package name + resolved version + scope
```

Canonicalization matters because advisory matching must be deterministic. Guessing package identities or versions would create false confidence.

## Direct vs transitive dependencies

A vulnerable transitive dependency can matter even when the root project did not declare it explicitly.

The optional root `composer.json` is used only to explain whether a locked package is direct or transitive. That classification does not change whether an advisory matches the resolved version.

## Advisory data is evidence, not truth

The auditor consumes a normalized advisory snapshot. Its findings are bounded by that snapshot and by the supported matching semantics.

Important states are intentionally distinct:

- `AFFECTED` — active advisory evidence demonstrably matches the resolved version;
- `NOT_KNOWN_AFFECTED` — the assessment completed against the supplied snapshot and no active advisory matched;
- `UNKNOWN` — the claim cannot be established reliably because advisory/version semantics are incomplete or unsupported;
- `NOT_ASSESSABLE` — the local dependency evidence itself is insufficient or contradictory.

There is deliberately no `SAFE` state.

## Why `NOT_KNOWN_AFFECTED` is not `SAFE`

A clean bounded advisory lookup cannot detect:

- unknown vulnerabilities;
- unpublished vulnerabilities;
- gaps in the chosen advisory source;
- source-code-specific exploitability;
- vulnerable behavior outside dependency advisories;
- future advisories published after the snapshot.

Therefore the correct claim is only that no known active advisory in the supplied bounded snapshot matched the resolved version.

## Version constraints

Composer's full version-constraint language is broad. Lab 04 v1 intentionally supports a small tested subset rather than pretending to implement the complete ecosystem semantics.

Unsupported relevant constraint syntax produces `UNKNOWN` instead of silently becoming a non-match.

This is an important security-engineering principle: unsupported evidence should reduce confidence, not increase it.

## Withdrawn advisories

A withdrawn advisory is not treated as active affected evidence. Withdrawal status is part of advisory provenance and must be considered explicitly.

## Detection is separate from remediation

The auditor does not:

- edit `composer.json`;
- edit `composer.lock`;
- run `composer update`;
- choose replacement versions;
- claim that a newer version is compatible or safe.

Finding a vulnerable dependency and deciding how to remediate it are separate engineering tasks.

## Deterministic exit behavior

A completed bounded assessment with no `AFFECTED` dependency can exit successfully, but that is not certification.

Material uncertainty has higher precedence than a superficially clean result. Mixed `AFFECTED + UNKNOWN` evidence remains visibly incomplete rather than being collapsed into a simple pass/fail story.

## Offline-first verification

The canonical tests use synthetic local advisory fixtures and require no Internet access. This provides:

- reproducibility;
- stable evidence;
- no dependency on changing external APIs;
- no leakage of private package identities;
- a clear distinction between semantic correctness and future live-source integration.

## Canonical learning transition

Using one fixed advisory snapshot:

```text
resolved version 1.5.0
    -> AFFECTED

learner changes resolved fixture to 2.1.0
    -> NOT_KNOWN_AFFECTED
```

Because the advisory snapshot stays unchanged, the learner can attribute the result change to resolved dependency evidence.

## Security and privacy boundary

Lab 04 is defensive and read-only. It operates on learner-owned dependency metadata and synthetic advisory datasets. v1 performs no package installation, source upload, network lookup or remediation action.

## Main takeaway

Dependency vulnerability scanning is not `package -> safe/unsafe`.

A more honest model is:

```text
resolved dependency evidence
    + bounded advisory evidence
    + supported matching semantics
    -> explainable assessment state
    + explicit uncertainty
```

That uncertainty is part of the result, not an inconvenience to hide.
