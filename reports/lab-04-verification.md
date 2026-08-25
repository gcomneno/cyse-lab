# Lab 04 — Verification evidence

## Scope

This evidence records the canonical offline learning transition for the Composer Dependency Vulnerability Auditor v1.

The verification uses synthetic dependency and advisory data only. No network access, package installation, external vulnerability service, source-code upload or third-party target is involved.

## Fixed advisory snapshot

Both assessments use the same normalized synthetic advisory snapshot.

Affected package identity:

```text
package: acme/demo-package
ecosystem: Composer/Packagist
affected constraint: >=1.0.0,<2.0.0
```

The advisory snapshot is intentionally held constant across the transition so the observed state change is attributable to the learner-controlled resolved dependency version rather than changing intelligence data.

## Before learner-controlled version change

Resolved synthetic version:

```text
1.5.0
```

Observed result:

```text
AFFECTED
```

Reason: the resolved version matches the active bounded advisory constraint in the fixed snapshot.

## After learner-controlled version change

Resolved synthetic version:

```text
2.1.0
```

Observed result against the **same advisory snapshot**:

```text
NOT_KNOWN_AFFECTED
```

Reason: no active advisory in that bounded snapshot matches the resolved version under the v1 supported constraint semantics.

## Immutability

The verifier operates on temporary/synthetic fixtures and does not mutate package-manager state. The auditor itself performs read-only assessment: it does not edit `composer.json` or `composer.lock`, install packages, execute Composer update commands or select remediation automatically.

## Epistemic boundary

`NOT_KNOWN_AFFECTED` is not `SAFE`.

It means only that no active advisory in the supplied, bounded advisory snapshot matched the assessed resolved version using the semantics supported by v1.

It does not establish:

- absence of unknown or unpublished vulnerabilities;
- complete advisory-source coverage;
- exploitability or reachability;
- compatibility of a remediation;
- overall application security.

## Result

**PASS — canonical `AFFECTED -> learner-controlled version change -> NOT_KNOWN_AFFECTED` transition is exercised by `tools/verify_lab04.php` and enforced in CI.**
