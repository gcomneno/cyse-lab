# Lab 03 — Metadata Privacy Scrubber

## Status

**Canonical design specification — implementation not started.**

This document resolves the design work tracked by issue #12. Implementation requires a separate issue and must preserve the contracts defined here.

## Provenance and decision

External concept source:

- repository: `CarterPerez-dev/Cybersecurity-Projects`;
- upstream license: AGPL-3.0;
- CYSE decision: **ADAPT**;
- upstream implementation code: **REFERENCE ONLY**;
- upstream implementation inspected for this design: **no**.

The problem is adapted as a CYSE learning objective. Architecture, terminology, CLI, result model, tests and implementation requirements are independently defined here.

## Learning objective

Learn how common image files can disclose privacy-relevant embedded metadata, how to remove a deliberately bounded set of that metadata without modifying the source file, and how to verify the exact property that CYSE claims to have changed.

The learner must be able to explain the distinction between:

1. metadata recognized by this tool;
2. metadata successfully removed by this tool;
3. other metadata or identifying content the tool does not understand;
4. anonymity, which this lab does **not** claim to provide.

## Prerequisites

- basic file-system and CLI use;
- binary-file safety: never treat an output as valid merely because a command succeeded;
- basic structured-data concepts;
- CYSE evidence loop: observe -> change -> verify;
- ability to work only with learner-owned or synthetic fixtures.

Lab 02 is recommended because it introduces deterministic findings and verification, but it is not a semantic prerequisite for image metadata handling.

## v1 scope decision

### Supported format

**JPEG only.**

Rationale:

- JPEG provides a focused, recognizable privacy problem through EXIF metadata;
- a single format keeps parsing, mutation and verification explainable;
- adding PNG, PDF, Office documents, audio/video or arbitrary containers would create materially different metadata models and mutation risks;
- breadth is deliberately deferred until the JPEG contract is proven.

### Recognized metadata family

v1 recognizes **EXIF application metadata in JPEG APP1 segments whose payload is explicitly identified as EXIF**.

The scrub operation removes recognized EXIF APP1 segments from the output JPEG.

v1 does **not** claim to remove every JPEG application segment or every possible metadata representation. In particular, XMP, IPTC, ICC profiles, comments, thumbnails outside the recognized EXIF structure, steganographic content, pixel-visible identifiers and unknown vendor data are outside the v1 removal claim unless later added explicitly.

This narrow claim is intentional: verification must never exceed parser knowledge.

## Threat model

The lab addresses accidental disclosure caused by recognized embedded EXIF metadata in a learner-owned JPEG, including fields that may describe device, software, capture time, author-like information or location when present.

The lab does not defend against:

- identifying visual content in pixels;
- face/place recognition;
- file names or surrounding directory/context information;
- network/service logs;
- fingerprints derived from encoding characteristics;
- unrecognized metadata families;
- malicious polyglot/steganographic content;
- adversaries who possess the original file.

Therefore `verified absent` always means **recognized EXIF absent according to the v1 parser**, never `anonymous` or `safe to publish`.

## Safety boundary

- inputs and fixtures must be learner-owned or synthetic;
- core operation is fully offline and performs no network access;
- fixtures must not contain real personal data;
- the original input is immutable under normal v1 commands;
- no recursive directory traversal;
- no automatic discovery of user photos;
- no hidden upload, telemetry or external metadata lookup;
- malformed or unsupported files fail closed rather than being rewritten optimistically.

## Core semantic model

Lab 03 has three explicit operations:

`inspect -> scrub -> verify`

### Inspect

Read a JPEG without modifying it and report recognized EXIF evidence.

Inspect answers only:

> Does the v1 parser recognize EXIF metadata in this JPEG, and what bounded evidence can it report?

### Scrub

Create a **new output file** by removing recognized EXIF APP1 segments while preserving the remaining JPEG byte structure as defined by the implementation contract.

Scrub must never overwrite the input path in v1.

### Verify

Independently parse an output JPEG and establish whether recognized EXIF APP1 metadata remains.

Verify is not satisfied by trusting the scrub operation's return value. It must re-read the produced file through the inspection/parser boundary.

## Non-destructive mutation contract

The v1 command requires distinct input and output paths.

Rules:

1. input must exist and be a supported regular JPEG file;
2. output path must differ from input after path normalization;
3. existing output must not be overwritten unless an explicit future contract adds such behavior; v1 fails instead;
4. write to a temporary file in the output directory;
5. validate the temporary result as a structurally supported JPEG;
6. re-inspect it and verify recognized EXIF absence;
7. only then atomically publish/rename the temporary file to the requested output path where the platform permits;
8. on failure, remove the temporary artifact and leave the original untouched.

No `--in-place` option exists in v1.

## Dry-run contract

`--dry-run` is valid for `scrub`.

It performs all read-only validation and reports what recognized metadata would be removed, but:

- creates no output file;
- creates no persistent temporary artifact;
- reports `mutation_performed: false`;
- cannot claim post-mutation verification.

## Evidence and result model

Human and JSON output must be projections of the same semantic result.

Minimum structured fields:

```text
schema_version
tool_version
operation
input_path
output_path|null
format
recognized_metadata
recognized_segment_count
metadata_present
mutation_performed
verification
warnings
limitations
```

### `recognized_metadata`

A bounded list of evidence records. Each record should contain at least:

```text
family        = EXIF
category      = location | device | capture-time | software | descriptive | other
field         = normalized field name when decoded
value         = safely rendered value or null
source        = parser/segment evidence
```

Sensitive values may be shown for synthetic/learner-owned fixtures, but the design must make it possible to suppress values in future workflows. Tests use synthetic values only.

### `verification`

For `verify` and completed `scrub`:

```text
status = PASS | FAIL | UNKNOWN
claim  = recognized-exif-absent
recognized_segment_count
reason
```

Meaning:

- `PASS`: the output is parseable under the v1 JPEG contract and no recognized EXIF APP1 segment remains;
- `FAIL`: recognized EXIF remains;
- `UNKNOWN`: the parser cannot establish the bounded claim because the file is malformed, unsupported or ambiguous.

`PASS` must never be worded as anonymity or complete metadata removal.

## CLI contract

Canonical executable name is left to implementation packaging, but command semantics are fixed:

```text
cyse-metadata inspect <INPUT> [--json]
cyse-metadata scrub <INPUT> --output <OUTPUT> [--dry-run] [--json]
cyse-metadata verify <INPUT> [--json]
```

### Inspect exit codes

- `0` — supported JPEG inspected successfully, regardless of whether recognized EXIF exists;
- `2` — invalid CLI/input contract;
- `3` — read/parser/unsupported-file failure.

### Scrub exit codes

- `0` — output safely produced and post-write verification is PASS; for dry-run, validation completed successfully;
- `1` — mutation completed far enough to evaluate but required recognized-EXIF-absent verification failed;
- `2` — invalid CLI/path contract;
- `3` — read/write/parser/unsupported-file failure.

### Verify exit codes

- `0` — verification PASS;
- `1` — verification FAIL because recognized EXIF remains;
- `2` — invalid CLI/input contract;
- `3` — verification UNKNOWN because the bounded claim cannot be established.

## JPEG parser/mutation boundary

Implementation must not search raw bytes for arbitrary strings such as `Exif` and delete matching regions.

It must understand enough JPEG marker structure to:

- validate JPEG framing required by the v1 contract;
- walk segments safely with explicit length bounds;
- identify APP1 segments;
- distinguish EXIF APP1 payloads from other APP1 payloads;
- reject truncated/impossible segment lengths;
- preserve unrecognized/non-target segments byte-for-byte where feasible;
- preserve compressed image scan data rather than decoding/re-encoding pixels.

Avoiding image re-encoding is a v1 design goal because the learning objective is metadata mutation, not lossy pixel transformation.

## Handling malformed and unusual input

Fail closed for:

- non-JPEG input;
- truncated JPEG structures required for safe traversal;
- impossible/out-of-bounds segment lengths;
- unreadable files;
- input/output path collision;
- pre-existing output;
- output verification that cannot establish the bounded claim.

Multiple recognized EXIF APP1 segments are permitted as input evidence and all must be removed for verification PASS.

An EXIF segment whose TIFF payload cannot be fully decoded may still be recognized at the EXIF-family level. The implementation must distinguish `recognized EXIF segment` from `decoded EXIF fields`; inability to decode fields must not cause the scrubber to silently retain a recognized EXIF segment.

## Batch behavior

**Out of scope for v1.**

No directory traversal, glob expansion inside the tool, recursive operation or concurrent mutation. One explicit input and, for scrub, one explicit output per invocation.

This keeps evidence attributable and prevents accidental mass mutation.

## Deterministic offline test matrix

All fixtures must be synthetic and generated or stored without personal data.

Required cases:

1. valid JPEG with no APP1 -> inspect reports no recognized EXIF;
2. valid JPEG with one synthetic EXIF APP1 -> inspect reports metadata present;
3. valid JPEG with synthetic GPS/device/time-like EXIF fields -> bounded categories are reported;
4. valid JPEG with EXIF plus non-EXIF APP1 -> scrub removes EXIF and preserves non-EXIF APP1;
5. valid JPEG with multiple EXIF APP1 segments -> scrub removes all recognized EXIF segments;
6. scrubbed output -> independent verify PASS;
7. unsanitized EXIF fixture -> verify FAIL;
8. dry-run -> reports intended removal and creates no output;
9. input == output -> rejected;
10. existing output -> rejected;
11. non-JPEG -> rejected;
12. truncated/invalid segment length -> fail closed;
13. recognized EXIF with undecodable TIFF fields -> segment remains recognizable/removable and warning is explicit;
14. output image payload/non-target segments -> preservation test demonstrates no pixel-data re-encoding by the scrub operation.

Tests must run offline in CI.

## Required learning transition

Implementation is not complete until learner-owned/synthetic evidence demonstrates:

```text
inspect source
    -> recognized EXIF present
scrub source -> distinct output
    -> mutation succeeds
verify output
    -> PASS: recognized EXIF absent
inspect original again
    -> recognized EXIF still present
```

The last step proves the non-destructive contract as well as the privacy transformation.

## Limitations that must remain visible

Every human-readable report and JSON result must make the relevant bounded claim clear. Documentation must state prominently:

- v1 supports JPEG only;
- v1 targets recognized EXIF APP1 metadata only;
- `PASS` does not mean all metadata is absent;
- `PASS` does not mean the image is anonymous;
- visible pixels may reveal identity/location;
- file name and external context are not scrubbed;
- unknown metadata is preserved rather than destroyed blindly.

## Explicit non-goals for v1

- PNG/PDF/Office/audio/video support;
- arbitrary metadata deletion;
- image anonymization or face redaction;
- steganography detection/removal;
- pixel re-encoding;
- cloud/API metadata services;
- recursive/batch processing;
- in-place overwrite;
- secure deletion of originals;
- claiming forensic sanitization.

## Implementation independence requirements

The implementation issue must record:

- this specification as the design authority;
- external source and AGPL-3.0 license;
- CYSE decision `ADAPT`;
- upstream implementation code remained `REFERENCE ONLY` during design;
- whether upstream code was subsequently inspected, and why, before any implementation comparison;
- any reused code separately, with explicit license review (default: none).

## Definition of Done for Lab 03

Lab 03 is complete only when:

1. this design has been reviewed and merged;
2. implementation is tracked separately;
3. parser/mutation tests cover the required offline matrix;
4. CI is green;
5. original-file immutability is tested;
6. the controlled metadata-present -> scrub -> verified-absent transition is captured as evidence;
7. the original is re-inspected to prove it remained unchanged;
8. limitations and false-confidence boundaries are documented in user-facing output/docs;
9. a Lessons Learned artifact explains JPEG segments, EXIF privacy risk, safe mutation, verification and limitations;
10. repository progress/navigation is updated to mark the unit complete and identify the next prerequisite.

## Recommended next step after design

Open a dedicated implementation issue for the JPEG-only v1. Do not broaden format support during implementation unless the design issue is explicitly revisited.
