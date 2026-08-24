# Lab 03 — Lessons Learned

## What this lab teaches

Lab 03 turns a vague privacy task — “remove metadata from an image” — into a bounded, verifiable claim:

> remove JPEG APP1 segments that are explicitly recognized as EXIF, preserve non-target bytes, and independently verify that recognized EXIF is absent from the produced output.

That narrower claim is stronger than a broad but unverifiable promise of “anonymization”.

## JPEG structure matters

A JPEG is not safely scrubbed by searching raw bytes for strings such as `Exif` and deleting nearby content. JPEG uses marker-based segments with explicit lengths, and compressed scan data has its own byte-stuffing and restart-marker rules.

The implementation therefore walks JPEG structure, validates segment bounds and treats entropy-coded scan bytes separately from ordinary marker segments.

## EXIF is one metadata family, not all metadata

The v1 parser recognizes EXIF carried in APP1 segments beginning with the EXIF identifier. Other metadata may coexist in a JPEG, including XMP, IPTC-like data, ICC profiles, comments or vendor-specific structures.

The scrubber intentionally preserves unknown/non-target metadata instead of destroying bytes it does not understand.

This creates an important security-engineering rule:

> verification must not claim more than the parser can actually establish.

## Recognition and decoding are different

An EXIF APP1 segment can be recognized even when its TIFF payload cannot be fully decoded.

The implementation therefore distinguishes:

- recognition of EXIF at the container/segment level;
- optional bounded decoding of selected TIFF tags.

Failure to decode fields does not make a recognized EXIF segment invisible to the scrubber.

## Non-destructive mutation is part of the security property

The original learner file is never overwritten by the v1 contract. Scrub requires a distinct output path and rejects pre-existing output.

The output is first written to a temporary file, re-parsed and verified. Only a verified output is published to the requested path.

This avoids turning a privacy tool into a data-loss risk.

## Verification must be independent

The scrub operation does not prove success merely because it believes it removed a segment.

The produced bytes are parsed again through the normal inspection boundary. `PASS` requires the independent parser to find zero recognized EXIF APP1 segments.

The learning transition therefore becomes:

```text
inspect original -> recognized EXIF present
scrub original -> distinct output
verify output -> PASS
inspect original again -> recognized EXIF still present
```

The final step verifies both privacy transformation and original-file immutability.

## Pixel data should not be re-encoded unnecessarily

Re-encoding an image would introduce unrelated lossy transformation and make it harder to reason about what the tool actually changed.

The v1 scrubber instead preserves compressed image scan data and non-target JPEG segments byte-for-byte where the JPEG structure allows it.

This keeps the mutation focused on the metadata property under study.

## Offline-first testing reduces risk

All fixtures are synthetic. The test suite does not require real photographs, personal metadata, external services or network access.

The matrix covers positive, negative and malformed cases, including:

- no EXIF;
- one or multiple EXIF APP1 segments;
- recognized device/time/location-like fields;
- non-EXIF APP1 preservation;
- undecodable but recognizable EXIF;
- malformed segment bounds;
- dry-run behavior;
- input/output collision;
- pre-existing output;
- output verification;
- original immutability;
- preservation of compressed scan bytes.

## What PASS does not mean

A successful verification means:

> no EXIF APP1 metadata recognized by the v1 parser remains in the verified JPEG.

It does **not** mean:

- all metadata is absent;
- the image is anonymous;
- people or places are not visible in pixels;
- the filename or surrounding context is safe;
- steganographic content is absent;
- the file has been forensically sanitized.

## Provenance lesson

The project concept came from `CarterPerez-dev/Cybersecurity-Projects`, licensed AGPL-3.0, but CYSE classified the implementation as **ADAPT** with upstream code **REFERENCE ONLY**.

The design and implementation were derived independently from CYSE requirements. This preserves both learning value and provenance clarity.

## Next direction

Once Lab 03 is verified end-to-end, CYSE can move from the **Observe** phase toward a more explicit **Assess** unit, with the Dependency Vulnerability Auditor remaining a strong candidate because it combines local software-engineering evidence with security assessment while preserving a low-impact safety boundary.
