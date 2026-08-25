# Lab 05 — Offline Network Traffic Analyzer

## Status

**Canonical design specification — implementation not started.**

This document resolves design issue #22. Implementation requires a separate issue and must preserve the contracts defined here.

## Provenance and decision

External concept source:

- repository: `CarterPerez-dev/Cybersecurity-Projects`;
- upstream license: AGPL-3.0;
- CYSE decision: **ADAPT**;
- upstream implementation code: **REFERENCE ONLY**;
- upstream implementation inspected for this design: **no**.

CYSE independently defines the capture boundary, parser, evidence model, aggregation semantics, CLI, tests and safety contract.

## Learning objective

Learn to transform a bounded offline packet capture into reproducible packet and flow evidence without confusing network observations with security verdicts.

The learner must be able to explain:

1. what a packet capture can and cannot prove;
2. practical Ethernet, IPv4/IPv6, TCP and UDP identity;
3. endpoint, port and transport-protocol evidence;
4. directionality versus canonical flow identity;
5. packet/byte aggregation;
6. timestamps and capture ordering;
7. why truncation, encryption and unsupported protocols limit interpretation;
8. why an unusual connection is an observation rather than automatically malicious activity;
9. why absence from one capture does not prove absence of network activity.

## Prerequisites

- basic IP addressing and ports;
- TCP/UDP concepts;
- binary-file safety and bounded parsing;
- CYSE evidence discipline from Labs 02–04;
- ability to work only with synthetic or learner-owned capture data.

Historical CYSE recon/networking evidence is useful preparation but does not substitute for this lab's packet-level verification.

## v1 capture-format decision

**Classic PCAP only. PCAPNG is out of scope for v1.**

Rationale:

- classic PCAP has a deliberately small file/record structure suitable for independent learning;
- supporting PCAPNG correctly requires block types, options, multiple interfaces and per-interface link-layer semantics that would dominate the first implementation;
- a narrow format lets the learner reason directly about file headers, record bounds, timestamps and captured/original lengths;
- PCAPNG can be evaluated later as a format-extension exercise after the semantic evidence model is stable.

### Byte order and timestamp precision

v1 must recognize the standard classic-PCAP magic variants needed to distinguish:

- little-endian vs big-endian captures;
- microsecond vs nanosecond timestamp precision.

Timestamp precision must be preserved in structured evidence rather than silently normalized in a way that claims more precision than the source provides.

## Link-layer decision

**Ethernet (DLT_EN10MB / linktype 1) only for v1.**

A syntactically valid PCAP with another linktype is a recognized-but-unsupported capture and must fail explicitly rather than being decoded as Ethernet.

VLAN-tagged Ethernet may be deferred unless the implementation issue explicitly proves a bounded single-tag parser without broadening the learning objective. The minimum required v1 path is untagged Ethernet II.

## Parser/dependency decision

**Implement the bounded classic-PCAP + required protocol parsing directly in CYSE v1.**

Do not shell out to `tcpdump`, `tshark`, Wireshark or libpcap for canonical parsing.

Rationale:

- the file and protocol subset is intentionally small;
- direct parsing exposes the learning concepts instead of hiding them behind a mature decoder;
- deterministic CI has no native-package dependency;
- byte bounds, endianness, protocol discrimination and evidence preservation become explicit testable behavior.

This is not a claim that hand-written packet parsers are preferable for production analyzers. A Lessons Learned artifact must compare the educational parser with mature libraries/tools and explain when those should be preferred.

## Required protocol boundary

### Required

- Ethernet II;
- IPv4;
- IPv6;
- TCP;
- UDP.

### Optional bounded enrichment

DNS metadata may be added only if implementation remains small and tests prove safe bounds. It is **not required** for Lab 05 completion.

HTTP payload parsing is **out of scope for v1**. Lab 02 already teaches HTTP security properties; Lab 05 focuses on packet/flow evidence rather than application-protocol reconstruction.

### Explicitly unsupported for semantic decoding

Examples include ARP, ICMP/ICMPv6, non-IP Ethernet payloads, IP fragments requiring reassembly, IPv6 extension chains not handled by the bounded parser, encapsulation/tunnels and arbitrary application protocols.

Unsupported packets must remain accounted for; they must not disappear from totals.

## Packet evidence model

Every successfully read PCAP record receives an ordinal packet number and capture evidence.

Minimum packet fields:

```text
packet_number
timestamp
captured_length
original_length
truncated
linktype
network_protocol       = IPv4 | IPv6 | UNSUPPORTED | MALFORMED
transport_protocol     = TCP | UDP | OTHER | UNKNOWN
source_address|null
destination_address|null
source_port|null
destination_port|null
wire_bytes
capture_bytes
parse_status           = PARSED | UNSUPPORTED | MALFORMED
reason|null
```

### Captured versus original length

- `capture_bytes` is the bytes physically present in the capture record;
- `wire_bytes` is the record's original packet length reported by PCAP;
- `truncated` is true when captured length is smaller than original length.

The analyzer must not infer missing bytes from a truncated capture.

## Flow evidence model

A flow is a bounded aggregation over packets for which the required IP + TCP/UDP tuple is safely parseable.

### Canonical flow identity

Flow identity is **bidirectional** and uses:

```text
transport protocol
endpoint A = IP + port
endpoint B = IP + port
```

The two endpoints are canonically ordered by their normalized binary address representation and then port. This makes packets in opposite directions map to the same flow without guessing which side is client/server.

### Direction evidence

The flow retains directional counters relative to canonical endpoints:

```text
A_to_B_packets
A_to_B_capture_bytes
A_to_B_wire_bytes
B_to_A_packets
B_to_A_capture_bytes
B_to_A_wire_bytes
```

It also records:

```text
first_timestamp
last_timestamp
total_packets
total_capture_bytes
total_wire_bytes
truncated_packets
```

The analyzer must not label endpoints `client` or `server` solely from port numbers.

### Packets excluded from flows

Unsupported/malformed packets and packets lacking a safely parseable TCP/UDP endpoint tuple are counted in capture summaries but are not forced into a flow.

## Capture summary

Minimum summary:

```text
total_records
parsed_packets
unsupported_packets
malformed_packets
truncated_packets
flow_count
total_capture_bytes
total_wire_bytes
first_timestamp|null
last_timestamp|null
```

Counts must reconcile with packet records.

## Epistemic boundary

Lab 05 reports observations and bounded derived summaries.

It does **not** classify flows as attacks, malware, exfiltration, command-and-control or vulnerabilities.

Examples:

- destination port 4444 is evidence of a connection to port 4444, not proof of a reverse shell;
- cleartext bytes visible in a packet may support a later security hypothesis but do not by themselves establish exploitability;
- encrypted payload means content is unavailable to this parser, not that the traffic is safe;
- no observed packet for a service means only that the bounded capture did not contain one;
- flow aggregation is evidence compression, not security judgment.

This preserves the wider CYSE chain:

`observation -> interpretation/hypothesis -> evidence -> human review`

## Malformed/truncated behavior

### File-level fatal errors

The entire assessment fails for:

- unreadable file;
- invalid/unsupported PCAP magic;
- unsupported PCAP major version required by v1;
- unsupported linktype;
- truncated global header;
- truncated record header;
- record captured length extending beyond available file bytes;
- unreasonable record length exceeding an explicit implementation safety bound.

### Packet-level malformed evidence

A complete PCAP record whose contained Ethernet/IP/transport structure is too short or internally impossible is retained as a packet record with `parse_status: MALFORMED` and a reason.

This does not make the entire capture unreadable when record framing itself remains trustworthy.

### Truncated packets

A record with `captured_length < original_length` is explicitly marked truncated.

If enough captured bytes exist to establish bounded headers, those observed fields may be reported, but the packet retains `truncated: true`. Missing payload/header evidence must never be invented.

## Fragmentation boundary

v1 performs **no IP fragment reassembly**.

- IPv4 fragmented datagrams are explicitly represented as unsupported for transport-flow decoding unless the packet is unfragmented under the bounded parser rules;
- IPv6 packets requiring unsupported extension-header traversal/reassembly are represented explicitly rather than guessed.

## Encryption boundary

The core parser does not decrypt traffic and does not attempt TLS interception.

Because v1 does not reconstruct arbitrary application payloads, encryption is primarily a documented interpretive limitation: packet endpoints, ports, sizes and timing may remain observable while application content may not.

No credential extraction is a Lab 05 objective.

## Input immutability

The analyzer is strictly read-only.

It must not modify:

- the PCAP file;
- timestamps/metadata of the capture intentionally;
- packet contents;
- network interfaces or system network configuration.

Canonical tests must demonstrate byte-for-byte input immutability across analysis.

## Result model

Human and JSON output must be projections of one semantic result.

Minimum top-level fields:

```text
schema_version
tool_version
input_path
capture_format
byte_order
timestamp_precision
linktype
summary
packets
flows
warnings
limitations
```

Human output may default to summary + flows while JSON contains packet evidence, but filtering/presentation must not alter the underlying semantic counts.

No `SAFE`, `MALICIOUS` or vulnerability verdict field exists in v1.

## CLI contract

Canonical semantics:

```text
cyse-traffic analyze <capture.pcap> [--json] [--packets]
```

- default human mode: capture summary plus flow table and explicit unsupported/malformed/truncated counts;
- `--packets`: additionally render packet-level evidence in human output;
- `--json`: emit the complete structured semantic result.

No interface name, capture duration, BPF filter, live mode or packet-write option exists in v1.

## Exit-code contract

- `0` — PCAP framing is valid/supported and analysis completed, including captures that contain packet-level unsupported or malformed evidence;
- `2` — invalid CLI/input path contract;
- `3` — file-level parsing/unsupported-format/linktype failure.

Exit code `0` means the bounded analyzer completed; it is not a security verdict and does not imply every packet was semantically decoded.

## Resource/safety bounds

Implementation must define deterministic upper bounds appropriate for a learning CLI, including at least maximum accepted captured-record length.

Tests should avoid requiring large captures. The analyzer may process records incrementally rather than loading the complete capture into memory.

Any future aggregate-memory bound or streaming JSON tradeoff must be documented rather than hidden.

## Deterministic offline test matrix

Fixtures must be synthetic and contain no personal data or secrets.

Required cases:

1. little-endian microsecond PCAP with one Ethernet/IPv4/TCP packet -> parsed evidence;
2. big-endian PCAP -> equivalent semantic decode;
3. nanosecond magic -> precision represented correctly;
4. Ethernet/IPv4/UDP packet -> parsed evidence;
5. Ethernet/IPv6/TCP packet -> parsed evidence;
6. two opposite-direction TCP packets -> one bidirectional flow with correct directional counters;
7. multiple flows -> deterministic canonical ordering/identity;
8. production-like port numbers do not create client/server or malicious labels;
9. unsupported Ethernet protocol -> packet counted as `UNSUPPORTED`, not dropped;
10. unsupported IP transport -> packet accounted for outside TCP/UDP flow aggregation;
11. complete record with malformed short Ethernet/IP/TCP/UDP structure -> packet `MALFORMED`;
12. truncated-on-wire packet (`captured < original`) -> explicit truncated evidence;
13. truncated PCAP global header -> fatal;
14. truncated record header -> fatal;
15. record length exceeds remaining file -> fatal;
16. unreasonable captured-record length -> rejected by safety bound;
17. unsupported linktype -> explicit fatal unsupported result;
18. non-PCAP input -> rejected;
19. IPv4 fragmentation requiring reassembly -> explicit unsupported flow decode;
20. IPv6 unsupported extension/reassembly case -> explicit limitation/evidence;
21. empty valid capture -> zero packets/flows with no `safe` claim;
22. capture input SHA-256 unchanged before/after analysis;
23. human and JSON summary/flow counts agree;
24. total record accounting reconciles parsed + unsupported + malformed categories.

All CI tests run without network access or packet-capture privileges.

## Controlled learning evidence

Implementation is not complete until a synthetic capture demonstrates a manually predictable conversation.

Minimum canonical fixture:

```text
packet 1: 192.0.2.10:40000 -> 198.51.100.20:443 TCP
packet 2: 198.51.100.20:443 -> 192.0.2.10:40000 TCP
packet 3: 192.0.2.10:53000 -> 192.0.2.53:53 UDP
```

Before running the analyzer, the learner records the expected:

- packet count;
- endpoint tuples;
- protocol counts;
- bidirectional TCP flow identity;
- directional packet counters;
- second UDP flow.

Then:

`predict manually -> analyze -> compare structured evidence -> verify counts/flows -> record limitations`

The evidence must show that the tool reproduced the learner-understood packet/flow facts. The tool output itself is not sufficient evidence of understanding.

## Limitations that must remain visible

User-facing documentation/output must state as applicable:

- v1 supports classic PCAP only;
- v1 supports Ethernet linktype only;
- protocol decoding is intentionally bounded;
- no IP reassembly;
- no TCP stream reconstruction;
- no HTTP/application reconstruction;
- no decryption;
- unsupported packets remain counted but may lack endpoint/flow detail;
- truncated captures can omit evidence;
- a capture represents only traffic actually captured during its bounded interval/location;
- absence from the capture is not proof of absence from the network;
- flows/ports are observations, not vulnerability or maliciousness verdicts.

## Explicit non-goals for v1

- live capture;
- promiscuous-mode management;
- BPF capture filters;
- packet injection/replay;
- ARP spoofing/MITM;
- credential harvesting;
- PCAPNG;
- Wi-Fi/radiotap parsing;
- fragment reassembly;
- TCP stream reassembly;
- TLS interception/decryption;
- IDS signatures;
- malware/C2 classification;
- vulnerability scoring;
- GeoIP/reputation APIs;
- network access of any kind.

## Implementation independence requirements

The implementation issue must record:

- this specification as design authority;
- external concept source and AGPL-3.0 license;
- CYSE decision `ADAPT`;
- upstream implementation remained `REFERENCE ONLY` during design;
- whether upstream implementation is later inspected and why before comparison;
- any third-party parsing dependency separately, although canonical v1 currently specifies direct bounded parsing.

## Definition of Done for Lab 05

Lab 05 is complete only when:

1. this design has been reviewed and merged;
2. implementation is tracked separately;
3. bounded PCAP/Ethernet/IP/TCP/UDP parser tests cover the required offline matrix;
4. CI runs without network/capture privileges and is green;
5. capture immutability is demonstrated;
6. packet/flow accounting reconciles deterministically;
7. controlled manual prediction -> analyzer -> verification evidence is committed;
8. unsupported/malformed/truncated evidence remains visible;
9. user-facing limitations prevent traffic observations becoming security verdicts;
10. a Lessons Learned artifact explains PCAP framing, link/network/transport boundaries, flow aggregation, truncation, encryption limits and production-parser tradeoffs;
11. repository progress/navigation is updated and the next prerequisite is selected.

## Recommended next step after design

Open a separate implementation issue for the classic-PCAP/Ethernet/IPv4+IPv6/TCP+UDP offline v1. Do not add live capture during that implementation.