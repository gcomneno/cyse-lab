# Reconnaissance Source Selection and Correlation

## Status

Candidate CYSE Lab learning contract.

## Core principle

> Select and correlate reconnaissance sources according to the investigative objective, evaluating authority, freshness, coverage, provenance, and the limits of the evidence.

CYSE Lab must not teach reconnaissance as a flat list of tools. The learner starts from an investigative question, identifies the evidence class required, selects appropriate source families, correlates independent observations, and records what can and cannot be concluded.

```text
investigative objective
  -> required evidence class
  -> source family selection
  -> authority / freshness / coverage review
  -> authorized query
  -> cross-source correlation
  -> provenance + uncertainty
  -> bounded conclusion
```

## Discovery provenance

This candidate was prompted by an Instagram carousel published by HexSec Community / `hexsecteam`:

- https://www.instagram.com/p/DcF_ljTCtwy/?igsi=b3N3c3FrendxanY1

The carousel is a **discovery source only**. It is not an authority and its list must not be treated as a verified catalogue.

Canonical distinction:

```text
discovery source != authority
listed service != trusted evidence
publicly indexed data != authorization
single observation != verified conclusion
```

## Learning outcomes

A learner should be able to:

1. formulate the reconnaissance question before choosing tools;
2. identify which evidence class could answer the question;
3. choose one or more appropriate source families;
4. distinguish primary/official sources from aggregators, community services and convenience interfaces;
5. assess freshness, historical depth, indexing scope and blind spots;
6. correlate independent sources rather than trusting one result;
7. preserve provenance: source, query, observation time, returned evidence and interpretation;
8. separate observation from inference;
9. state uncertainty and explicit non-conclusions;
10. operate only on authorized targets and within legal, privacy and terms-of-service boundaries.

## Source families

The catalogue should be normalized by function rather than by popularity:

- general web search and advanced operators;
- internet-exposed asset and service discovery;
- domain, DNS and certificate transparency;
- vulnerability intelligence and CVE/security-advisory lookup;
- source-code and technology reconnaissance;
- wireless/network mapping;
- people, email and public-record discovery;
- breach/data-exposure discovery;
- malware, exploit and threat-intelligence research;
- reverse-image and geolocation;
- Tor/onion discovery and broader research indexes.

A service may belong to more than one family when this is explicitly justified.

## Candidate catalogue captured from the carousel

The following links are recorded exactly as candidate sources observed in the discovery material. Inclusion is **not** an endorsement, safety determination, authority classification, or guarantee that the service is active or correctly described. Every entry must be independently verified before it becomes maintained lab material.

### 01–10 — Infrastructure / exposure / vulnerabilities

1. Google — https://google.com
2. Shodan — https://shodan.io
3. Censys — https://censys.io
4. ZoomEye — https://zoomeye.org
5. GreyNoise — https://greynoise.io
6. FOFA — https://fofa.info
7. ONYPHE — https://onyphe.io
8. NIST NVD — https://nvd.nist.gov
9. OSV — https://osv.dev
10. VulnIQ — https://vulniq.com

### 11–20 — Vulnerabilities / certificates / domains / DNS

11. VulDB — https://vuldb.com
12. 0day.today — https://0day.today
13. OpenCVE — https://opencve.io
14. crt.sh — https://crt.sh
15. Hunter — https://hunter.io
16. Searchcode — https://searchcode.com
17. BuiltWith — https://builtwith.com
18. Robtex — https://robtex.com
19. MITRE resource as shown in the carousel — https://goaway.mitre.org
20. DNSDB — https://dnsdb.io

### 21–30 — DNS / wireless / people / data exposure

21. DNSViz — https://dnsviz.net
22. WiGLE — https://wigle.net
23. WiFiMap — https://wifimap.io
24. WiFiSPC — https://wifispc.com
25. Skymem — https://skymem.info
26. ThatsThem — https://thatsthem.com
27. Snusbase — https://snusbase.com
28. DeHashed — https://dehashed.com
29. LOLBAS — https://lolbas-project.github.io
30. FullHunt — https://fullhunt.io

### 31–40 — Code / URLs / attack surface

31. grep.app — https://grep.app
32. urlscan.io — https://urlscan.io
33. ProjectDiscovery Chaos — https://chaos.projectdiscovery.io
34. C99 — https://c99.nl
35. WiGLE — https://wigle.net
36. SynapsInt — https://synapsint.com
37. OmniSint — https://omnisint.io
38. Riddler — https://riddler.io
39. NerdyData — https://nerdydata.com
40. OSV — https://osv.dev

### 41–50 — Threat intel / malware / exposure / reverse search

41. Insecam — https://insecam.org
42. Triage — https://tria.ge
43. LeakIX — https://leakix.net
44. FileSec — https://filesec.io
45. MalAPI — https://malapi.io
46. SpyDialer — https://spydialer.com
47. Tellows — https://tellows.com
48. Rapid7 DB — https://rapid7.com/db
49. Exploit Database — https://exploit-db.com
50. TinEye — https://tineye.com

### 51–60 — Deeper / specialized discovery

51. Mylnikov — https://mylnikov.org
52. Ahmia — https://ahmia.fi
53. Tor.link — https://tor.link
54. ORKL — https://orkl.org
55. BuiltWith — https://builtwith.com
56. Netlas — https://netlas.io
57. Recon.dev — https://recon.dev
58. Vulmon — https://vulmon.com
59. SpyDialer — https://spydialer.com
60. Bing — https://bing.com

## Catalogue normalization requirements

Before promotion into maintained lab material:

- verify that each service still exists and matches the claimed function;
- record duplicates explicitly rather than pretending the list contains 60 unique sources;
- correct transcription or naming errors only with independent evidence;
- classify each service by source family;
- record whether it is primary/authoritative, aggregator, commercial service, community service or general search interface;
- record account/API/subscription requirements when relevant;
- record documented freshness and historical-depth semantics where available;
- record important coverage limitations;
- document privacy, legal, authorization and ToS concerns;
- exclude or quarantine services that are unsafe, legally problematic, defunct, non-reproducible or inappropriate for a public educational lab.

## Evidence model

Every lab observation should distinguish:

### FACT / OBSERVATION
What the source actually returned at a recorded time.

### INTERPRETATION
What the learner believes the observation suggests.

### CORROBORATION
Which independent source or sources support or contradict that interpretation.

### LIMITATION
What cannot be concluded from the available evidence.

The existence of a CVE, exposed service, DNS record, certificate, indexed source-code hit or public-data entry must not automatically establish exploitability, ownership, identity, compromise or malicious intent.

## Source evaluation dimensions

At minimum, compare:

- **authority** — primary/official vs secondary/aggregated;
- **freshness** — update cadence and observation age;
- **coverage** — which population or evidence class is indexed;
- **historical depth** — current state vs available history;
- **provenance quality** — whether returned evidence identifies origin/time;
- **reproducibility** — whether another learner can repeat the query under comparable conditions;
- **access constraints** — free/account/API/commercial;
- **legal/privacy/ToS sensitivity** — restrictions relevant to the use case.

Do not collapse these dimensions into a single vague trust score without a justified model.

## First controlled lab candidate

Working title: **Goal-driven multi-source reconnaissance**.

Use only an explicitly authorized, low-risk target, such as a domain owned or controlled by the learner/project, a local/demo target, or a public training target whose terms explicitly permit the activity.

Example task:

> Starting from one authorized domain, determine what can responsibly be established about its DNS, certificate history, exposed web technology and publicly indexed vulnerability context using multiple independent source families.

The learner must:

1. write investigative questions first;
2. justify each selected source before querying it;
3. capture timestamped observations;
4. correlate at least two independent sources where possible;
5. identify contradictions and stale observations;
6. produce a short evidence table;
7. finish with conclusions and explicit non-conclusions.

No exploitation is required.

## Safety boundary

CYSE Lab remains white-hat and authorization-first.

This material must not:

- encourage probing arbitrary third-party systems;
- teach credential abuse or unauthorized access;
- treat breach-data availability as permission to access or use personal data;
- turn public indexing into authorization for intrusive testing;
- operationalize exploit data against real non-consenting targets;
- require Tor, breach-search or people-search services for the baseline lab;
- publish sensitive observations about third parties;
- automate broad scanning merely because a source supports it.

Potentially sensitive source categories should remain optional or quarantined until their legal, ethical, privacy and reproducibility boundaries are explicit.

## Promotion criteria

This candidate becomes a maintained CYSE Lab skill/lab only when:

- the catalogue has been independently verified and normalized;
- duplicates and stale/incorrect entries are explicit;
- the source-selection rubric is documented;
- observation, interpretation, corroboration and limitation remain separate;
- the controlled lab uses an authorized target;
- sensitive source categories are bounded appropriately;
- conclusions require provenance and explicit uncertainty.
