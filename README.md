# cyse-lab

Laboratorio **white-hat** evidence-driven per imparare cybersecurity costruendo, verificando e spiegando sistemi in ambienti controllati.

## Principi

- **Etica**: solo sistemi posseduti o esplicitamente autorizzati.
- **Ripetibilità**: stessi passi e stessi input devono produrre evidence verificabile.
- **Sobrietà**: meno magia da tool, più comprensione dei meccanismi.
- **Tracciabilità**: ogni finding, decisione e mitigazione deve avere un perché.
- **Indipendenza**: le fonti esterne forniscono problemi e reference; CYSE costruisce la propria conoscenza.

## Stato attuale

Il repository contiene più evidence di quanto mostrasse il vecchio README. Oltre al recon web iniziale, sono già documentati:

- recon ed enumerazione web;
- Apache hardening;
- logging di rete/firewall;
- SQL injection: exploit controllato e fix;
- prepared statements e password hashing;
- reflected XSS ed escaping contestuale;
- Content Security Policy;
- networking isolato Kali/Ubuntu.

Lo stato canonico è ricostruito in [`docs/progress.md`](docs/progress.md).

## Learning architecture

La progressione CYSE è organizzata nelle fasi:

1. Observe
2. Assess
3. Protect
4. Test security properties
5. Detect & correlate
6. Advanced controlled adversarial labs

Dettagli, Definition of Done ed evidence model: [`docs/architecture.md`](docs/architecture.md).

## External sources

Le fonti esterne sono trattate tramite decisioni esplicite `ADOPT / ADAPT / REFERENCE ONLY / REJECT` e regole di provenance/clean-room adaptation.

Policy e registro iniziale: [`docs/external-sources.md`](docs/external-sources.md).

## Next lab

Il primo nuovo candidato è:

**Lab 02 — HTTP Security Headers Auditor**

Stato: **design only**. L'implementazione non è ancora iniziata.

La scelta deriva dalla conoscenza HTTP/CSP già presente nel repository e dal basso impatto operativo di un auditor passivo degli header.

## Safety

CYSE privilegia ambienti locali, fixture, PCAP offline, VM isolate e sistemi autorizzati. Scanner attivi, applicazioni intenzionalmente vulnerabili e simulazioni avversariali richiedono safety boundary espliciti.

## Repository rules

Le regole operative specifiche del repository sono in [`AGENTS.md`](AGENTS.md).

## License

MIT. Le fonti esterne possono avere licenze differenti; la loro presenza come reference non implica che il relativo codice possa essere copiato o incorporato nel repository.
