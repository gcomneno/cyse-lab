# Roadmap: Check-list operativa — Ottobre

**Aggiornamento:** Oggi è **20 ottobre 2025** — restano **~2 settimane** alla fine di ottobre. Questa checklist è pronta da copiare/incollare in un repository; è pensata per essere eseguita *subito*, con priorità sulle attività di setup e sugli esercizi pratici rimasti.

---

## Struttura repo (consigliata)
```
lab-ready/
├─ README.md
├─ tools/
│  └─ enumerate.sh
├─ burp/
│  └─ burp-project.json
├─ reports/
│  └─ 20251020_<lab>.md
└─ snapshots/
   └─ lab-ready-october-complete.txt  (note sullo snapshot)
```

---

## Obiettivo residuo per le 2 settimane (20 → 31 ottobre)
- **Obiettivo minimo realizzabile ora:** completare i lab PortSwigger (2) e TryHackMe (1-2), produrre 2 write-up puliti, e avere VM snapshot `lab-ready-october-complete`.
- **Tempo stimato disponibile (tu):** 25–30h/w — concentrati su attività pratiche e write-up.

---

## Checklist operativa (giorno per giorno — copia/incolla)

### Giorno 1 (oggi)
- [ ] Avvia VM `lab-ready`. Verifica snapshot `lab-ready` esistente.
- [ ] Aggiorna sistema:
  ```bash
  sudo apt update && sudo apt upgrade -y
  ```
- [ ] Verifica installazioni fondamentali:
  ```bash
  which nmap sqlmap gobuster ffuf wireshark tcpdump python3 git
  ```
- [ ] Scarica e avvia Burp Suite Community; configura Firefox + FoxyProxy (proxy 127.0.0.1:8080).
- [ ] Crea/aggiorna repo:
  ```bash
  git init
  git add README.md
  git commit -m "init lab-ready - 2025-10-20"
  ```
- [ ] Commit 1: aggiungi `tools/enumerate.sh` (base), vedi snippet sotto.

---

### Giorno 2
- [ ] TryHackMe: completa 1 room "Linux Fundamentals" o "Complete Beginner" (se non l'hai già fatto).
- [ ] Esegui `enumerate.sh` su VM e salva output in `tools/outputs/enum_$(date +%Y%m%d).txt`.
- [ ] Inizia PortSwigger: lab **SQL injection — login bypass**.
- [ ] Scrivi primo mini-writeup `reports/20251020_sqlinj-login.md` (vedi template minimo sotto).

---

### Giorno 3
- [ ] PortSwigger: completa lab **retrieve hidden data (SQLi)**.
- [ ] Crea una Burp macro utile e salva esportazione (burp/macros.txt).
- [ ] Commit changes: scripts + primo writeup.

---

### Giorno 4
- [ ] Lab pratico con nmap: esegui scansione su host lab (o VM target).
  ```bash
  nmap -sC -sV -oA scans/scan-basic <target>
  nmap -p- -T4 -oN scans/full-ports.txt <target>
  ```
- [ ] Analizza risultati e aggiungi note in `reports/20251023_enum.md`.
- [ ] Se trovi endpoint web, fai dirbusting con gobuster/ffuf e salva output.

---

### Giorno 5
- [ ] Porta a termine un box TryHackMe/HTB (facile → medio) che combini web + enum.
- [ ] Scrivi secondo writeup `reports/20251024_boxX.md` (1 pagina).
- [ ] Crea snapshot VM `lab-ready-mid-october`.

---

### Giorno 6 (weekend / sessione lunga)
- [ ] Consolidamento: pulisci i report, formatta in markdown e genera PDF (opzionale).
- [ ] Rivedi Burp project, salva preferenze, esporta macros.
- [ ] Controlla che `tools/enumerate.sh` sia idempotente e committalo.

---

### Giorno 7
- [ ] Finalizza il repo: `README.md` con indice e instructions.
- [ ] Snapshot finale: `lab-ready-october-complete`.
- [ ] Push su GitHub (repo privato o pubblico a piacere).

---

## Snippet utile: `tools/enumerate.sh`
Salva questo script in `tools/enumerate.sh` e rendilo eseguibile (`chmod +x tools/enumerate.sh`).
```bash
#!/usr/bin/env bash
set -euo pipefail
outdir="tools/outputs"
mkdir -p "$outdir"
ts=$(date +%Y%m%d_%H%M%S)
echo "=== ENUM START $ts ===" > "$outdir/enum_${ts}.txt"
echo "HOSTNAME:" >> "$outdir/enum_${ts}.txt"
hostname >> "$outdir/enum_${ts}.txt" 2>&1
echo -e "\nUNAME:" >> "$outdir/enum_${ts}.txt"
uname -a >> "$outdir/enum_${ts}.txt" 2>&1
echo -e "\nIP ADDRESSES:" >> "$outdir/enum_${ts}.txt"
ip a >> "$outdir/enum_${ts}.txt" 2>&1
echo -e "\nSS:" >> "$outdir/enum_${ts}.txt"
ss -tunelp >> "$outdir/enum_${ts}.txt" 2>&1
echo -e "\nDF:" >> "$outdir/enum_${ts}.txt"
df -h >> "$outdir/enum_${ts}.txt" 2>&1
echo -e "\nWHOAMI / ID:" >> "$outdir/enum_${ts}.txt"
whoami >> "$outdir/enum_${ts}.txt" 2>&1
echo "=== ENUM END $ts ===" >> "$outdir/enum_${ts}.txt"
echo "Saved -> $outdir/enum_${ts}.txt"
```

---

## Template minimo di write-up (salva in `reports/` come .md)
```
# Titolo: <lab-name> — <data>
**Host / Room:** <nome>
**Tempo impiegato:** <hh:mm>
**Tools:** nmap, gobuster, burp, sqlmap, etc.

## 1) Scope/Obiettivo
Breve.

## 2) Panoramica tecnica
Comandi principali usati.

## 3) Steps
1. Enumerazione: comandi e output principali.
2. Exploit/PoC: payload / request.
3. Risultato e privilegio ottenuto.

## 4) Impatto
Low/Medium/High

## 5) Mitigazione raccomandata
Bulleted.

```

---

## Suggerimenti rapidi (per chi non vuole perdersi)
- Lavora per **slot**: 2–3 ore intense + 15–30 min di break.  
- Se sei bloccato >3h su un lab, cerca hint; annota sempre dove ti sei bloccato.  
- Commit spesso: `git add . && git commit -m "progress: <cosa>"`.
- Backup snapshot prima di tentare exploit distruttivi.

---

## Note legali e comportamentali
- Testa solo su lab o host **con chiara autorizzazione**.  
- Non pubblicare PoC che può essere abusato su servizi in produzione senza autorizzazione.

---
