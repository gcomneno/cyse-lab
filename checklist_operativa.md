## Struttura repo (consigliata, CLI-first)

```
cyse-lab/
├─ README.md
├─ tools/
│  └─ enumerate.sh
├─ wordlists/
│  └─ Discovery/Web-Content/common.txt
├─ scans/
│  ├─ scan_basic_local.*    (nmap)
│  ├─ gobuster_127.0.0.1.txt
│  └─ nikto_*.txt
├─ reports/
│  ├─ lessons_learned_apache.md
│  └─ 20251021_apache_hardening_mini_writeup.md
└─ .git/
```

> Se hai già `tools_enumerate.sh` in root, va bene. In alternativa: spostalo in `tools/enumerate.sh` e aggiorna i comandi.

---

## Obiettivo residuo (21 → 31 ottobre)

* **Minimo realizzabile:**
  2 lab PortSwigger + 1–2 room TryHackMe → **2 write-up** puliti

  * repo con **Lessons Learned** e **mini-writeup hardening**
  * **snapshot finale** `lab-ready-october-complete`.

* **Tempo (realistico):** 20–30h complessive → focus su pratica + documentazione breve.

---

## Checklist operativa (giorno per giorno)

### Giorno 1 — **oggi (21/10)**

* [ ] Allinea repo:

  ```bash
  mkdir -p scans reports wordlists/Discovery/Web-Content tools
  ```
* [ ] Installa/Verifica tool essenziali (CLI-only):

  ```bash
  sudo apt update && sudo apt install -y nmap gobuster nikto curl git
  which nmap gobuster nikto curl git
  ```
* [ ] Wordlist minima (se non presente):

  ```bash
  wget -q -O wordlists/Discovery/Web-Content/common.txt \
    https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt
  ls -lh wordlists/Discovery/Web-Content/common.txt
  ```
* [ ] Esegui ricognizione locale (già fatto, ma formalizza gli output in `scans/`):

  ```bash
  nmap -sC -sV -p 1-1000 -oA scans/scan_basic_local 127.0.0.1
  gobuster dir -u http://127.0.0.1/ -w $(pwd)/wordlists/Discovery/Web-Content/common.txt \
    -o scans/gobuster_127.0.0.1.txt -t 10
  nikto -host http://127.0.0.1 -output scans/nikto_127.0.0.1.txt
  ```
* [ ] Hardening Apache (se non fatto): limitazione/disabilitazione `/server-status`, header, `ServerName`.
  Verifica:

  ```bash
  curl -I http://127.0.0.1/ | grep -iE 'x-frame|x-content-type|etag' || true
  curl -I http://127.0.0.1/server-status
  sudo apache2ctl -S | head -n 3
  ```
* [ ] Aggiungi **Lessons Learned** e mini-writeup hardening a `reports/` (quelli che abbiamo preparato).
* [ ] Commit:

  ```bash
  git init 2>/dev/null || true
  git add README.md tools/ scans/ reports/ wordlists/
  git commit -m "init+recon: scans, wordlist, hardening writeups (2025-10-21)"
  ```

---

### Giorno 2

* [ ] **PortSwigger** (CLI mentalità, niente Burp obbligatorio): lab **SQL injection – login bypass**.

  * Usa `curl` per riprodurre la richiesta e annota payload minimi.
* [ ] **Write-up 1**: `reports/20251022_sqli_login_bypass.md` (1 pagina: obiettivo, comando/payload, evidenza, fix).
* [ ] Snapshot VM: `lab-ready-oct21`.

---

### Giorno 3

* [ ] **PortSwigger**: lab **SQLi – retrieve hidden data** (o XSS riflesso base se preferisci).
* [ ] **Write-up 2**: `reports/20251023_sqli_hidden_data.md` **oppure** `reports/20251023_xss_reflected.md`.
* [ ] Commit:

  ```bash
  git add reports/ && git commit -m "writeups: PortSwigger #1-2"
  ```

---

### Giorno 4

* [ ] Room **TryHackMe** “Linux Fundamentals” **o** “Complete Beginner” (se già fatta, scegline una web).
* [ ] Raccogli comandi `nmap`, `gobuster`, richieste `curl` significative.
* [ ] **Write-up 3 (opzionale)**: `reports/20251024_thm_room.md`.

---

### Giorno 5

* [ ] **Revisione repo**: rinomina file, aggiungi indice in `README.md` (link a scans e reports).
* [ ] Integra sezione “**Nikto – sintesi & azioni**” nel README (quella che ti ho passato).

---

### Giorno 6 (sessione lunga)

* [ ] Consolidamento: formatta i 2 (o 3) write-up; aggiungi **POC con `curl`** minimali.
* [ ] (Opz.) Genera PDF via `pandoc` se lo vuoi condividere.
* [ ] Commit intermedio.

---

### Giorno 7–10 (finestra flessibile)

* [ ] 1 box facile (TryHackMe / HTB) **mix web+enum**, se hai tempo.
* [ ] Snapshot finale: `lab-ready-october-complete`.
* [ ] Push su GitHub:

  ```bash
  git remote add origin <URL>
  git branch -M main
  git push -u origin main
  ```

---

## Snippet utile — `tools/enumerate.sh`  *(se vuoi standardizzare)*

```bash
#!/usr/bin/env bash
set -euo pipefail
outdir="tools/outputs"
mkdir -p "$outdir"
ts=$(date +%Y%m%d_%H%M%S)
f="$outdir/enum_${ts}.txt"
{
  echo "=== ENUM START $ts ==="
  echo -e "HOSTNAME:"; hostname
  echo -e "\nUNAME:"; uname -a
  echo -e "\nIP ADDRESSES:"; ip a
  echo -e "\nSS:"; ss -tunelp
  echo -e "\nDF:"; df -h
  echo -e "\nWHOAMI / ID:"; whoami
  echo "=== ENUM END $ts ==="
} > "$f"
echo "Saved -> $f"
```

---

## Template minimo di write-up (corto, replicabile)

```
# <lab-name> — <data>
**Scope:** <breve>
**Tools:** nmap, gobuster, curl, nikto

## Passi chiave
1) Enum: comandi + evidenze
2) Exploit/PoC: richiesta/payload (curl)
3) Risultato: <accesso / evidenza / flag>
4) Mitigazione: <1-3 bullet>

## Note
- Tempo impiegato: <hh:mm>
- Difficoltà: <bassa/media>
```

---

## Note rapide

* **Niente Burp** se non lo vuoi: usa `curl`, `gobuster`, `nikto`, `nmap`.
* **Wordlists “irrinunciabili”** (se hai spazio):

  * `Discovery/Web-Content/common.txt` (già ok)
  * `Discovery/Web-Content/raft-large-directories.txt` (più profonda)
  * `Fuzzing/burp-parameter-names.txt` (solo per fuzz param: usabile anche senza Burp)
* Controllo metodi:

  ```bash
  curl -i -X OPTIONS http://127.0.0.1/ | sed -n '1,15p'
  curl -s -I -X TRACE  http://127.0.0.1/ | head -n 1   # atteso 405/501
  ```

---
