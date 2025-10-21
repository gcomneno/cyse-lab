# Lessons Learned — Apache Discovery & Hardening (Local VM)
**Data:** 2025-10-21  
**Autore:** Giancarlo (work-in-progress notes)

> Scopo: fornire una guida pratica, ripetibile e didattica per riprodurre la ricognizione e l'hardening che abbiamo fatto sulla VM Ubuntu con Apache. Comandi, motivazioni, varianti e caveat. Tutto testato su una VM di laboratorio.

---

## Indice
1. Recon & scansione
2. Enumerazione web (directory discovery)
3. Rilevazione header e banner
4. Analisi automatica (Nikto)
5. Pulizia spazio disco (se serve)
6. Scaricare wordlist (se serve)
7. Hardening applicato (comandi, perché, varianti)
8. Verifiche post-hardening
9. Troubleshooting e note pratiche
10. Wordlists e risorse consigliate
11. Nikto – sintesi risultati & azioni consigliate
12. Note legali e comportamento etico
13. Ultime raccomandazioni pratiche

---

## 1) Recon & scansione

### Comando principale (usato)
\```bash
nmap -sC -sV -p 1-1000 127.0.0.1 -oA scans/scan_basic_local
\```

### Cosa fa
- `-sC` esegue script "default" (banner/version, alcuni checks).
- `-sV` identifica versione servizio.
- `-p 1-1000` limita alla porzione di porte più comune (più veloce).
- `-oA` salva output in diversi formati (nmap, .gnmap, .xml).

### Perché
Serve a raccogliere la mappa dei servizi attivi (es. SSH, HTTP) e la loro versione. Da qui capisci cosa esplorare (web, SMB, database...).

### Variante/estensioni
- `-p-` (tutte le porte) se vuoi essere esaustivo.
- `-A` (più aggressivo: OS detection, script extra, traceroute).
- `--script vuln` per testare vulnerabilità note (usare con cautela).

---

## 2) Enumerazione web (directory discovery)

### Strumento principale: gobuster
Comando usato (esempio):
\```bash
/usr/bin/gobuster -m dir -u http://127.0.0.1/ \
  -w /home/ba_alti_imo_ora_a/progetti/cyse-lab/tools/wordlists/Discovery/Web-Content/common.txt \
  -o scans/gobuster_127.0.0.1.txt -t 10 -r -e
\```

### Cosa fa
Prova percorsi presenti nella wordlist e segna quelli non restituenti 404. Trova file e directory "nascosti" o non linkati.

### Perché
Molti admin lasciano directory di admin, backup, o endpoint che non compaiono nella navigazione normale. Trovarli è utile per ricognizione.

### Problemi frequenti & risoluzione
- `WordList (-w): Must be specified` → spesso percorso errato o file mancante. Usa percorsi assoluti con `$(pwd)` per evitare ambiguità.
- Se `gobuster` non è nel PATH: `which gobuster` mostra il percorso; in caso di assenza, `sudo apt install gobuster`.

### Fallback con curl (se gobuster non funziona)
\```bash
head -n 500 wordlists/Discovery/Web-Content/common.txt | while read -r p; do
  url="http://127.0.0.1/${p}"
  code=$(curl -o /dev/null -s -w "%{http_code}" "$url")
  if [ "$code" != "404" ]; then
    echo "$p (HTTP $code)"
  fi
done | tee scans/gobuster_like_results.txt
\```

- Più lento, ma sempre funzionante. Utile su server locali.

---

## 3) Rilevazione header e banner

### Comando usato
\```bash
curl -I http://127.0.0.1/ | grep -E "X-|ETag"
\```

### Cosa cercare
- `Server:` e versione (banner).
- Header di sicurezza: `X-Frame-Options`, `X-Content-Type-Options`, `Strict-Transport-Security` (se HTTPS).
- `ETag:` che può leakare inode/version file.

### Perché
I header dicono subito quanto il server "parla" e quali best-practice mancano. Sono la base per raccomandazioni di hardening.

---

## 4) Analisi automatica (Nikto)

### Comando eseguito
\```bash
nikto -host http://127.0.0.1 -output scans/nikto_127.0.0.1.txt
\```

### Cosa fa
Esegue un set di test web "storici": header mancanti, file comuni, metodi HTTP consentiti, CGI note.

### Interpretazione
Nikto fa buone “punte” per ricognizione ma produce anche falsi positivi! usa i suoi risultati soltanto come input per investigazione manuale.

---

## 5) Pulizia spazio disco (se serve - le nostre azioni)
Se il clone di SecLists fallisce per spazio, usa questi comandi per liberare spazio senza toccare dati utente:

\```bash
sudo apt clean
sudo apt autoremove -y
sudo journalctl --vacuum-time=3d
sudo rm -rf /var/tmp/* /tmp/*
\```

Se ci sono snap che non usi (es. `docker`, `lxd`) rimuovili:

\```bash
sudo snap remove docker
sudo snap remove lxd
\```

Verifica lo spazio con:
\```bash
df -h
sudo du -h / --max-depth=1 2>/dev/null | sort -hr | head -n 15
\```

---

## 6) Scaricare wordlist "common.txt" (come l'abbiamo fatto) e altre wordlists pratiche

### Scarica solo la wordlist utile (rapida)
\```bash
mkdir -p ~/progetti/cyse-lab/wordlists/Discovery/Web-Content
wget -q -O ~/progetti/cyse-lab/wordlists/Discovery/Web-Content/common.txt \
  https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt
\```
Conferma:
\```bash
ls -lh ~/progetti/cyse-lab/wordlists/Discovery/Web-Content/common.txt
wc -l ~/progetti/cyse-lab/wordlists/Discovery/Web-Content/common.txt
\```

### Perché
SecLists intero è grande (~500MB) e non sempre serve. `common.txt` è leggera e spesso sufficiente per directory discovery iniziale.

### Altre liste irrinunciabili (SecLists paths)
- `Discovery/Web-Content/raft-large-directories.txt` — più completa (più lenta).
- `Discovery/Web-Content/raft-small-words.txt` — media.
- `Fuzzing/burp-parameter-names.txt` — utile per fuzz dei parametri.
- `Discovery/DNS/subdomains-top1million-5000.txt` — per enumerazione DNS/subdomain.
- `Passwords/Leaked-Databases/` — per test di credenziali (usare solo in lab).

### Come scaricare SecLists completo (se hai spazio)
\```bash
git clone https://github.com/danielmiessler/SecLists.git ~/wordlists/SecLists
\```

---

## 7) Hardening applicato — comandi, perché e varianti

### 7.1 Limitare o disabilitare `/server-status`
**Opzione A: disabilitare (semplice)**  
\```bash
sudo a2dismod status
sudo systemctl reload apache2
\```
- **Pro:** rimuove completamente l'handler.
- **Contro:** se usi `mod_status` per monitoring locale perdi l'accesso.

**Opzione B: limitare a IP/localhost (consigliata in produzione)**  
\```bash
sudo cp /etc/apache2/mods-available/status.conf /etc/apache2/mods-available/status.conf.bak
cat <<'EOF' | sudo tee /etc/apache2/mods-available/status.conf >/dev/null
<IfModule mod_status.c>
    ExtendedStatus On
    <Location /server-status>
        SetHandler server-status
        Require ip 127.0.0.1
        # oppure: Require ip 10.0.2.0/24
    </Location>
</IfModule>
EOF
sudo systemctl reload apache2
\```
- **Pro:** conservi il monitoring ma lo limiti a management network.
- **Note:** `Require local` permette accesso da localhost; utile per troubleshooting ma non per ambienti esposti.

### 7.2 Aggiungere header di sicurezza e disattivare ETag
Edita il VirtualHost (es. `/etc/apache2/sites-enabled/000-default.conf`) e aggiungi:
\```apache
ServerName 127.0.0.1
Header always set X-Frame-Options "SAMEORIGIN"
Header always set X-Content-Type-Options "nosniff"
FileETag None
\```
Abilita headers:
\```bash
sudo a2enmod headers
sudo systemctl reload apache2
\```
- **Perché:** evita clickjacking, MIME sniffing e leak di ETag.  
- **Varianti:** `Strict-Transport-Security` se hai HTTPS.

### 7.3 Impostare ServerName globale (rimuovere warning)
\```bash
echo 'ServerName 127.0.0.1' | sudo tee /etc/apache2/conf-available/servername.conf >/dev/null
sudo a2enconf servername
sudo systemctl reload apache2
\```
- Rimuove il warning `Could not reliably determine the server's fully qualified domain name`.

---

## 8) Verifiche post-hardening (comandi + cosa aspettarsi)

### Header di sicurezza
\```bash
curl -I http://127.0.0.1/ | grep -E "X-|ETag"
\```
**Atteso:**
\```
X-Frame-Options: SAMEORIGIN
X-Content-Type-Options: nosniff
# Nessuna riga ETag se FileETag None è applicato
\```

### /server-status
- Se `mod_status` disabilitato: `curl -I http://127.0.0.1/server-status` → **404/Not Found**.
- If limited to IP: responds 200 from localhost; 403 from external IPs.

### ServerName warning
\```bash
sudo apache2ctl -S | sed -n '1,20p'
\```
**Atteso:** nessun messaggio “Could not reliably determine...”.

---

## 9) Troubleshooting & note pratiche

### Gobuster "WordList must be specified"
- Controlla che il file esista (`ls -l path`).
- Usa percorso assoluto `$(pwd)/...`.
- Verifica la versione di gobuster (`gobuster -h`).

### Scarica SecLists fallisce per spazio
- Scarica solo `common.txt`.
- Pulizia: `sudo apt clean`, `sudo snap remove docker`, `sudo journalctl --vacuum-time=3d`.

### Nikto warnings
- Nikto segnala best-practice non applicate ma anche falsi positivi; investigare manualmente.

### Commit dei risultati
\```bash
git init
git add scans/ reports/
git commit -m "Recon & hardening scans 2025-10-21"
\```

---

## 10) Wordlists e risorse consigliate (ulteriori dettagli)
- **SecLists** (GitHub): https://github.com/danielmiessler/SecLists  
  - `Discovery/Web-Content/common.txt` → lightweight, primo step.
  - `Discovery/Web-Content/raft-large-directories.txt` → più completa per test approfonditi.
  - `Fuzzing/burp-parameter-names.txt` → utile per scansione parametri.
- **Burp Suite Academy** (PortSwigger) per lab web: https://portswigger.net/web-security
- **TryHackMe** — rooms per Linux e Web fundamentals.
- **Wordlists extra**: `SVNDorks`, `common-login-usernames`, `raft-small-words`, `apache-usernames`.

---

## 11) Nikto – sintesi risultati & azioni consigliate

**Output analizzato (estratto):**
- `Uncommon header 'x-frame-options': SAMEORIGIN`
- `Uncommon header 'x-content-type-options': nosniff`
- `Allowed HTTP Methods: GET, POST, OPTIONS, HEAD`

### Cosa significa (in breve)
- **X-Frame-Options: SAMEORIGIN** → *bene*: riduce il rischio di clickjacking.
- **X-Content-Type-Options: nosniff** → *bene*: blocca MIME sniffing del browser.
- **Metodi permessi: GET, POST, OPTIONS, HEAD** → *ok*: sono comuni. `OPTIONS` serve spesso per CORS/preflight. Il problema sarebbe vedere metodi come `PUT`, `DELETE`, `TRACE`, `CONNECT`, `PROPFIND`, ecc.

### Cosa fare (azione pratica)
1. **Mantieni gli header** già presenti (sono best practice).
2. **Verifica che TRACE sia disabilitato**:
   ```bash
   curl -s -I -X TRACE http://127.0.0.1/ | head -n 1
   # Atteso: HTTP/1.1 405 Method Not Allowed  (o 501 Not Implemented)

Se non è così, in Apache imposta:
# /etc/apache2/conf-available/security.conf (o conf equivalente)
TraceEnable off

e poi:
sudo a2enconf security 2>/dev/null || true
sudo systemctl reload apache2

Non rimuovere a cuor leggero OPTIONS: molte app/API lo usano per CORS.
Se il sito è puramente statico e vuoi essere restrittivo, limita i metodi a GET/POST/HEAD:

<Directory "/var/www/html">
    <LimitExcept GET POST HEAD>
        Require all denied
    </LimitExcept>
</Directory>

# Nota: questo può rompere preflight CORS; applicalo solo se sai che non serve.

Test rapidi post-hardening
# Header di sicurezza (devono comparire)
curl -I http://127.0.0.1/ | grep -iE 'x-frame|x-content-type|etag'

# TRACE disabilitato
curl -s -I -X TRACE http://127.0.0.1/ | head -n 1

# Metodi ancora consentiti (osserva Allow:)
curl -i -X OPTIONS http://127.0.0.1/ | sed -n '1,15p'

Le tre righe di Nikto non indicano vulnerabilità, ma buone pratiche già presenti e un set di metodi accettabile.
Controlla solo che TRACE sia off; lascia OPTIONS se ti serve il CORS; opzionalmente restringi i metodi nei contesti statici.

---

## 12) Note legali e comportamento etico
- Esegui test **solo** su host di cui hai il permesso (lab/VM/host autorizzati).  
- Non pubblicare PoC che possono essere usati per attaccare terzi senza autorizzazione.  
- Conserva backup e snapshot prima di cambi strutturali.

---

## 13) Ultime raccomandazioni pratiche
- Documenta ogni comando che esegui (come hai fatto: outputs in `scans/`).  
- Usa snapshot VM prima di provare exploit o modifiche invasive: `poweroff` VM → snapshot/restore.  
- Mantieni un README che spieghi come riprodurre l’ambiente (versioni, pacchetti installati).

---