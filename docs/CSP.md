# Content Security Policy (CSP) — Guida pratica

## Perché
La CSP riduce fortemente l’impatto di XSS: limita **da dove** possono essere caricati script/richieste e **come** possono essere eseguiti. **Non sostituisce** l’escaping: è difesa-in-profondità.

---

## Opzione A — CSP server-wide (Apache)

**Quando usarla:** vuoi una base sicura per **tutto** il sito, e poi — se serve — fare eccezioni per singole pagine lato applicazione.

1) Abilita mod_headers
```bash
sudo a2enmod headers
````

2. Crea **/etc/apache2/conf-available/csp.conf**

```apache
<IfModule mod_headers.c>
  # Base policy per tutto il sito
  # setifempty: applica solo se l'app non ha già inviato una CSP
  Header always setifempty Content-Security-Policy "default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'"
</IfModule>
```

3. Abilita e ricarica

```bash
sudo a2enconf csp
sudo systemctl reload apache2
```

4. Verifica

```bash
curl -I http://HOST/ | grep -i '^Content-Security-Policy:'
```

**Note**

* Evita **duplicati**: più CSP si **intersecano** (risk di bloccare troppo).
* Se vuoi testare senza bloccare: usa `Content-Security-Policy-Report-Only` (solo segnalazioni in console).

---

## Opzione B — CSP **con nonce** (per-pagina, lato PHP)

**Quando usarla:** pagina dinamica che ha bisogno di uno (o pochi) script inline controllati. Generi un **nonce casuale** per richiesta e lo usi sia nell’header che nel tag `<script>`.

Esempio minimale:

```php
<?php
declare(strict_types=1);
$nonce = base64_encode(random_bytes(16));
header("Content-Security-Policy: default-src 'self'; script-src 'nonce-{$nonce}' 'strict-dynamic' 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'");
?>
<!doctype html><meta charset="utf-8">
<script nonce="<?= htmlspecialchars($nonce, ENT_QUOTES, 'UTF-8') ?>">
  // JS autorizzato da questo nonce
</script>
```

**Regole pratiche**

* **Niente** `onclick=`/`onload=` nel markup: collega eventi con JS.
* Evita `javascript:` negli `href` (whitelist schemi `http/https` o URL relativi).
* Genera il nonce **per ogni richiesta**, non statico.

---

## Differenze rapide

| Scelta                   | Pro                                                              | Contro                                                    |
| ------------------------ | ---------------------------------------------------------------- | --------------------------------------------------------- |
| Server-wide `'self'`     | Semplice, copertura totale, zero inline                          | Blocca inline; JS esterni solo dal tuo host               |
| Per-pagina con **nonce** | Permette inline controllati e catene sicure (`'strict-dynamic'`) | Va implementata in app; serve generare/propagare il nonce |

---

## Pitfall comuni

* `header()` **prima** di ogni output, o errore “headers already sent”.
* Framework/JS che richiedono inline: usa nonce o sposta in file esterni.
* Terze parti (CDN): servono host espliciti in `script-src` o hashing/nonce.

---

## Test rapidi

* Header presente:

  ```bash
  curl -I http://HOST/page | grep -i '^Content-Security-Policy:'
  ```
* Browser console (F12): vedi eventuali violazioni CSP.

---

## CSP + Escaping (perché entrambi)

* **Escaping** (es. `htmlspecialchars`) impedisce l’iniezione in **quell’output specifico**.
* **CSP** limita i modi in cui **script** possono essere eseguiti, anche se un escape viene dimenticato altrove.

Suggerimento: metti una CSP **base** in Apache e usa CSP **con nonce** solo sulle pagine che la richiedono.

````

---

# `LESSONS_LEARNED_2025-10-23.md`

```md
# Lessons Learned — Lab White-Hat
**Data:** 23 ottobre 2025  
**Setup:** Ubuntu (difensore) 192.168.56.102 ↔ Kali (attaccante) 192.168.56.103 su rete Host-Only

---

## 0) Rete di Lab: NAT vs Host-Only (e nomi interfacce)
- **NAT** (10.0.2.0/24): accesso Internet per ogni VM, IP identici tra VM possibili (es. 10.0.2.15 su entrambe).
- **Host-Only** (es. 192.168.56.0/24): rete isolata tra host + VM (o solo VM con “Internal Network”).
- Naming interfacce: `enp0s3` (prima NIC), `enp0s8` (seconda NIC), `eth1` su Kali.

**Comandi utili**
```bash
ip -br addr      # interfacce/IP rapidi
ip route         # rotte; default via NAT (10.0.2.2)
````

**Assegnazioni usate**

* Ubuntu: `enp0s8 = 192.168.56.102/24`
* Kali:   `eth1  = 192.168.56.103/24`

---

## 1) Logging di rete (vedere chi bussa: ICMP + TCP:80)

**Perché:** ping (ICMP) e SYN su 80 **non** appaiono nei log di Apache; servono log a livello kernel/firewall.

**Log ICMP (ping) — con rate-limit**

```bash
# log
sudo iptables -I INPUT -i enp0s8 -p icmp --icmp-type echo-request \
  -m limit --limit 10/min --limit-burst 20 \
  -j LOG --log-prefix "ICMP_ECHO_REQ " --log-level 4
# allow
sudo iptables -I INPUT -i enp0s8 -p icmp --icmp-type echo-request -j ACCEPT
# vedere i log
sudo journalctl -k -f | grep ICMP_ECHO_REQ
```

**Log nuove connessioni HTTP**

```bash
sudo iptables -I INPUT -i enp0s8 -p tcp --dport 80 \
  -m conntrack --ctstate NEW \
  -m limit --limit 10/min --limit-burst 20 \
  -j LOG --log-prefix "TCP80_NEW " --log-level 4
```

**Note**

* `-I` = inserisci in cima (si applica prima delle altre).
* Log visibili con `journalctl -k -f` o `dmesg -w`.
* Rimozione: `sudo iptables -L INPUT -n -v --line-numbers` → `sudo iptables -D INPUT N`.

*(Persistenza futura: `iptables-persistent`, non lo abbiamo attivato per restare “leggeri”.)*

---

## 2) Recon HTTP (nmap/gobuster/nikto) e come leggere i log

* **nmap -sC -sV** invia probe HTTP per capire versioni/feature:

  * `GET /`, `OPTIONS /` → metodi.
  * `PROPFIND /` → test WebDAV (405 è **bene**).
  * metodi “finti” (es. `SQRW`) → devono dare `501`.
* **nikto** prova percorsi/payload noti (Adminer, WP, metadata cloud…): tanti `404`/`400`/`405` = **bene**.
* **gobuster** enumera directory/URL con wordlist.

**Comandi**

```bash
nmap -sC -sV -p 1-1000 192.168.56.102 -oA scans/nmap_basic
WORDLIST="/usr/share/seclists/Discovery/Web-Content/common.txt"
gobuster dir -u http://192.168.56.102/ -w "$WORDLIST" -o scans/gobuster.txt -t 20
nikto -host http://192.168.56.102 -output scans/nikto.txt
```

**SecLists**

* Kali: `sudo apt install -y seclists` → `/usr/share/seclists/.../common.txt`
* Se non presente, scarica versione singola: `wget -O ~/common.txt <URL>`

---

## 3) `sed` & `curl` (micro-cheat)

* `sed -n '1,10p'` → stampa **solo** righe 1..10.
* `sed '/^$/q'` → stampa fino alla prima riga **vuota** (header HTTP).
* `head -n 40` è equivalente per “prime N righe”.
* `curl -I URL` → **solo header**; `-i` → header + body; `--data-urlencode` → codifica sicura per POST.

Esempi:

```bash
curl -I http://HOST/ | sed -n '1,10p'
curl -s -i http://HOST/ | sed '/^$/q'
```

---

## 4) Hardening Apache (mirato)

* **/server-status** → solo localhost:

  ```apache
  <Location /server-status>
    SetHandler server-status
    Require ip 127.0.0.1
  </Location>
  ```

  Reload: `sudo systemctl reload apache2`

* **Limitare esposizione**: (opzionale) bind solo a host-only

  ```
  # /etc/apache2/ports.conf
  Listen 192.168.56.102:80
  ```

* **UFW** (se attivo): consenti solo su `enp0s8` e porte necessarie.

* **Header**: X-Frame-Options / X-Content-Type-Options (già visti), CSP vedi §7.

---

## 5) SQL Injection — exploit → fix

### 5.1 Micro-lab (SQLite)

* `setup_db.php`: crea DB e utenti demo.
* `login.php` (vulnerabile): concatenava input in SQL.

**Exploit PoC (fallito inizialmente)**

* `username=' OR '1'='1` → fallisce perché `AND password='x'` rimane attivo.

**Exploit PoC (valido)**

* `username=' OR 1=1-- ` *(nota lo spazio dopo `--` in SQLite)* → commenta il resto:

```bash
curl -s -X POST http://HOST/login.php \
  --data-urlencode "username=' OR 1=1-- " \
  --data-urlencode "password=qualcosa"
# → Welcome, carlos
```

### 5.2 Fix (a regola d’arte)

* **Prepared statements nativi** (no emulazione driver):

  ```php
  new PDO('sqlite:.../lab.db', null, null, [
    PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
    PDO::ATTR_EMULATE_PREPARES => false
  ]);
  $stmt = $db->prepare('SELECT id, username FROM users WHERE username = :u AND password = :p');
  $stmt->execute([':u'=>$u, ':p'=>$p]);
  ```

* **Password hashate** + `password_verify()`:

  ```php
  $hash = password_hash('wonderland', PASSWORD_DEFAULT);
  if ($row && password_verify($p, $row['password'])) { ... }
  ```

* **Input validation** (riduce second-order SQLi):

  ```php
  preg_match('/^[A-Za-z0-9_]{3,32}$/', $username)
  ```

* **Blocca multi-statement** (quando usi MySQL):

  ```php
  PDO::MYSQL_ATTR_MULTI_STATEMENTS => false
  ```

---

## 6) XSS riflesso — exploit → fix

### 6.1 Vulnerabilità

```php
# search.php (vuln)
$q = $_GET['q'] ?? '';
<p>Results for: <?=$q?></p>
```

* Iniettare: `?q=<script>alert(1)</script>` → esecuzione nel browser.

### 6.2 Fix (escaping) + difesa-in-profondità (CSP)

* **Escaping HTML corretto:**

  ```php
  <?= htmlspecialchars($q, ENT_QUOTES, 'UTF-8') ?>
  ```
* **CSP base (Apache server-wide):**

  ```
  default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'
  ```
* **CSP con nonce (pagina dinamica):**

  ```php
  $nonce = base64_encode(random_bytes(16));
  header("Content-Security-Policy: ... script-src 'nonce-{$nonce}' 'strict-dynamic' 'self' ...");
  <script nonce="<?= htmlspecialchars($nonce, ENT_QUOTES, 'UTF-8') ?>">...</script>
  ```

**Perché serve entrambi:** CSP riduce il danno se qualcuno dimentica l’escape, ma senza escape restano rischi (HTML injection, DOM XSS, UI abuse).

---

## 7) Escaping per contesto (cheat rapido)

| Contesto       | Usa                                                     | Esempio                                                        |               |               |                             |
| -------------- | ------------------------------------------------------- | -------------------------------------------------------------- | ------------- | ------------- | --------------------------- |
| HTML testo     | `htmlspecialchars(s, ENT_QUOTES, 'UTF-8')`              | `<?= htmlspecialchars($q, ENT_QUOTES, 'UTF-8') ?>`             |               |               |                             |
| Attributo HTML | virgolette + `htmlspecialchars`                         | `<a title="<?= htmlspecialchars($t, ENT_QUOTES, 'UTF-8') ?>">` |               |               |                             |
| URL query      | `http_build_query()`                                    | `'/search?'.http_build_query(['q'=>$q])`                       |               |               |                             |
| URL path       | `rawurlencode()` per segmento                           | `"/u/".rawurlencode($user)`                                    |               |               |                             |
| href/src       | **Whitelist schema** (`http/https` o relativo) + escape | vedi funzione `safe_url()`                                     |               |               |                             |
| In JS          | `json_encode(..., JSON_HEX_*)`                          | `<script>const q = <?= json_encode($q, JSON_HEX_TAG            | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_HEX_AMP) ?>;</script>` |
| DOM client     | `textContent` / `setAttribute`                          | **Mai** `innerHTML` con input                                  |               |               |                             |

**Whitelist URL (PHP)**

```php
function safe_url(string $u): ?string {
  $u = trim($u);
  if ($u === '') return null;
  if (preg_match('#^https?://#i', $u)) return $u;
  if ($u[0] === '/') return $u;
  return null;
}
```

---

## 8) Hardening extra “one-liners” utili

* **Disabilita TRACE**

  ```apache
  # /etc/apache2/conf-available/security.conf
  TraceEnable off
  sudo a2enconf security && sudo systemctl reload apache2
  ```
* **Firewall (UFW) host-only minimo**

  ```bash
  sudo ufw default deny incoming
  sudo ufw allow in on enp0s8 to any port 80 proto tcp
  # opzionale: SSH lab
  sudo ufw allow in on enp0s8 to any port 22 proto tcp
  sudo ufw enable
  ```

---
