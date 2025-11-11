# cyse-lab
Laboratorio **white-hat** CLI-first per ricon, enumerazione e hardening. Focus: ripetibilità, write-up corti, risultati spiegabili.

## ⚡ Quickstart (Ubuntu)
```bash
# requisiti minimi
sudo apt update
sudo apt install -y curl dnsutils whois nmap whatweb jq
```

# clona ed esegui il primo lab (recon web)
./src/bin/recon-web.sh example.org --out scans/01-recon
Output: file in scans/01-recon/ e un mini report guidato in reports/01-recon-LL.md.

## 🎯 Principi
**Etica**: solo target autorizzati.
**Ripetibilità**: stessi passi → stessi risultati.
**Sobrietà**: meno “tool”, più comprensione.
**Tracciabilità**: ogni decisione ha un perché.

## 🧪 Labs
Lab 01 — Recon Web essenziale

## 📄 Template Report
reports/templates/lesson-learned.md

## 🔐 Nota legale
Usa questo materiale solo su sistemi autorizzati. Nessuna responsabilità per usi impropri.

— Giadaware, laboratorio semi-serio di un folle lucido 😎
