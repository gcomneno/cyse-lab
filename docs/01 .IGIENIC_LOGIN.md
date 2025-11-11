# Tabella: quando i prepared **non bastano** e come si rimedia

| # | Perché i prepared non bastano                                                                                         | Esempio rischio (pseudo-codice)                                       | Mitigazione corretta                                                                                                   |        |
| - | --------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------- | ------ |
| 1 | **Identificatori dinamici** (nomi di colonne/tabelle, ORDER BY) non sono parametrizzabili                             | `ORDER BY $col` con `$col` da input                                   | **Allow-list** di valori ammessi; *mai* concatenare identificatori dall’utente.                                        |        |
| 2 | **Clausole speciali** (LIMIT, OFFSET, direzione ASC/DESC) spesso non accettano placeholder                            | `LIMIT $n` con `$n` da input                                          | **Cast/validazione forte** (`(int)$n`) e allow-list per `ASC                                                           | DESC`. |
| 3 | **Concatenazione prima del prepare**: se componi pezzi di SQL con input e *poi* fai `prepare`, sei già fregato        | `$where = "WHERE role='$r'"; $db->prepare("SELECT * FROM u $where")`  | Componi la query **solo** con segnaposto; costruisci la logica (branching) in PHP, non in SQL.                         |        |
| 4 | **Stored procedure** che usano SQL dinamico interno                                                                   | `EXEC('SELECT ... '+ @userInput)`                                     | Dentro la SP usare **parametrizzazione vera** (p.es. `sp_executesql`) o evitare SQL dinamico.                          |        |
| 5 | **Query multiple** nella stessa chiamata (stacked statements)                                                         | `user='x'; DROP TABLE users;--`                                       | Disabilita le query multiple a livello driver/connessione; esegui **una** query per volta.                             |        |
| 6 | **Second-order SQLi**: input malevolo salvato oggi, iniettato domani quando lo riusi in una query concatenata altrove | Salvi `username="a' OR '1'='1"` e più tardi lo concateni in un report | **Valida/normalizza all’ingresso** + **parametrizza ad ogni riuso**; evita di concatenare dati “persistiti”.           |        |
| 7 | **Prepared “emulati” dal driver** (es. PDO emulation) → escaping fragile                                              | PDO con `ATTR_EMULATE_PREPARES = true`                                | **Disattiva emulazione** → usa prepared **nativi**; per MySQL imposta anche `charset=utf8mb4` e blocca query multiple. |        |

---

## Mini-checklist “igiene” per il login

* **Input**: validazione forte (username) e lunghezze ragionevoli (#6).
* **Query**: solo placeholder; nessuna concatenazione (#3).
* **Niente identificatori dinamici** (ORDER BY/colonne) nel login (#1).
* **Una query per volta**, multi-statements disabilitati (#5).
* **Prepared nativi**, emulazione off (#7).
* **Password hashate** + `password_verify` (mai in chiaro).
* **Errori neutri** all’utente, log lato server.
* **Utente DB** con privilegi minimi (quando non sei su SQLite).

---

## Dove metterli e come usarli

* **Nel repo**: `docs/code/setup_db_explained.php` e `docs/code/login_explained.php` (materiale didattico).
* **Per il lab**: i file “operativi” restano in `/var/www/html/`:
  * `/var/www/html/setup_db.php`
  * `/var/www/html/login.php`

* **Test (da Kali)**:
  ```bash
  curl -s http://192.168.56.102/setup_db.php               # "DB ready"
  curl -s -X POST http://192.168.56.102/login.php \
    --data-urlencode "username=alice" \
    --data-urlencode "password=wonderland"                 # Welcome, alice
  curl -s -X POST http://192.168.56.102/login.php \
    --data-urlencode "username=' OR 1=1-- " \
    --data-urlencode "password=x"                          # Login failed (fix ok)
  ```

---
