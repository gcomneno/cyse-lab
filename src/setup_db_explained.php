<?php
declare(strict_types=1);                        // ✔ Attiva type checking più rigoroso in PHP

try {
  // ✔ Crea un oggetto PDO verso un DB SQLite salvato in /var/www/html/data/lab.db
  //   __DIR__ è la directory corrente (quella del file PHP); concateniamo /data/lab.db
  $pdo = new PDO('sqlite:' . __DIR__ . '/data/lab.db', null, null, [
    PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,    // ✔ Eccezioni su errori DB (più semplice da gestire)
    PDO::ATTR_EMULATE_PREPARES => false,            // ✔ Prepared nativi (non emulati) — vedi “caso #7”
  ]);

  // ✔ Pulisci eventuali residui del lab precedente
  $pdo->exec('DROP TABLE IF EXISTS users');         // ⚠ In un’app reale NON faresti DROP così “alla leggera”

  // ✔ Crea la tabella utenti con vincoli minimi sensati
  //   - id: chiave primaria
  //   - username: univoco
  //   - password: stringa NON nulla (conterrà l’hash)
  $pdo->exec('CREATE TABLE users(
                id INTEGER PRIMARY KEY,
                username TEXT UNIQUE,
                password TEXT NOT NULL
              )');

  // ✔ Prepara un inserimento parametrizzato (mai concatenare dati)
  $ins = $pdo->prepare('INSERT INTO users(username, password) VALUES(?, ?)');

  // ✔ Calcola gli hash delle password (bcrypt/argon a scelta di PHP con PASSWORD_DEFAULT)
  //   Mai salvare password in chiaro
  $hCarlos = password_hash('letmein',    PASSWORD_DEFAULT);
  $hAlice  = password_hash('wonderland', PASSWORD_DEFAULT);

  // ✔ Inserisci due utenti di test
  $ins->execute(['carlos', $hCarlos]);
  $ins->execute(['alice',  $hAlice]);

  echo "DB ready\n";                                 // ✔ Feedback minimale per il lab

} catch (Throwable $e) {
  // ✔ Niente stack trace all’utente: in un’app reale loggheresti server-side
  http_response_code(500);
  echo "DB error";
}
