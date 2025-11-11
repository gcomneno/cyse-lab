<?php
/* SPDX-License-Identifier: MIT */
declare(strict_types=1);                                  // ✔ Type checking più rigoroso

/**
 * db(): crea una connessione PDO sicura a SQLite
 * - ERRMODE_EXCEPTION: al primo errore lancia eccezione (niente stati silenziosi)
 * - EMULATE_PREPARES=false: prepared nativi (evita “caso #7”)
 */
function db(): PDO {
  $dsn = 'sqlite:' . __DIR__ . '/data/lab.db';           // ✔ Percorso DB relativo alla directory del file
  $opt = [
    PDO::ATTR_ERRMODE          => PDO::ERRMODE_EXCEPTION,
    PDO::ATTR_EMULATE_PREPARES => false,                 // ✔ Niente emulazione dei prepared
  ];
  return new PDO($dsn, null, null, $opt);
}

/**
 * valid_username(): validazione “forte” dell’username
 * - accetta solo [A-Za-z0-9_] da 3 a 32 caratteri
 * - aiuta a prevenire second-order SQLi (#6) e schifezze varie
 */
function valid_username(string $u): bool {
  return (bool)preg_match('/^[A-Za-z0-9_]{3,32}$/', $u);
}

try {
  if ($_SERVER['REQUEST_METHOD'] === 'POST') {          // ✔ Processa solo POST (come un vero form)
    // ✔ Recupera input utente (se non presenti, stringa vuota)
    $u = $_POST['username'] ?? '';
    $p = $_POST['password'] ?? '';

    // ✔ Validazione input:
    //   - username deve rispettare il pattern
    //   - password non può essere vuota
    //   (Niente identificatori dinamici, niente ORDER BY da input → no #1/#2)
    if (!valid_username($u) || $p === '') {
      http_response_code(400);                           // ✔ Bad Request per input non valido
      echo "Login failed";                               // ✔ Messaggio neutro (no info leakage)
      exit;
    }

    $pdo = db();                                         // ✔ Ottieni connessione sicura

    // ✔ Query parametrizzata: UNA sola query (no multiple statements → no #5)
    //   Se il driver supporta solo parametri per i valori (sì), qui siamo al sicuro (no concatenazioni → no #3)
    $stmt = $pdo->prepare('SELECT id, username, password FROM users WHERE username = :u');
    $stmt->execute([':u' => $u]);                        // ✔ Bind sicuro del parametro

    $row = $stmt->fetch(PDO::FETCH_ASSOC);               // ✔ Array associativo o false

    // ✔ Verifica password con l’hash salvato (mai confronto in chiaro)
    if ($row && password_verify($p, $row['password'])) {
      // (Opzionale) session_start(); session_regenerate_id(true); // 🔒 contro fixation
      echo "<h1>Welcome, " . htmlspecialchars($row['username'], ENT_QUOTES, 'UTF-8') . "</h1>";
      // htmlspecialchars: evita XSS se l’username contiene caratteri speciali
    } else {
      echo "Login failed";                               // ✔ Messaggio unico (no user enumeration)
    }
    exit;                                                // ✔ Fine del ramo POST
  }

} catch (Throwable $e) {
  // ✔ Error handling sobrio: niente dettagli all’utente; in produzione log server-side
  http_response_code(500);
  echo "Server error";
  exit;
}
?>
<!doctype html>
<meta charset="utf-8">
<h2>Login</h2>
<!-- ✔ Semplice form: niente autocomplete (opzionale), required su campi -->
<form method="post" action="login.php" autocomplete="off">
  <input name="username" placeholder="user" required>
  <input name="password" placeholder="pass" type="password" required>
  <button>Login</button>
</form>
