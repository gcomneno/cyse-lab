<?php
/* SPDX-License-Identifier: MIT */
declare(strict_types=1);

// 1) Genera un nonce forte per QUESTA risposta
$nonce = base64_encode(random_bytes(16));

// 2) Imposta CSP con il nonce
// - 'strict-dynamic' fa sì che gli script con nonce possano caricare altri script sicuri
// - manteniamo anche fallback 'self' per vecchi browser
header("Content-Security-Policy: default-src 'self'; script-src 'nonce-{$nonce}' 'strict-dynamic' 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'");

// 3) Dati (user input)
$q = $_GET['q'] ?? '';

?>
<!doctype html><meta charset="utf-8">

<h2>Search</h2>
<p>Results for: <?=htmlspecialchars($q, ENT_QUOTES, 'UTF-8')?></p>

<form method="get" action="search.php">
  <input name="q" placeholder="term">
  <button>Go</button>
</form>

<!-- 4) Script consentito grazie al nonce -->
<script nonce="<?= htmlspecialchars($nonce, ENT_QUOTES, 'UTF-8') ?>">
  // Esempio: no event inline nel markup; usa JS per il wiring
  document.querySelector('form').addEventListener('submit', e => {
    // demo innocua
  });
</script>
