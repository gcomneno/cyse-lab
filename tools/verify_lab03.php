<?php

declare(strict_types=1);

require __DIR__ . '/../src/cyse_metadata.php';

function beSegment(int $marker, string $payload): string
{
    $length = strlen($payload) + 2;
    return "\xFF" . chr($marker) . chr(($length >> 8) & 0xFF) . chr($length & 0xFF) . $payload;
}

function minimalSyntheticExif(): string
{
    // Little-endian TIFF, magic 42, IFD0 at offset 8, zero entries, no next IFD.
    return "Exif\x00\x00II\x2A\x00\x08\x00\x00\x00\x00\x00\x00\x00\x00\x00";
}

function syntheticVerificationJpeg(): string
{
    return "\xFF\xD8"
        . beSegment(0xE0, "JFIF\x00\x01\x01")
        . beSegment(0xE1, minimalSyntheticExif())
        . beSegment(0xDA, "\x01\x01\x00\x00\x3F\x00")
        . "\x10\x20\xFF\x00\x30"
        . "\xFF\xD9";
}

$root = sys_get_temp_dir() . '/cyse-lab03-evidence-' . bin2hex(random_bytes(5));
if (!mkdir($root, 0700, true) && !is_dir($root)) {
    throw new RuntimeException('cannot create verification directory');
}

$input = $root . '/original.jpg';
$output = $root . '/scrubbed.jpg';

try {
    file_put_contents($input, syntheticVerificationJpeg());
    $originalHashBefore = hash_file('sha256', $input);

    $before = inspectPath($input);
    if ($before['recognized_segment_count'] < 1) {
        throw new RuntimeException('expected recognized EXIF in original');
    }

    $scrub = scrubPath($input, $output, false);
    if (($scrub['verification']['status'] ?? null) !== 'PASS') {
        throw new RuntimeException('scrub verification did not PASS');
    }

    $verified = verifyPath($output);
    if (($verified['verification']['status'] ?? null) !== 'PASS') {
        throw new RuntimeException('independent output verification did not PASS');
    }

    $originalAgain = inspectPath($input);
    if ($originalAgain['recognized_segment_count'] < 1) {
        throw new RuntimeException('original no longer exposes expected EXIF');
    }

    $originalHashAfter = hash_file('sha256', $input);
    if ($originalHashBefore !== $originalHashAfter) {
        throw new RuntimeException('original bytes changed');
    }

    echo "LAB 03 LEARNING TRANSITION\n";
    echo "source: synthetic learner-safe JPEG fixture\n";
    echo "network: none\n";
    echo "original_sha256_before={$originalHashBefore}\n";
    echo "inspect_original_before=EXIF_PRESENT({$before['recognized_segment_count']})\n";
    echo "scrub_output={$scrub['verification']['status']}\n";
    echo "verify_output={$verified['verification']['status']}\n";
    echo "inspect_original_after=EXIF_PRESENT({$originalAgain['recognized_segment_count']})\n";
    echo "original_sha256_after={$originalHashAfter}\n";
    echo "original_immutable=" . ($originalHashBefore === $originalHashAfter ? 'YES' : 'NO') . "\n";
    echo "RESULT=PASS\n";
} finally {
    @unlink($output);
    @unlink($input);
    @rmdir($root);
}
