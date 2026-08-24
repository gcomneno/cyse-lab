<?php

declare(strict_types=1);

const CYSE_METADATA_VERSION = '1.0.0';
const CYSE_METADATA_SCHEMA = '1';

final class JpegParseException extends RuntimeException {}

function u16be(string $data, int $offset): int
{
    if ($offset < 0 || $offset + 2 > strlen($data)) {
        throw new JpegParseException('truncated 16-bit value');
    }
    return (ord($data[$offset]) << 8) | ord($data[$offset + 1]);
}

function tiffU16(string $data, int $offset, bool $little): int
{
    if ($offset < 0 || $offset + 2 > strlen($data)) {
        throw new JpegParseException('truncated TIFF uint16');
    }
    $a = ord($data[$offset]);
    $b = ord($data[$offset + 1]);
    return $little ? ($a | ($b << 8)) : (($a << 8) | $b);
}

function tiffU32(string $data, int $offset, bool $little): int
{
    if ($offset < 0 || $offset + 4 > strlen($data)) {
        throw new JpegParseException('truncated TIFF uint32');
    }
    $b0 = ord($data[$offset]);
    $b1 = ord($data[$offset + 1]);
    $b2 = ord($data[$offset + 2]);
    $b3 = ord($data[$offset + 3]);
    if ($little) {
        return $b0 | ($b1 << 8) | ($b2 << 16) | ($b3 << 24);
    }
    return ($b0 << 24) | ($b1 << 16) | ($b2 << 8) | $b3;
}

function isStandaloneMarker(int $marker): bool
{
    return $marker === 0x01 || ($marker >= 0xD0 && $marker <= 0xD9);
}

/**
 * Parse a JPEG into exact byte-preserving tokens.
 * Segment tokens include marker + length + payload bytes.
 * Entropy tokens contain scan bytes until the next real marker.
 */
function parseJpeg(string $bytes): array
{
    $n = strlen($bytes);
    if ($n < 4 || substr($bytes, 0, 2) !== "\xFF\xD8") {
        throw new JpegParseException('not a supported JPEG: missing SOI');
    }

    $tokens = [[
        'kind' => 'standalone',
        'marker' => 0xD8,
        'raw' => "\xFF\xD8",
        'payload' => '',
    ]];

    $pos = 2;
    $inScan = false;
    $sawEoi = false;

    while ($pos < $n) {
        if ($inScan) {
            $start = $pos;
            while ($pos < $n) {
                if (ord($bytes[$pos]) !== 0xFF) {
                    $pos++;
                    continue;
                }

                $ffStart = $pos;
                $pos++;
                if ($pos >= $n) {
                    throw new JpegParseException('truncated scan marker');
                }

                while ($pos < $n && ord($bytes[$pos]) === 0xFF) {
                    $pos++;
                }
                if ($pos >= $n) {
                    throw new JpegParseException('truncated scan fill bytes');
                }

                $code = ord($bytes[$pos]);
                if ($code === 0x00 || ($code >= 0xD0 && $code <= 0xD7)) {
                    $pos++;
                    continue;
                }

                if ($ffStart > $start) {
                    $tokens[] = [
                        'kind' => 'entropy',
                        'marker' => null,
                        'raw' => substr($bytes, $start, $ffStart - $start),
                        'payload' => '',
                    ];
                }
                $pos = $ffStart;
                $inScan = false;
                break;
            }

            if ($inScan) {
                if ($pos > $start) {
                    $tokens[] = [
                        'kind' => 'entropy',
                        'marker' => null,
                        'raw' => substr($bytes, $start, $pos - $start),
                        'payload' => '',
                    ];
                }
                break;
            }
            continue;
        }

        if (ord($bytes[$pos]) !== 0xFF) {
            throw new JpegParseException('unexpected byte outside JPEG scan data');
        }

        $markerStart = $pos;
        while ($pos < $n && ord($bytes[$pos]) === 0xFF) {
            $pos++;
        }
        if ($pos >= $n) {
            throw new JpegParseException('truncated JPEG marker');
        }

        $marker = ord($bytes[$pos]);
        $pos++;

        if ($marker === 0x00) {
            throw new JpegParseException('unexpected stuffed byte outside scan data');
        }

        if (isStandaloneMarker($marker)) {
            $raw = substr($bytes, $markerStart, $pos - $markerStart);
            $tokens[] = ['kind' => 'standalone', 'marker' => $marker, 'raw' => $raw, 'payload' => ''];
            if ($marker === 0xD9) {
                $sawEoi = true;
                if ($pos !== $n) {
                    $tokens[] = [
                        'kind' => 'trailing',
                        'marker' => null,
                        'raw' => substr($bytes, $pos),
                        'payload' => '',
                    ];
                    $pos = $n;
                }
                break;
            }
            continue;
        }

        if ($pos + 2 > $n) {
            throw new JpegParseException('truncated JPEG segment length');
        }
        $length = u16be($bytes, $pos);
        if ($length < 2) {
            throw new JpegParseException('invalid JPEG segment length');
        }
        $segmentEnd = $pos + $length;
        if ($segmentEnd > $n) {
            throw new JpegParseException('JPEG segment exceeds file bounds');
        }

        $payload = substr($bytes, $pos + 2, $length - 2);
        $raw = substr($bytes, $markerStart, $segmentEnd - $markerStart);
        $tokens[] = [
            'kind' => 'segment',
            'marker' => $marker,
            'raw' => $raw,
            'payload' => $payload,
        ];
        $pos = $segmentEnd;

        if ($marker === 0xDA) {
            $inScan = true;
        }
    }

    if (!$sawEoi) {
        throw new JpegParseException('missing JPEG EOI');
    }

    return $tokens;
}

function isExifApp1(array $token): bool
{
    return $token['kind'] === 'segment'
        && $token['marker'] === 0xE1
        && str_starts_with($token['payload'], "Exif\x00\x00");
}

function jpegInspection(string $bytes): array
{
    $tokens = parseJpeg($bytes);
    $records = [];
    $warnings = [];
    $count = 0;

    foreach ($tokens as $index => $token) {
        if (!isExifApp1($token)) {
            continue;
        }
        $count++;
        $decoded = decodeExifEvidence($token['payload']);
        foreach ($decoded['records'] as $record) {
            $record['source'] = 'jpeg-app1-exif-segment:' . $index;
            $records[] = $record;
        }
        foreach ($decoded['warnings'] as $warning) {
            $warnings[] = 'segment ' . $index . ': ' . $warning;
        }
        if ($decoded['records'] === []) {
            $records[] = [
                'family' => 'EXIF',
                'category' => 'other',
                'field' => null,
                'value' => null,
                'source' => 'jpeg-app1-exif-segment:' . $index,
            ];
        }
    }

    return [
        'format' => 'JPEG',
        'recognized_metadata' => $records,
        'recognized_segment_count' => $count,
        'metadata_present' => $count > 0,
        'warnings' => array_values(array_unique($warnings)),
        'limitations' => [
            'v1 recognizes JPEG EXIF APP1 metadata only',
            'absence of recognized EXIF does not imply anonymity or complete metadata removal',
            'pixels, filenames, XMP/IPTC/ICC/comments and unknown metadata are outside the v1 removal claim',
        ],
    ];
}

function decodeExifEvidence(string $payload): array
{
    $records = [];
    $warnings = [];
    if (!str_starts_with($payload, "Exif\x00\x00")) {
        return ['records' => [], 'warnings' => ['not an EXIF payload']];
    }
    $tiff = substr($payload, 6);
    if (strlen($tiff) < 8) {
        return ['records' => [], 'warnings' => ['recognized EXIF but TIFF header is truncated']];
    }

    $order = substr($tiff, 0, 2);
    if ($order === 'II') {
        $little = true;
    } elseif ($order === 'MM') {
        $little = false;
    } else {
        return ['records' => [], 'warnings' => ['recognized EXIF but TIFF byte order is invalid']];
    }

    try {
        if (tiffU16($tiff, 2, $little) !== 42) {
            return ['records' => [], 'warnings' => ['recognized EXIF but TIFF magic is invalid']];
        }
        $ifd0 = tiffU32($tiff, 4, $little);
        $visited = [];
        parseIfd($tiff, $ifd0, $little, 'ifd0', $records, $warnings, $visited, 0);
    } catch (JpegParseException $e) {
        $warnings[] = 'recognized EXIF but TIFF fields are undecodable: ' . $e->getMessage();
    }

    return ['records' => $records, 'warnings' => array_values(array_unique($warnings))];
}

function exifTagInfo(string $ifdKind, int $tag): ?array
{
    $ifd0 = [
        0x010F => ['device', 'make'],
        0x0110 => ['device', 'model'],
        0x0131 => ['software', 'software'],
        0x0132 => ['capture-time', 'datetime'],
        0x013B => ['descriptive', 'artist'],
        0x8298 => ['descriptive', 'copyright'],
    ];
    $exif = [
        0x9003 => ['capture-time', 'datetime-original'],
        0x9004 => ['capture-time', 'datetime-digitized'],
        0xA434 => ['device', 'lens-model'],
    ];
    $gps = [
        0x0001 => ['location', 'gps-latitude-ref'],
        0x0002 => ['location', 'gps-latitude'],
        0x0003 => ['location', 'gps-longitude-ref'],
        0x0004 => ['location', 'gps-longitude'],
        0x001D => ['location', 'gps-date-stamp'],
    ];
    return match ($ifdKind) {
        'ifd0' => $ifd0[$tag] ?? null,
        'exif' => $exif[$tag] ?? null,
        'gps' => $gps[$tag] ?? null,
        default => null,
    };
}

function tiffTypeSize(int $type): ?int
{
    return match ($type) {
        1, 2, 7 => 1,
        3 => 2,
        4, 9 => 4,
        5, 10 => 8,
        default => null,
    };
}

function decodeTiffValue(string $tiff, int $entryOffset, int $type, int $count, bool $little): ?string
{
    $size = tiffTypeSize($type);
    if ($size === null || $count < 0) {
        return null;
    }
    $total = $size * $count;
    if ($total < 0 || $total > 1048576) {
        throw new JpegParseException('unreasonable TIFF value size');
    }
    if ($total <= 4) {
        $raw = substr($tiff, $entryOffset + 8, 4);
        $raw = substr($raw, 0, $total);
    } else {
        $offset = tiffU32($tiff, $entryOffset + 8, $little);
        if ($offset + $total > strlen($tiff)) {
            throw new JpegParseException('TIFF value exceeds payload bounds');
        }
        $raw = substr($tiff, $offset, $total);
    }

    if ($type === 2) {
        return rtrim($raw, "\x00");
    }
    if ($type === 3 && $count === 1) {
        return (string)tiffU16($raw . "\x00\x00", 0, $little);
    }
    if ($type === 4 && $count === 1) {
        return (string)tiffU32($raw, 0, $little);
    }
    if (($type === 5 || $type === 10) && $count > 0) {
        $parts = [];
        for ($i = 0; $i < min($count, 3); $i++) {
            $base = $i * 8;
            $num = tiffU32($raw, $base, $little);
            $den = tiffU32($raw, $base + 4, $little);
            $parts[] = $den === 0 ? "$num/0" : sprintf('%.6f', $num / $den);
        }
        return implode(', ', $parts);
    }
    if (($type === 1 || $type === 7) && $count <= 16) {
        return strtoupper(bin2hex($raw));
    }
    return null;
}

function parseIfd(
    string $tiff,
    int $offset,
    bool $little,
    string $kind,
    array &$records,
    array &$warnings,
    array &$visited,
    int $depth
): void {
    if ($depth > 4) {
        $warnings[] = 'TIFF IFD depth limit reached';
        return;
    }
    if ($offset === 0) {
        return;
    }
    $key = $kind . ':' . $offset;
    if (isset($visited[$key])) {
        $warnings[] = 'TIFF IFD cycle detected';
        return;
    }
    $visited[$key] = true;

    $count = tiffU16($tiff, $offset, $little);
    if ($count > 1024) {
        throw new JpegParseException('unreasonable TIFF IFD entry count');
    }
    $entryStart = $offset + 2;
    $entryEnd = $entryStart + ($count * 12);
    if ($entryEnd + 4 > strlen($tiff)) {
        throw new JpegParseException('TIFF IFD exceeds payload bounds');
    }

    $exifPointer = null;
    $gpsPointer = null;
    for ($i = 0; $i < $count; $i++) {
        $e = $entryStart + ($i * 12);
        $tag = tiffU16($tiff, $e, $little);
        $type = tiffU16($tiff, $e + 2, $little);
        $items = tiffU32($tiff, $e + 4, $little);

        if ($kind === 'ifd0' && $tag === 0x8769) {
            $exifPointer = tiffU32($tiff, $e + 8, $little);
            continue;
        }
        if ($kind === 'ifd0' && $tag === 0x8825) {
            $gpsPointer = tiffU32($tiff, $e + 8, $little);
            $records[] = [
                'family' => 'EXIF',
                'category' => 'location',
                'field' => 'gps-ifd-present',
                'value' => null,
            ];
            continue;
        }

        $info = exifTagInfo($kind, $tag);
        if ($info === null) {
            continue;
        }
        try {
            $value = decodeTiffValue($tiff, $e, $type, $items, $little);
        } catch (JpegParseException $ex) {
            $warnings[] = sprintf('cannot decode %s: %s', $info[1], $ex->getMessage());
            $value = null;
        }
        $records[] = [
            'family' => 'EXIF',
            'category' => $info[0],
            'field' => $info[1],
            'value' => $value,
        ];
    }

    if ($exifPointer !== null) {
        parseIfd($tiff, $exifPointer, $little, 'exif', $records, $warnings, $visited, $depth + 1);
    }
    if ($gpsPointer !== null) {
        parseIfd($tiff, $gpsPointer, $little, 'gps', $records, $warnings, $visited, $depth + 1);
    }
}

function scrubExifBytes(string $bytes): array
{
    $tokens = parseJpeg($bytes);
    $removed = 0;
    $out = '';
    foreach ($tokens as $token) {
        if (isExifApp1($token)) {
            $removed++;
            continue;
        }
        $out .= $token['raw'];
    }
    return ['bytes' => $out, 'removed_segments' => $removed];
}

function canonicalPathForComparison(string $path): string
{
    $dir = realpath(dirname($path));
    $base = basename($path);
    return ($dir === false ? dirname($path) : $dir) . DIRECTORY_SEPARATOR . $base;
}

function readRegularFile(string $path): string
{
    if (!is_file($path) || is_link($path)) {
        throw new RuntimeException('input must be an existing non-symlink regular file');
    }
    $bytes = @file_get_contents($path);
    if ($bytes === false) {
        throw new RuntimeException('cannot read input file');
    }
    return $bytes;
}

function baseResult(string $operation, string $input, ?string $output): array
{
    return [
        'schema_version' => CYSE_METADATA_SCHEMA,
        'tool_version' => CYSE_METADATA_VERSION,
        'operation' => $operation,
        'input_path' => $input,
        'output_path' => $output,
        'format' => 'JPEG',
        'recognized_metadata' => [],
        'recognized_segment_count' => 0,
        'metadata_present' => false,
        'mutation_performed' => false,
        'verification' => null,
        'warnings' => [],
        'limitations' => [],
    ];
}

function inspectPath(string $path): array
{
    $result = baseResult('inspect', $path, null);
    $inspection = jpegInspection(readRegularFile($path));
    return array_replace($result, $inspection);
}

function verifyPath(string $path): array
{
    $result = baseResult('verify', $path, null);
    try {
        $inspection = jpegInspection(readRegularFile($path));
        $result = array_replace($result, $inspection);
        $present = $inspection['recognized_segment_count'] > 0;
        $result['verification'] = [
            'status' => $present ? 'FAIL' : 'PASS',
            'claim' => 'recognized-exif-absent',
            'recognized_segment_count' => $inspection['recognized_segment_count'],
            'reason' => $present
                ? 'recognized EXIF APP1 metadata remains'
                : 'no recognized EXIF APP1 metadata remains under the v1 parser',
        ];
    } catch (Throwable $e) {
        $result['verification'] = [
            'status' => 'UNKNOWN',
            'claim' => 'recognized-exif-absent',
            'recognized_segment_count' => null,
            'reason' => $e->getMessage(),
        ];
        $result['warnings'][] = $e->getMessage();
    }
    return $result;
}

function scrubPath(string $input, string $output, bool $dryRun): array
{
    if (canonicalPathForComparison($input) === canonicalPathForComparison($output)) {
        throw new InvalidArgumentException('input and output paths must differ');
    }
    if (file_exists($output) || is_link($output)) {
        throw new InvalidArgumentException('output path already exists');
    }
    $outputDir = dirname($output);
    if (!is_dir($outputDir) || !is_writable($outputDir)) {
        throw new RuntimeException('output directory is not writable');
    }

    $source = readRegularFile($input);
    $inspection = jpegInspection($source);
    $result = array_replace(baseResult('scrub', $input, $output), $inspection);

    if ($dryRun) {
        $result['warnings'][] = 'dry-run: no output was created and no post-mutation verification was claimed';
        $result['verification'] = null;
        return $result;
    }

    $scrubbed = scrubExifBytes($source);
    $tmp = tempnam($outputDir, '.cyse-metadata-');
    if ($tmp === false) {
        throw new RuntimeException('cannot create temporary output');
    }

    try {
        $written = @file_put_contents($tmp, $scrubbed['bytes'], LOCK_EX);
        if ($written === false || $written !== strlen($scrubbed['bytes'])) {
            throw new RuntimeException('failed to write complete temporary output');
        }

        $post = jpegInspection(readRegularFile($tmp));
        $verificationPass = $post['recognized_segment_count'] === 0;
        $result['mutation_performed'] = true;
        $result['verification'] = [
            'status' => $verificationPass ? 'PASS' : 'FAIL',
            'claim' => 'recognized-exif-absent',
            'recognized_segment_count' => $post['recognized_segment_count'],
            'reason' => $verificationPass
                ? 'temporary output re-parsed successfully with no recognized EXIF APP1 metadata'
                : 'recognized EXIF remains after scrub',
        ];
        $result['removed_segment_count'] = $scrubbed['removed_segments'];

        if (!$verificationPass) {
            throw new RuntimeException('post-write recognized-EXIF verification failed');
        }

        if (!@rename($tmp, $output)) {
            throw new RuntimeException('cannot atomically publish verified output');
        }
        $tmp = '';
    } finally {
        if ($tmp !== '' && file_exists($tmp)) {
            @unlink($tmp);
        }
    }

    return $result;
}

function renderHuman(array $r): string
{
    $lines = [];
    $lines[] = 'CYSE Metadata Privacy Scrubber';
    $lines[] = 'Operation: ' . $r['operation'];
    $lines[] = 'Input: ' . $r['input_path'];
    if ($r['output_path'] !== null) {
        $lines[] = 'Output: ' . $r['output_path'];
    }
    $lines[] = 'Format: ' . $r['format'];
    $lines[] = 'Recognized EXIF segments: ' . $r['recognized_segment_count'];
    $lines[] = 'Recognized metadata present: ' . ($r['metadata_present'] ? 'yes' : 'no');
    foreach ($r['recognized_metadata'] as $m) {
        $field = $m['field'] ?? 'undecoded-exif';
        $value = $m['value'] ?? '(not decoded)';
        $lines[] = sprintf('  - [%s] %s = %s', $m['category'], $field, $value);
    }
    if ($r['verification'] !== null) {
        $lines[] = 'Verification: ' . $r['verification']['status'] . ' — ' . $r['verification']['claim'];
        $lines[] = '  ' . $r['verification']['reason'];
    }
    foreach ($r['warnings'] as $warning) {
        $lines[] = 'Warning: ' . $warning;
    }
    $lines[] = 'Limitation: PASS/absence means recognized EXIF APP1 absent under v1, not anonymity or complete metadata removal.';
    return implode(PHP_EOL, $lines) . PHP_EOL;
}

function usage(): string
{
    return "usage:\n"
        . "  cyse-metadata inspect <INPUT> [--json]\n"
        . "  cyse-metadata scrub <INPUT> --output <OUTPUT> [--dry-run] [--json]\n"
        . "  cyse-metadata verify <INPUT> [--json]\n";
}

function emitResult(array $result, bool $json): void
{
    if ($json) {
        echo json_encode($result, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . PHP_EOL;
    } else {
        echo renderHuman($result);
    }
}

function metadataMain(array $argv): int
{
    $operation = $argv[1] ?? '';
    $input = $argv[2] ?? '';
    $json = in_array('--json', $argv, true);

    if (!in_array($operation, ['inspect', 'scrub', 'verify'], true) || $input === '' || str_starts_with($input, '--')) {
        fwrite(STDERR, usage());
        return 2;
    }

    try {
        if ($operation === 'inspect') {
            $result = inspectPath($input);
            emitResult($result, $json);
            return 0;
        }

        if ($operation === 'verify') {
            $result = verifyPath($input);
            emitResult($result, $json);
            return match ($result['verification']['status']) {
                'PASS' => 0,
                'FAIL' => 1,
                default => 3,
            };
        }

        $idx = array_search('--output', $argv, true);
        if ($idx === false || !isset($argv[$idx + 1]) || str_starts_with($argv[$idx + 1], '--')) {
            fwrite(STDERR, "scrub requires --output <OUTPUT>\n");
            return 2;
        }
        $output = $argv[$idx + 1];
        $dryRun = in_array('--dry-run', $argv, true);
        $result = scrubPath($input, $output, $dryRun);
        emitResult($result, $json);
        if ($dryRun) {
            return 0;
        }
        return ($result['verification']['status'] ?? 'UNKNOWN') === 'PASS' ? 0 : 1;
    } catch (InvalidArgumentException $e) {
        fwrite(STDERR, 'input error: ' . $e->getMessage() . PHP_EOL);
        return 2;
    } catch (Throwable $e) {
        fwrite(STDERR, 'metadata error: ' . $e->getMessage() . PHP_EOL);
        return 3;
    }
}

if (realpath($_SERVER['SCRIPT_FILENAME'] ?? '') === __FILE__) {
    exit(metadataMain($argv));
}
