<?php

declare(strict_types=1);

require __DIR__ . '/../src/cyse_metadata.php';

function checkMeta(bool $condition, string $message): void
{
    if (!$condition) {
        throw new RuntimeException('TEST FAILED: ' . $message);
    }
}

function le16(int $v): string
{
    return chr($v & 0xFF) . chr(($v >> 8) & 0xFF);
}

function le32(int $v): string
{
    return chr($v & 0xFF) . chr(($v >> 8) & 0xFF) . chr(($v >> 16) & 0xFF) . chr(($v >> 24) & 0xFF);
}

function jpegSegment(int $marker, string $payload): string
{
    $length = strlen($payload) + 2;
    return "\xFF" . chr($marker) . chr(($length >> 8) & 0xFF) . chr($length & 0xFF) . $payload;
}

function tiffAsciiEntry(int $tag, string $value, int &$dataOffset, string &$extra): string
{
    $value .= "\x00";
    $count = strlen($value);
    if ($count <= 4) {
        $inline = str_pad($value, 4, "\x00");
        return le16($tag) . le16(2) . le32($count) . $inline;
    }
    $entry = le16($tag) . le16(2) . le32($count) . le32($dataOffset);
    $extra .= $value;
    $dataOffset += $count;
    return $entry;
}

function syntheticExifPayload(bool $withGps = true): string
{
    // TIFF header + IFD0 with Make, DateTime and optional GPS IFD pointer.
    $entryCount = $withGps ? 3 : 2;
    $ifd0Offset = 8;
    $ifd0Size = 2 + ($entryCount * 12) + 4;
    $dataOffset = $ifd0Offset + $ifd0Size;
    $extra = '';

    $entries = '';
    $entries .= tiffAsciiEntry(0x010F, 'CYSE-CAMERA', $dataOffset, $extra);
    $entries .= tiffAsciiEntry(0x0132, '2026:08:24 12:00:00', $dataOffset, $extra);

    $gpsIfd = '';
    if ($withGps) {
        $gpsOffset = $dataOffset;
        $entries .= le16(0x8825) . le16(4) . le32(1) . le32($gpsOffset);
        $gpsDataOffset = $gpsOffset + 2 + (2 * 12) + 4;
        $gpsExtra = '';
        $gpsEntries = '';
        $gpsEntries .= tiffAsciiEntry(0x0001, 'N', $gpsDataOffset, $gpsExtra);
        $gpsEntries .= tiffAsciiEntry(0x0003, 'E', $gpsDataOffset, $gpsExtra);
        $gpsIfd = le16(2) . $gpsEntries . le32(0) . $gpsExtra;
    }

    $ifd0 = le16($entryCount) . $entries . le32(0) . $extra . $gpsIfd;
    $tiff = 'II' . le16(42) . le32($ifd0Offset) . $ifd0;
    return "Exif\x00\x00" . $tiff;
}

function malformedButRecognizedExifPayload(): string
{
    return "Exif\x00\x00" . 'ZZ' . "\x00\x00\x00\x00\x00\x00";
}

function syntheticJpeg(array $segments = [], string $entropy = "\x11\x22\xFF\x00\x33"): string
{
    $bytes = "\xFF\xD8";
    $bytes .= jpegSegment(0xE0, "JFIF\x00\x01\x01");
    foreach ($segments as $segment) {
        $bytes .= $segment;
    }
    // Minimal structural SOS header; parser preserves it and entropy bytes verbatim.
    $bytes .= jpegSegment(0xDA, "\x01\x01\x00\x00\x3F\x00");
    $bytes .= $entropy;
    $bytes .= "\xFF\xD9";
    return $bytes;
}

function tokenRawByMarker(array $tokens, int $marker): array
{
    $out = [];
    foreach ($tokens as $token) {
        if (($token['marker'] ?? null) === $marker) {
            $out[] = $token['raw'];
        }
    }
    return $out;
}

$plain = syntheticJpeg();
$plainInspection = jpegInspection($plain);
checkMeta($plainInspection['recognized_segment_count'] === 0, 'JPEG without APP1 has no recognized EXIF');
checkMeta($plainInspection['metadata_present'] === false, 'metadata_present false without EXIF');

$exifSegment = jpegSegment(0xE1, syntheticExifPayload());
$withExif = syntheticJpeg([$exifSegment]);
$inspection = jpegInspection($withExif);
checkMeta($inspection['recognized_segment_count'] === 1, 'one EXIF APP1 is recognized');
checkMeta($inspection['metadata_present'] === true, 'metadata_present true with EXIF');
$categories = array_column($inspection['recognized_metadata'], 'category');
checkMeta(in_array('device', $categories, true), 'device metadata category decoded');
checkMeta(in_array('capture-time', $categories, true), 'capture-time metadata category decoded');
checkMeta(in_array('location', $categories, true), 'location metadata category decoded');

$xmpSegment = jpegSegment(0xE1, "http://ns.adobe.com/xap/1.0/\x00<xmp>synthetic</xmp>");
$entropy = "\x10\x20\x30\xFF\x00\x40\xFF\xD0\x50";
$exifAndXmp = syntheticJpeg([$exifSegment, $xmpSegment], $entropy);
$beforeTokens = parseJpeg($exifAndXmp);
$scrub = scrubExifBytes($exifAndXmp);
$afterTokens = parseJpeg($scrub['bytes']);
checkMeta($scrub['removed_segments'] === 1, 'scrub removes one EXIF APP1');
checkMeta(jpegInspection($scrub['bytes'])['recognized_segment_count'] === 0, 'scrubbed bytes verify EXIF absent');
checkMeta(tokenRawByMarker($afterTokens, 0xE1) === [$xmpSegment], 'non-EXIF APP1 is preserved byte-for-byte');

$beforeEntropy = array_values(array_map(fn(array $t): string => $t['raw'], array_filter($beforeTokens, fn(array $t): bool => $t['kind'] === 'entropy')));
$afterEntropy = array_values(array_map(fn(array $t): string => $t['raw'], array_filter($afterTokens, fn(array $t): bool => $t['kind'] === 'entropy')));
checkMeta($beforeEntropy === $afterEntropy, 'compressed scan/entropy bytes are not re-encoded');

$multiple = syntheticJpeg([$exifSegment, jpegSegment(0xE1, syntheticExifPayload(false))]);
$multiScrub = scrubExifBytes($multiple);
checkMeta($multiScrub['removed_segments'] === 2, 'all recognized EXIF APP1 segments removed');
checkMeta(jpegInspection($multiScrub['bytes'])['recognized_segment_count'] === 0, 'multiple EXIF segments absent after scrub');

$undecodable = syntheticJpeg([jpegSegment(0xE1, malformedButRecognizedExifPayload())]);
$undecInspection = jpegInspection($undecodable);
checkMeta($undecInspection['recognized_segment_count'] === 1, 'undecodable TIFF remains recognized as EXIF');
checkMeta($undecInspection['warnings'] !== [], 'undecodable TIFF produces explicit warning');
checkMeta(scrubExifBytes($undecodable)['removed_segments'] === 1, 'undecodable recognized EXIF remains removable');

try {
    parseJpeg("not-a-jpeg");
    checkMeta(false, 'non-JPEG must fail');
} catch (JpegParseException) {
    checkMeta(true, 'non-JPEG rejected');
}

$truncated = "\xFF\xD8\xFF\xE1\x00\x20Exif\x00\x00\xFF\xD9";
try {
    parseJpeg($truncated);
    checkMeta(false, 'truncated segment must fail closed');
} catch (JpegParseException) {
    checkMeta(true, 'truncated segment rejected');
}

$tmpRoot = sys_get_temp_dir() . '/cyse-meta-' . bin2hex(random_bytes(6));
mkdir($tmpRoot, 0700, true);
$input = $tmpRoot . '/input.jpg';
$output = $tmpRoot . '/output.jpg';
file_put_contents($input, $withExif);
$originalHash = hash_file('sha256', $input);

$verifyBefore = verifyPath($input);
checkMeta($verifyBefore['verification']['status'] === 'FAIL', 'unscrubbed fixture verify FAIL');

$dryOutput = $tmpRoot . '/dry.jpg';
$dry = scrubPath($input, $dryOutput, true);
checkMeta($dry['mutation_performed'] === false, 'dry-run reports no mutation');
checkMeta(!file_exists($dryOutput), 'dry-run creates no output');
checkMeta($dry['verification'] === null, 'dry-run does not claim post-mutation verification');

$result = scrubPath($input, $output, false);
checkMeta($result['mutation_performed'] === true, 'scrub reports mutation');
checkMeta($result['verification']['status'] === 'PASS', 'scrub independently verifies output');
checkMeta(file_exists($output), 'scrub publishes output');
checkMeta(verifyPath($output)['verification']['status'] === 'PASS', 'independent verify PASS on output');
checkMeta(verifyPath($input)['verification']['status'] === 'FAIL', 'original still contains recognized EXIF');
checkMeta(hash_file('sha256', $input) === $originalHash, 'original file bytes are unchanged');

try {
    scrubPath($input, $input, false);
    checkMeta(false, 'input/output collision must fail');
} catch (InvalidArgumentException) {
    checkMeta(true, 'input/output collision rejected');
}

try {
    scrubPath($input, $output, false);
    checkMeta(false, 'existing output must fail');
} catch (InvalidArgumentException) {
    checkMeta(true, 'existing output rejected');
}

$notJpeg = $tmpRoot . '/not.jpg';
file_put_contents($notJpeg, 'not jpeg');
try {
    inspectPath($notJpeg);
    checkMeta(false, 'non-JPEG file inspect must fail');
} catch (JpegParseException) {
    checkMeta(true, 'non-JPEG inspect rejected');
}

checkMeta(metadataMain(['cyse-metadata', 'inspect']) === 2, 'missing input is CLI error');
checkMeta(metadataMain(['cyse-metadata', 'scrub', $input]) === 2, 'missing output is CLI error');

@unlink($output);
@unlink($input);
@unlink($notJpeg);
@rmdir($tmpRoot);

echo "OK: metadata scrubber offline tests passed\n";
