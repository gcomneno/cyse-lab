<?php

declare(strict_types=1);

const CYSE_DEPS_VERSION = '1.0.0';

function deps_read_json(string $path): array {
    if (!is_file($path) || !is_readable($path)) throw new RuntimeException("unreadable file: $path");
    $raw = file_get_contents($path);
    if ($raw === false) throw new RuntimeException("read failure: $path");
    $data = json_decode($raw, true);
    if (!is_array($data)) throw new RuntimeException("invalid JSON: $path");
    return $data;
}

function deps_norm_name(string $name): ?string {
    $n = strtolower(trim($name));
    return preg_match('#^[a-z0-9_.-]+/[a-z0-9_.-]+$#', $n) ? $n : null;
}

function deps_norm_version(string $version): ?string {
    $v = ltrim(trim($version), 'vV');
    return preg_match('/^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$/', $v) ? $v : null;
}

function deps_compare(string $a, string $b, string $op): bool {
    return version_compare($a, $b, $op);
}

function deps_constraint_match(string $version, string $constraint): ?bool {
    $c = trim($constraint);
    if ($c === '') return null;
    if (preg_match('/^\d+\.\d+\.\d+$/', $c)) return version_compare($version, $c, '==');
    $parts = preg_split('/\s*,\s*/', $c);
    if (!$parts) return null;
    foreach ($parts as $part) {
        if (!preg_match('/^(<=|>=|<|>|=|==)\s*(\d+\.\d+\.\d+)$/', trim($part), $m)) return null;
        $op = $m[1] === '=' ? '==' : $m[1];
        if (!deps_compare($version, $m[2], $op)) return false;
    }
    return true;
}

function deps_root_sets(?array $root): array {
    if ($root === null) return [null, null];
    $prod = [];
    $dev = [];
    foreach (($root['require'] ?? []) as $name => $_) {
        if (($n = deps_norm_name((string)$name)) !== null) $prod[$n] = true;
    }
    foreach (($root['require-dev'] ?? []) as $name => $_) {
        if (($n = deps_norm_name((string)$name)) !== null) $dev[$n] = true;
    }
    return [$prod, $dev];
}

function deps_parse_lock(array $lock, ?array $root): array {
    [$rootProd, $rootDev] = deps_root_sets($root);
    $out = [];
    $seen = [];
    foreach ([['packages', 'production'], ['packages-dev', 'development']] as [$key, $scope]) {
        $items = $lock[$key] ?? [];
        if (!is_array($items)) throw new RuntimeException("invalid lock section: $key");
        foreach ($items as $idx => $pkg) {
            if (!is_array($pkg)) throw new RuntimeException("invalid package record: $key[$idx]");
            $rawName = (string)($pkg['name'] ?? '');
            $rawVersion = (string)($pkg['version'] ?? '');
            $name = deps_norm_name($rawName);
            $version = deps_norm_version($rawVersion);
            $state = 'OK';
            $reason = null;
            if ($name === null || $version === null) {
                $state = 'NOT_ASSESSABLE';
                $reason = $name === null ? 'invalid or missing package name' : 'unsupported or missing resolved version';
            }
            if ($name !== null && isset($seen[$name]) && $seen[$name] !== $version) {
                throw new RuntimeException("contradictory locked versions for $name");
            }
            if ($name !== null) $seen[$name] = $version;
            $kind = 'UNKNOWN';
            if ($rootProd !== null && $name !== null) {
                $kind = (($scope === 'production' && isset($rootProd[$name])) || ($scope === 'development' && isset($rootDev[$name]))) ? 'DIRECT' : 'TRANSITIVE';
            }
            $out[] = [
                'package' => $name ?? $rawName,
                'resolved_version' => $version ?? $rawVersion,
                'scope' => $scope,
                'dependency_kind' => $kind,
                '_local_state' => $state,
                '_local_reason' => $reason,
            ];
        }
    }
    return $out;
}

function deps_index_advisories(array $dataset): array {
    if (($dataset['available'] ?? true) !== true) return ['available' => false, 'snapshot' => $dataset['snapshot'] ?? null, 'by_package' => []];
    $records = $dataset['advisories'] ?? null;
    if (!is_array($records)) throw new RuntimeException('invalid advisory dataset');
    $by = [];
    foreach ($records as $i => $a) {
        if (!is_array($a)) throw new RuntimeException("invalid advisory record: $i");
        $name = deps_norm_name((string)($a['package_name'] ?? ''));
        if ($name === null) throw new RuntimeException("invalid advisory package name: $i");
        if (strtolower((string)($a['package_ecosystem'] ?? 'composer')) !== 'composer') continue;
        $a['_name'] = $name;
        $by[$name][] = $a;
    }
    return ['available' => true, 'snapshot' => $dataset['snapshot'] ?? null, 'by_package' => $by];
}

function deps_assess(array $lock, array $dataset, ?array $root = null): array {
    $deps = deps_parse_lock($lock, $root);
    $adv = deps_index_advisories($dataset);
    $counts = ['AFFECTED'=>0,'NOT_KNOWN_AFFECTED'=>0,'UNKNOWN'=>0,'NOT_ASSESSABLE'=>0];
    $complete = true;
    foreach ($deps as &$d) {
        $matches = [];
        $reason = '';
        if ($d['_local_state'] === 'NOT_ASSESSABLE') {
            $state = 'NOT_ASSESSABLE';
            $reason = $d['_local_reason'];
            $complete = false;
        } elseif (!$adv['available']) {
            $state = 'UNKNOWN';
            $reason = 'advisory dataset unavailable';
            $complete = false;
        } else {
            $unknown = false;
            foreach ($adv['by_package'][$d['package']] ?? [] as $a) {
                if (($a['withdrawn_at'] ?? null) !== null) continue;
                $constraints = $a['affected_constraints'] ?? null;
                if (!is_array($constraints) || $constraints === []) {
                    $unknown = true;
                    continue;
                }
                foreach ($constraints as $constraint) {
                    $m = deps_constraint_match($d['resolved_version'], (string)$constraint);
                    if ($m === null) { $unknown = true; continue; }
                    if ($m) {
                        $matches[] = [
                            'advisory_id' => (string)($a['advisory_id'] ?? $a['source_record_id'] ?? 'unknown'),
                            'source' => (string)($a['source'] ?? 'fixture'),
                            'source_record_id' => (string)($a['source_record_id'] ?? ''),
                            'affected_constraint' => (string)$constraint,
                            'source_severity' => $a['severity'] ?? null,
                            'summary' => (string)($a['summary'] ?? ''),
                            'references' => is_array($a['references'] ?? null) ? $a['references'] : [],
                        ];
                    }
                }
            }
            if ($unknown) {
                $state = 'UNKNOWN';
                $reason = 'relevant advisory evidence uses unsupported or incomplete constraint semantics';
                $complete = false;
            } elseif ($matches !== []) {
                $state = 'AFFECTED';
                $reason = 'resolved version matches active advisory evidence';
            } else {
                $state = 'NOT_KNOWN_AFFECTED';
                $reason = 'no active advisory in the bounded snapshot matched the resolved version';
            }
        }
        $d['state'] = $state;
        $d['matched_advisories'] = $matches;
        $d['reason'] = $reason;
        $d['limitations'] = ['NOT_KNOWN_AFFECTED is not proof of safety; assessment is bounded by the advisory snapshot and supported matcher semantics.'];
        unset($d['_local_state'], $d['_local_reason']);
        $counts[$state]++;
    }
    unset($d);
    return [
        'schema_version' => '1',
        'tool_version' => CYSE_DEPS_VERSION,
        'ecosystem' => 'Composer',
        'advisory_snapshot' => $adv['snapshot'],
        'assessment_complete' => $complete,
        'dependencies' => $deps,
        'summary' => ['assessed_dependencies'=>count($deps),'state_counts'=>$counts],
        'warnings' => [],
        'limitations' => [
            'Composer/PHP lockfiles only.',
            'Constraint support is intentionally bounded to exact versions and comma-separated < <= > >= = == comparisons.',
            'NOT_KNOWN_AFFECTED does not mean SAFE.',
            'The tool does not determine exploitability, reachability, compatibility of upgrades, or undisclosed vulnerabilities.',
        ],
    ];
}

function deps_exit_code(array $r): int {
    $c = $r['summary']['state_counts'];
    if (!$r['assessment_complete'] || ($c['UNKNOWN'] ?? 0) > 0 || ($c['NOT_ASSESSABLE'] ?? 0) > 0) return 3;
    if (($c['AFFECTED'] ?? 0) > 0) return 1;
    return 0;
}

function deps_render_human(array $r): string {
    $lines = ["CYSE Dependency Vulnerability Auditor", "ecosystem={$r['ecosystem']} snapshot=" . ($r['advisory_snapshot'] ?? 'unknown')];
    foreach ($r['dependencies'] as $d) {
        $lines[] = sprintf('%-22s %-12s %-11s %-10s %s', $d['package'], $d['resolved_version'], $d['scope'], $d['dependency_kind'], $d['state']);
    }
    $c = $r['summary']['state_counts'];
    $lines[] = 'Summary: AFFECTED=' . $c['AFFECTED'] . ' NOT_KNOWN_AFFECTED=' . $c['NOT_KNOWN_AFFECTED'] . ' UNKNOWN=' . $c['UNKNOWN'] . ' NOT_ASSESSABLE=' . $c['NOT_ASSESSABLE'];
    $lines[] = 'Boundary: NOT_KNOWN_AFFECTED is not SAFE; results are bounded by this advisory snapshot.';
    return implode("\n", $lines) . "\n";
}

function deps_main(array $argv): int {
    if (($argv[1] ?? '') !== 'audit' || ($argv[2] ?? '') === '') {
        fwrite(STDERR, "usage: cyse-deps audit <composer.lock> --advisories <fixture.json> [--root composer.json] [--json]\n");
        return 2;
    }
    $lockPath = $argv[2];
    $ai = array_search('--advisories', $argv, true);
    if ($ai === false || !isset($argv[$ai+1])) { fwrite(STDERR, "missing --advisories\n"); return 2; }
    $ri = array_search('--root', $argv, true);
    $json = in_array('--json', $argv, true);
    try {
        $lock = deps_read_json($lockPath);
        $dataset = deps_read_json($argv[$ai+1]);
        $root = ($ri !== false && isset($argv[$ri+1])) ? deps_read_json($argv[$ri+1]) : null;
        $r = deps_assess($lock, $dataset, $root);
        $r['input_lockfile'] = $lockPath;
        $r['root_manifest'] = $ri !== false ? ($argv[$ri+1] ?? null) : null;
    } catch (Throwable $e) {
        fwrite(STDERR, "assessment error: {$e->getMessage()}\n");
        return 3;
    }
    echo $json ? json_encode($r, JSON_PRETTY_PRINT|JSON_UNESCAPED_SLASHES) . "\n" : deps_render_human($r);
    return deps_exit_code($r);
}

if (realpath($_SERVER['SCRIPT_FILENAME'] ?? '') === __FILE__) exit(deps_main($argv));
