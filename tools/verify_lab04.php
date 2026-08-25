<?php

declare(strict_types=1);
require __DIR__ . '/../src/cyse_deps.php';

function fail(string $m): never { fwrite(STDERR, "FAIL: $m\n"); exit(1); }
function p(string $v): array { return ['name'=>'acme/widget','version'=>$v]; }
$advisories = ['snapshot'=>'lab04-fixed-snapshot','available'=>true,'advisories'=>[[
    'advisory_id'=>'CYSE-SYNTH-001','source'=>'synthetic','source_record_id'=>'CYSE-SYNTH-001',
    'package_ecosystem'=>'composer','package_name'=>'acme/widget','affected_constraints'=>['>=1.0.0,<2.0.0'],
    'severity'=>'HIGH','summary'=>'synthetic learning advisory','references'=>[],'withdrawn_at'=>null,
]]];

$before = deps_assess(['packages'=>[p('1.5.0')],'packages-dev'=>[]], $advisories);
$after = deps_assess(['packages'=>[p('2.1.0')],'packages-dev'=>[]], $advisories);

$sb = $before['dependencies'][0]['state'] ?? null;
$sa = $after['dependencies'][0]['state'] ?? null;
if ($sb !== 'AFFECTED') fail("expected AFFECTED before, got " . (string)$sb);
if ($sa !== 'NOT_KNOWN_AFFECTED') fail("expected NOT_KNOWN_AFFECTED after, got " . (string)$sa);
if ($before['advisory_snapshot'] !== $after['advisory_snapshot']) fail('snapshot changed across transition');

echo "snapshot={$before['advisory_snapshot']}\n";
echo "version_before=1.5.0 state_before=$sb\n";
echo "version_after=2.1.0 state_after=$sa\n";
echo "boundary=NOT_KNOWN_AFFECTED means no active advisory in this bounded snapshot matched version 2.1.0; it is not proof of safety.\n";
echo "RESULT=PASS\n";
