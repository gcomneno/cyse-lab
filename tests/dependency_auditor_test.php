<?php

declare(strict_types=1);
require __DIR__ . '/../src/cyse_deps.php';

function t(bool $ok, string $msg): void { if (!$ok) throw new RuntimeException($msg); }
function lock(array $prod = [], array $dev = []): array { return ['packages'=>$prod,'packages-dev'=>$dev]; }
function pkg(string $name, string $version): array { return ['name'=>$name,'version'=>$version]; }
function dataset(array $advisories, bool $available = true): array { return ['snapshot'=>'fixture-1','available'=>$available,'advisories'=>$advisories]; }
function adv(string $name, array $constraints, ?string $withdrawn = null, string $id = 'ADV-1'): array { return ['advisory_id'=>$id,'source'=>'synthetic','source_record_id'=>$id,'package_ecosystem'=>'composer','package_name'=>$name,'affected_constraints'=>$constraints,'severity'=>'HIGH','summary'=>'synthetic advisory','references'=>[],'withdrawn_at'=>$withdrawn]; }
function state(array $r, string $name): string { foreach ($r['dependencies'] as $d) if ($d['package'] === strtolower($name)) return $d['state']; throw new RuntimeException("missing $name"); }

$r = deps_assess(lock([pkg('Acme/Widget','1.2.0')]), dataset([adv('acme/widget',['>=1.0.0,<2.0.0'])]));
t(state($r,'acme/widget') === 'AFFECTED', 'matching advisory');
t(deps_exit_code($r) === 1, 'affected exit');

$r = deps_assess(lock([pkg('acme/widget','2.1.0')]), dataset([adv('acme/widget',['>=1.0.0,<2.0.0'])]));
t(state($r,'acme/widget') === 'NOT_KNOWN_AFFECTED', 'non matching version');
t(deps_exit_code($r) === 0, 'bounded clean exit');

$root = ['require'=>['acme/direct'=>'^1.0'],'require-dev'=>['acme/dev'=>'^1.0']];
$r = deps_assess(lock([pkg('acme/direct','1.0.0'),pkg('acme/transitive','1.0.0')],[pkg('acme/dev','1.0.0')]), dataset([]), $root);
$k=[]; foreach($r['dependencies'] as $d)$k[$d['package']]=$d['dependency_kind'];
t($k['acme/direct']==='DIRECT' && $k['acme/transitive']==='TRANSITIVE' && $k['acme/dev']==='DIRECT','direct/transitive classification');
$r2 = deps_assess(lock([pkg('acme/direct','1.0.0')]), dataset([]));
t($r2['dependencies'][0]['dependency_kind']==='UNKNOWN','classification unknown without root');

t($r['dependencies'][2]['scope']==='development','dev scope preserved');

$r = deps_assess(lock([pkg('acme/widget','1.2.0')]), dataset([adv('acme/widget',['>=1.0.0,<2.0.0'],null,'A1'),adv('acme/widget',['=1.2.0'],null,'A2')]));
t(count($r['dependencies'][0]['matched_advisories'])===2,'multiple advisories preserved');

$r = deps_assess(lock([pkg('acme/widget','1.2.0')]), dataset([adv('acme/widget',['>=1.0.0,<2.0.0'],'2026-01-01T00:00:00Z')]));
t(state($r,'acme/widget')==='NOT_KNOWN_AFFECTED','withdrawn advisory ignored as active evidence');

$r = deps_assess(lock([pkg('acme/widget','1.2.0')]), dataset([], false));
t(state($r,'acme/widget')==='UNKNOWN' && deps_exit_code($r)===3,'unavailable dataset unknown');

$r = deps_assess(lock([pkg('acme/widget','1.2.0')]), dataset([adv('acme/widget',['^1.0'])]));
t(state($r,'acme/widget')==='UNKNOWN' && !$r['assessment_complete'],'unsupported constraint unknown');

$r = deps_assess(lock([pkg('ACME/WIDGET','1.2.0')]), dataset([adv('acme/widget',['=1.2.0'])]));
t(state($r,'acme/widget')==='AFFECTED','case normalized');

$r = deps_assess(lock([pkg('acme/widget','dev-main')]), dataset([]));
t(state($r,'acme/widget')==='NOT_ASSESSABLE' && deps_exit_code($r)===3,'unnormalizable version');

$thrown=false; try { deps_assess(lock([pkg('acme/widget','1.0.0'),pkg('acme/widget','2.0.0')]), dataset([])); } catch (RuntimeException $e) { $thrown=true; }
t($thrown,'contradictory duplicates rejected');

$r = deps_assess(lock([pkg('acme/a','1.0.0'),pkg('acme/b','1.0.0')]), dataset([adv('acme/a',['=1.0.0']),adv('acme/b',['^1.0'])]));
t(state($r,'acme/a')==='AFFECTED' && state($r,'acme/b')==='UNKNOWN' && deps_exit_code($r)===3,'affected plus unknown precedence');

$r = deps_assess(lock(), dataset([]));
t($r['assessment_complete']===true && $r['summary']['assessed_dependencies']===0 && deps_exit_code($r)===0,'empty bounded assessment');

$tmp = sys_get_temp_dir() . '/cyse-deps-' . bin2hex(random_bytes(5)); mkdir($tmp);
$lp="$tmp/composer.lock"; $ap="$tmp/advisories.json"; $rp="$tmp/composer.json";
file_put_contents($lp,json_encode(lock([pkg('acme/widget','1.2.0')]))); file_put_contents($ap,json_encode(dataset([adv('acme/widget',['=1.2.0'])]))); file_put_contents($rp,json_encode(['require'=>['acme/widget'=>'*']]));
$before=[hash_file('sha256',$lp),hash_file('sha256',$ap),hash_file('sha256',$rp)];
ob_start(); $rc=deps_main(['cyse-deps','audit',$lp,'--advisories',$ap,'--root',$rp,'--json']); $json=ob_get_clean();
$after=[hash_file('sha256',$lp),hash_file('sha256',$ap),hash_file('sha256',$rp)];
t($rc===1,'CLI affected exit'); t($before===$after,'input immutability');
$j=json_decode($json,true); t(is_array($j) && $j['summary']['state_counts']['AFFECTED']===1,'JSON projection');
$human=deps_render_human($j); t(str_contains($human,'AFFECTED=1') && str_contains($human,'NOT_KNOWN_AFFECTED is not SAFE'),'human semantic parity/boundary');
@unlink($lp);@unlink($ap);@unlink($rp);@rmdir($tmp);

echo "OK: dependency auditor tests passed\n";
