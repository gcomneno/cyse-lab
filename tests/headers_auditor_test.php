<?php
declare(strict_types=1);
require __DIR__.'/../src/cyse_headers.php';
function check(bool $x,string $m):void{if(!$x)throw new RuntimeException($m);}
function statuses(array $h,string $url='https://example.test/'):array{$r=evaluate(['final_url'=>$url,'headers'=>norm($h)]);$o=[];foreach($r as $f)$o[$f['id']]=$f['status'];return $o;}
$s=statuses([]);check($s['hsts']==='FAIL','missing HSTS');check($s['csp']==='FAIL','missing CSP');check($s['nosniff']==='FAIL','missing nosniff');
$s=statuses(['Strict-Transport-Security'=>'max-age=31536000','Content-Security-Policy'=>"default-src 'self'",'X-Content-Type-Options'=>'NoSniff','X-Frame-Options'=>'SAMEORIGIN','Referrer-Policy'=>'strict-origin-when-cross-origin','Permissions-Policy'=>'camera=()']);foreach($s as $id=>$v)check($v==='PASS',"$id should pass");
$s=statuses(['Strict-Transport-Security'=>'max-age=0','Content-Security-Policy'=>'','X-Content-Type-Options'=>'wat','X-Frame-Options'=>'ALLOWALL','Referrer-Policy'=>'unsafe-url','Permissions-Policy'=>'']);check($s['hsts']==='WEAK','weak HSTS');check($s['nosniff']==='WEAK','weak nosniff');
$s=statuses(['Strict-Transport-Security'=>'nonsense','Referrer-Policy'=>'future-policy']);check($s['hsts']==='UNKNOWN','unknown HSTS');check($s['referrer']==='UNKNOWN','unknown referrer');
$s=statuses([], 'http://example.test/');check($s['hsts']==='NOT_APPLICABLE','HTTP HSTS N/A');
check(hv(norm(['X-CONTENT-TYPE-OPTIONS'=>'nosniff']),'x-content-type-options')==='nosniff','case insensitive names');
check(main(['x','audit','example.test'])===2,'bare host rejected');
echo "OK: headers auditor tests passed\n";
