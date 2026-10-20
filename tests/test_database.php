<?php
declare(strict_types=1);
final class ArrayDatabase implements Sentinel\DatabaseSource
{
    public $data=['admins'=>['1'=>'admin-hash'],'options'=>['siteurl'=>'url-hash']]; public $rows=[]; public $error=false;
    public function snapshot():array{if($this->error){throw new RuntimeException('SECRET-PASSWORD SELECT private_content');}return $this->data;}
    public function posts(int $after,int $limit):array{return array_slice(array_values(array_filter($this->rows,function($r)use($after){return $r['id']>$after;})),0,$limit);}
    public function postStats(int $after):array{$r=array_filter($this->rows,function($r)use($after){return $r['id']>$after;});return ['new_count'=>count($r),'max_id'=>$r?max(array_column($r,'id')):$after];}
}
function databaseFixture():array{
    $c=makeConfig(tmpdir(),['profile'=>'wordpress','database'=>['enabled'=>true,'batch_size'=>1,'new_post_threshold'=>2]]);
    $state=new Sentinel\State($c->stateDir); $source=new ArrayDatabase();$n=new FakeNotifier();$clock=new FakeClock();
    $db=new Sentinel\DatabaseMonitor($c,$state,[new Sentinel\Channel($n,Sentinel\Finding::WARNING)],$clock,$source);
    assertSame(0,$db->accept(bigBudget(),'all',true)['exit']);return [$c,$state,$source,$n,$db,$clock];
}
t('WordPress credential parsing reads literals without executing configuration',function(){
    $root=tmpdir();$marker=$root.'/must-not-exist';
    $code="<?php define('DB_NAME','wordpress'); define('DB_USER','reader'); define('DB_PASSWORD','pa\\'ss\\\\word'); define('DB_HOST','localhost:3307'); \$table_prefix='ae_'; file_put_contents(".var_export($marker,true).",'executed'); require 'wp-settings.php';";
    putFile($root,'wp-config.php',$code);$c=makeConfig($root,['profile'=>'wordpress','database'=>['enabled'=>true]]);
    $r=Sentinel\DatabaseCredentials::load($c);assertSame("pa'ss\\word",$r['password']);assertSame('ae_',$r['table_prefix']);assertSame(3307,$r['port']);assertTrue(!file_exists($marker));
    assertTrue(!isset(Sentinel\DatabaseCredentials::parseWordPress("<?php define('DB_PASSWORD',getenv('SECRET'));")['password']));
    assertThrows(Sentinel\DatabaseException::class,function(){Sentinel\DatabaseCredentials::parseWordPress("<?php define('DB_USER','a'); define('DB_USER','b');");});
});
t('Database settings reject oversized batches and unsafe prefixes',function(){
    assertThrows(Sentinel\ConfigException::class,function(){makeConfig(tmpdir(),['database'=>['enabled'=>true]]);});
    assertThrows(Sentinel\ConfigException::class,function(){makeConfig(tmpdir(),['database'=>['batch_size'=>100,'max_post_bytes'=>1048576]]);});
    $file=putFile(tmpdir(),'credentials.json',json_encode(['host'=>'localhost','name'=>'test','user'=>'u','password'=>'secret','table_prefix'=>'wp_;DROP TABLE users']));
    $c=makeConfig(tmpdir(),['profile'=>'wordpress','database'=>['enabled'=>true,'credentials_file'=>$file]]);
    assertThrows(Sentinel\DatabaseException::class,function()use($c){Sentinel\DatabaseCredentials::load($c);});
});
t('Database administrator and option changes stay held until scoped acceptance',function(){
    [,$state,$source,$n,$db]=databaseFixture();assertSame(0,$db->check(bigBudget())['exit']);
    $source->data['admins']['2']='rogue-hash';$source->data['options']['siteurl']='changed-hash';assertSame(1,$db->check(bigBudget())['exit']);
    assertContains('db-admin-change',$n->sent[0]['body']);assertContains('db-option-change',$n->sent[0]['body']);$db->check(bigBudget());assertSame(1,count($n->sent));
    $db->accept(bigBudget(),'admins');$r=$db->check(bigBudget());assertSame(1,$r['exit']);assertNotContains('db-admin-change',implode("\n",$r['lines']));
    $db->accept(bigBudget(),'options');assertSame(0,$db->check(bigBudget())['exit']);
});
t('Database post scans resume, detect suspicious content and bursts, and preserve privacy',function(){
    [,$state,$source,$n,$db]=databaseFixture();
    $source->rows=[['id'=>10,'title'=>'Private title','content'=>'normal','bytes'=>6],['id'=>11,'title'=>'Secret title','content'=>'online casino <script src="private-url">','bytes'=>40]];
    $r=$db->check(new Sentinel\Budget(0,1));assertSame(10,$state->readJson('database-progress.json')['post_cursor']);assertContains('db-post-burst',implode("\n",$r['lines']));
    $r=$db->check(new Sentinel\Budget(0,1));assertContains('db-post-spam',implode("\n",$r['lines']));assertContains('db-post-code',implode("\n",$r['lines']));
    $db->check(bigBudget());assertSame(0,$state->readJson('database-progress.json')['post_cursor']);
    $all=json_encode($n->sent);foreach(glob($state->dir().'/*')as$file){$all.=file_get_contents($file);}
    foreach(['Private title','Secret title','private-url','online casino']as$secret){assertNotContains($secret,$all);}
});
t('Database delivery failures retry cursors and error messages withhold secrets',function(){
    [,$state,$source,$n,$db]=databaseFixture();$source->rows=[['id'=>4,'title'=>'','content'=>'online casino','bytes'=>13]];$n->fail=true;
    $db->check(new Sentinel\Budget(0,1));assertSame([],$state->readJson('database-progress.json'));$n->fail=false;$db->check(new Sentinel\Budget(0,1));assertSame(4,$state->readJson('database-progress.json')['post_cursor']);
    $source->error=true;$r=$db->check(bigBudget());assertSame(2,$r['exit']);assertNotContains('SECRET-PASSWORD',json_encode([$r,$n->sent,$state->readJson('status.json')]));assertNotContains('SELECT private_content',json_encode([$r,$n->sent]));
});
t('Database checks refuse to auto-trust a missing baseline',function(){
    [,$state,,,$db]=databaseFixture();unlink($state->path('database-baseline.json'));$r=$db->check(bigBudget());assertSame(2,$r['exit']);assertContains('db-init',implode("\n",$r['lines']));assertTrue(!is_file($state->path('database-baseline.json')));
});
