<?php
declare(strict_types=1);
namespace Sentinel;
final class InitScan
{
    public static function run(Config $c, State $state, Analyzer $analyzer, string $script, bool $force, bool $restart, Budget $budget): array
    {
        $file = $state->path('baseline.init');
        $journal = $state->path('init-progress.json');
        if ($restart) { @unlink($file); @unlink($journal); }
        $fingerprint = hash('sha256', (string)json_encode($c->toArray()) . ($force ? 'force' : '') . (string)hash_file('sha256', $script));
        $progress = $state->readJson('init-progress.json');
        if ($progress && ($progress['fingerprint'] ?? '') !== $fingerprint) {
            throw new \RuntimeException('unfinished init used different settings or script; repeat its original command or use init --restart');
        }
        $offset = (int)($progress['offset'] ?? 0);
        if ($offset > 0 && (!is_file($file) || filesize($file) < $offset)) { throw new \RuntimeException('unfinished init data is missing; use init --restart'); }
        $fh = fopen($file, 'c+b');
        if ($fh === false) { throw new \RuntimeException('cannot write initial baseline'); }
        @chmod($file, 0600);
        $findings = [];
        foreach ((array)($progress['findings'] ?? []) as $f) { $findings[] = new Finding((int)$f['severity'], $f['path'], $f['rule'], $f['message'], $f['hash']); }
        $notes = (array)($progress['notes'] ?? []);
        $symlinks = (array)($progress['symlinks'] ?? []);
        $count = (int)($progress['count'] ?? 0);
        $last = (string)($progress['last'] ?? '');
        $walker = new Walker($c);
        $differ = new Differ($c);
        $complete = true;
        $processed = 0;
        try {
            if (!ftruncate($fh, $offset) || fseek($fh, $offset) !== 0) { throw new \RuntimeException('cannot resume initial baseline'); }
            foreach ($walker->walk($last) as $meta) {
                if ($processed > 0 && $budget->exceeded()) { $complete = false; break; }
                [$rec, $unreadable] = $differ->record($meta);
                if ($unreadable) { throw new \RuntimeException('initial scan cannot read code; correct permissions and use init --restart'); }
                if (($rec['mode'] & 0170000) === 0120000 && is_dir($c->abs($rec['path'])) && count($symlinks) < 100) { $symlinks[] = [$rec['path'], (string)readlink($c->abs($rec['path']))]; }
                if ($analyzer->wantsAnalysis($rec)) {
                    $change = ['type'=>'new','path'=>$rec['path'],'old'=>null,'new'=>$rec,'stealth'=>false,'content_same'=>false,'unreadable'=>false];
                    $a = $analyzer->analyze([$change], [], [], true, 0, $budget);
                    $findings = array_slice(array_merge($findings, $a['findings']), 0, 100);
                    $notes = array_slice(array_unique(array_merge($notes, $a['notes'])), 0, 100);
                    if ($findings && !$force) { break; }
                }
                $line = Baseline::formatLine($rec);
                if (fwrite($fh, $line) !== strlen($line)) { throw new \RuntimeException('cannot finish initial baseline'); }
                $last = $rec['path']; $count++; $processed++;
            }
            if ($walker->unreadable()) { throw new \RuntimeException('initial scan cannot read a directory; correct permissions and use init --restart'); }
            fflush($fh);
            $state->writeJson('init-progress.json', ['fingerprint'=>$fingerprint,'offset'=>ftell($fh),'last'=>$last,'count'=>$count,'findings'=>$findings,'notes'=>$notes,'symlinks'=>$symlinks]);
        } finally { fclose($fh); }
        return ['complete'=>$complete,'count'=>$count,'findings'=>$findings,'notes'=>$notes,'symlinks'=>$symlinks];
    }
}
