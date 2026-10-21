<?php
declare(strict_types=1);

namespace Sentinel;

final class Proc
{
    /** False on hosts that list proc_open in disable_functions. */
    public static function available(): bool
    {
        return function_exists('proc_open');
    }

    /**
     * Runs a command (argument array, no shell) with a timeout.
     *
     * @return array{exit:int, out:string, err:string, timed_out:bool}
     */
    public static function run(array $cmd, int $timeout): array
    {
        if (!self::available()) {
            return ['exit' => -1, 'out' => '', 'err' => 'proc_open is disabled on this host', 'timed_out' => false];
        }
        // stdin is a pipe closed straight away, not /dev/null: hosts that set open_basedir (xneelo's
        // php-wrapper does) refuse to open /dev/null, and then no command can be started at all.
        $spec = [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']];
        $p = @proc_open($cmd, $spec, $pipes);
        if (!is_resource($p)) {
            return ['exit' => -1, 'out' => '', 'err' => 'cannot start ' . (string)($cmd[0] ?? ''), 'timed_out' => false];
        }
        fclose($pipes[0]);
        stream_set_blocking($pipes[1], false);
        stream_set_blocking($pipes[2], false);
        $out = '';
        $err = '';
        $exit = -1;
        $timedOut = false;
        $start = microtime(true);
        while (true) {
            $out .= (string)stream_get_contents($pipes[1]);
            $err .= (string)stream_get_contents($pipes[2]);
            $st = proc_get_status($p);
            if (!$st['running']) {
                $exit = (int)$st['exitcode'];
                break;
            }
            if (microtime(true) - $start > $timeout) {
                proc_terminate($p, 9);
                $timedOut = true;
                break;
            }
            usleep(20000);
        }
        $out .= (string)stream_get_contents($pipes[1]);
        $err .= (string)stream_get_contents($pipes[2]);
        fclose($pipes[1]);
        fclose($pipes[2]);
        proc_close($p);
        return ['exit' => $exit, 'out' => $out, 'err' => $err, 'timed_out' => $timedOut];
    }
}
