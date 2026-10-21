<?php
declare(strict_types=1);

namespace Sentinel;

final class Alerter
{
    /** @var Channel[] */
    private $channels;

    /** @param Channel[] $channels */
    public function __construct(array $channels)
    {
        $this->channels = $channels;
    }

    /** @return array{ok: bool, results: string[], attempted: int} */
    public function send(string $subject, string $body, int $topSeverity, ?array $attachment = null): array
    {
        $results = [];
        $attempted = 0;
        $succeeded = 0;
        foreach ($this->channels as $ch) {
            if ($topSeverity < $ch->minSeverity) {
                continue;
            }
            $attempted++;
            try {
                $ch->notifier->send($subject, $body, $topSeverity, $attachment);
                $results[] = $ch->notifier->name() . ': sent';
                $succeeded++;
            } catch (\Throwable $e) {
                $results[] = $ch->notifier->name() . ': FAILED - ' . $e->getMessage();
            }
        }
        return ['ok' => $attempted === 0 || $succeeded > 0, 'results' => $results, 'attempted' => $attempted];
    }
}
