<?php
declare(strict_types=1);

namespace Sentinel;

final class Alerter
{
    /** @var Channel[] */
    private $channels;

    /** @var callable|null */
    private $scrub;

    /**
     * @param Channel[] $channels
     * @param callable|null $scrub Applied to the subject, the body and the attachment's texts
     *                             before they are sent (see Report::pathScrubber)
     */
    public function __construct(array $channels, ?callable $scrub = null)
    {
        $this->channels = $channels;
        $this->scrub = $scrub;
    }

    private function clean(string $text): string
    {
        return self::scrubbed($this->scrub, $text);
    }

    /** The text cleaned by the scrubber; if that fails in any way, as it was: an alert is never lost to it. */
    public static function scrubbed(?callable $scrub, string $text): string
    {
        if ($scrub === null || $text === '') {
            return $text;
        }
        try {
            $r = $scrub($text);
            return is_string($r) && $r !== '' ? $r : $text;
        } catch (\Throwable $e) {
            return $text;
        }
    }

    /** @return array{ok: bool, results: string[], attempted: int, delivered: string[]} delivered: names of the channels that sent it */
    public function send(string $subject, string $body, int $topSeverity, ?array $attachment = null): array
    {
        if ($this->scrub !== null) {
            $subject = $this->clean($subject);
            $body = $this->clean($body);
            if ($attachment !== null) {
                foreach (['content', 'body'] as $key) {
                    if (isset($attachment[$key])) {
                        $attachment[$key] = $this->clean((string)$attachment[$key]);
                    }
                }
            }
        }
        $results = [];
        $attempted = 0;
        $succeeded = 0;
        $delivered = [];
        foreach ($this->channels as $ch) {
            if ($topSeverity < $ch->minSeverity) {
                continue;
            }
            $attempted++;
            try {
                $ch->notifier->send($subject, $body, $topSeverity, $attachment);
                $results[] = $ch->notifier->name() . ': sent';
                $succeeded++;
                $delivered[] = $ch->notifier->name();
            } catch (\Throwable $e) {
                $results[] = $ch->notifier->name() . ': FAILED - ' . $e->getMessage();
            }
        }
        return ['ok' => $attempted === 0 || $succeeded > 0, 'results' => $results, 'attempted' => $attempted, 'delivered' => $delivered];
    }
}
