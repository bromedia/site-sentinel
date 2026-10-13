<?php
declare(strict_types=1);

namespace Sentinel;

interface Notifier
{
    public function name(): string;

    /** @throws \RuntimeException when the message could not be delivered */
    public function send(string $subject, string $body, int $severity): void;
}

final class Channel
{
    public $notifier;
    public $minSeverity;

    public function __construct(Notifier $notifier, int $minSeverity)
    {
        $this->notifier = $notifier;
        $this->minSeverity = $minSeverity;
    }
}
