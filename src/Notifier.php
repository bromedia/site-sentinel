<?php
declare(strict_types=1);

namespace Sentinel;

interface Notifier
{
    public function name(): string;

    /**
     * @param array{name:string, path:string, content:string}|null $attachment the full report (Report::attachment)
     * @throws \RuntimeException when the message could not be delivered
     */
    public function send(string $subject, string $body, int $severity, ?array $attachment = null): void;
}

/** What the channels that cannot carry a file say instead. */
final class AttachmentNote
{
    /** $attachment['path'] is the relative display path, never an absolute one. */
    public static function pointer(array $attachment): string
    {
        return 'Full report saved on the server: ' . $attachment['path'];
    }
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
