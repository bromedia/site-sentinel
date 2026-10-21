<?php
declare(strict_types=1);

final class FakeNotifier implements \Sentinel\Notifier
{
    /** @var array<int,array{subject:string,body:string,severity:int,attachment:?array}> */
    public $sent = [];
    public $fail = false;
    private $name;

    public function __construct(string $name = 'fake')
    {
        $this->name = $name;
    }

    public function name(): string
    {
        return $this->name;
    }

    public function send(string $subject, string $body, int $severity, ?array $attachment = null): void
    {
        if ($this->fail) {
            throw new RuntimeException('simulated failure');
        }
        $this->sent[] = ['subject' => $subject, 'body' => $body, 'severity' => $severity, 'attachment' => $attachment];
    }
}

/** A controllable clock: $c->t += 86400; pass $c wherever a callable returning int is expected. */
final class FakeClock
{
    public $t = 1760000000;

    public function __invoke(): int
    {
        return $this->t;
    }
}
