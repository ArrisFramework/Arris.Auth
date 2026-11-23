<?php

declare(strict_types=1);

namespace Tests\Support;

use Arris\Auth\Mailer\MailerInterface;

final class RecordingMailer implements MailerInterface
{
    /** @var list<array{email: string, key: string}> */
    public array $activations = [];

    /** @var list<array{email: string, key: string}> */
    public array $resets = [];

    public bool $result = true;

    public function send(
        string $to,
        string $subject = '',
        string $body = '',
        string $alternative_body = '',
        ?string $from = null,
        ?string $fromName = null,
    ): bool {
        return $this->result;
    }

    public function sendPasswordReset(string $email, string $resetKey): bool
    {
        $this->resets[] = ['email' => $email, 'key' => $resetKey];

        return $this->result;
    }

    public function sendActivation(string $email, string $activationKey): bool
    {
        $this->activations[] = ['email' => $email, 'key' => $activationKey];

        return $this->result;
    }
}
