<?php

declare(strict_types=1);

namespace Arris\Auth\Mailer;

/**
 * No-op mailer used when no mailer is configured.
 *
 * No-op мэйлер, используемый когда мэйлер не задан.
 */
final class NullMailer implements MailerInterface
{
    public function send(
        string $to,
        string $subject = '',
        string $body = '',
        string $alternative_body = '',
        ?string $from = null,
        ?string $fromName = null,
    ): bool {
        return true;
    }

    public function sendPasswordReset(string $email, string $resetKey): bool
    {
        return true;
    }

    public function sendActivation(string $email, string $activationKey): bool
    {
        return true;
    }
}
