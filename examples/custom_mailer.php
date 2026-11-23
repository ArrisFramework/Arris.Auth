<?php

declare(strict_types=1);

use Arris\Auth\Mailer\MailerInterface;
use Arris\Auth\Mailer\NativeMailer;

/**
 * Example mailer that turns activation/reset tokens into clickable links.
 *
 * Пример мэйлера, который превращает activation/reset-токены в кликабельные ссылки.
 */
final class LinkMailer implements MailerInterface
{
    public function __construct(
        private readonly NativeMailer $transport,
        private readonly string $confirmUrl = 'https://app.example.com/confirm',
        private readonly string $resetUrl = 'https://app.example.com/reset',
    ) {
    }

    public function send(
        string $to,
        string $subject = '',
        string $body = '',
        string $alternative_body = '',
        ?string $from = null,
        ?string $fromName = null,
    ): bool {
        return $this->transport->send($to, $subject, $body, $alternative_body, $from, $fromName);
    }

    public function sendActivation(string $email, string $activationKey): bool
    {
        $url = $this->confirmUrl . '?token=' . \rawurlencode($activationKey);

        return $this->send(
            $email,
            'Confirm your email address',
            '<p>Confirm your email address:</p><p><a href="' . \htmlspecialchars($url, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') . '">Confirm email</a></p>'
        );
    }

    public function sendPasswordReset(string $email, string $resetKey): bool
    {
        $url = $this->resetUrl . '?token=' . \rawurlencode($resetKey);

        return $this->send(
            $email,
            'Reset your password',
            '<p>Reset your password:</p><p><a href="' . \htmlspecialchars($url, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') . '">Reset password</a></p>'
        );
    }
}

/*
Usage:

$config->setMailer(new LinkMailer(
    new NativeMailer(['from' => 'noreply@example.com'])
));

The application routes are then:

GET /confirm?token=...  -> $auth->confirmUser($_GET['token'])
GET /reset?token=...    -> render a form; on POST:
                           $auth->resetPassword($_POST['token'], $_POST['password'])
*/
