<?php

declare(strict_types=1);

namespace Arris\Auth\Mailer;

class NativeMailer implements MailerInterface
{
    private string $defaultFrom;
    private string $defaultFromName;
    private string $activationSubject;
    private string $activationBody;
    private string $resetSubject;
    private string $resetBody;

    /**
     * @param array{
     *     from?: string,
     *     from_name?: string,
     *     activation_subject?: string,
     *     activation_body?: string,
     *     reset_subject?: string,
     *     reset_body?: string
     * } $config
     */
    public function __construct(array $config = [])
    {
        $this->defaultFrom = $config['from'] ?? 'noreply@example.com';
        $this->defaultFromName = $config['from_name'] ?? 'Arris.Auth';
        $this->activationSubject = $config['activation_subject'] ?? 'Confirm your email address';
        $this->activationBody = $config['activation_body'] ?? 'Activation key: {activation_key}';
        $this->resetSubject = $config['reset_subject'] ?? 'Reset your password';
        $this->resetBody = $config['reset_body'] ?? 'Password reset key: {reset_key}';
    }

    /**
     * Sends an HTML email using PHP mail().
     *
     * Отправляет HTML-письмо через PHP mail().
     *
     * @param string $to
     * @param string $subject
     * @param string $body
     * @param string $alternative_body
     * @param string|null $from
     * @param string|null $fromName
     *
     * @return bool
     */
    public function send(
        string $to,
        string $subject = '',
        string $body = '',
        string $alternative_body = '',
        ?string $from = null,
        ?string $fromName = null,
    ): bool {
        $from = $from ?? $this->defaultFrom;
        $fromName = $fromName ?? $this->defaultFromName;

        $headers = [
            'MIME-Version: 1.0',
            'Content-type: text/html; charset=utf-8',
            'From: ' . $this->headerValue($fromName) . ' <' . $this->headerValue($from) . '>',
            'X-Mailer: PHP/' . phpversion(),
        ];

        return mail(
            $this->headerValue($to),
            $this->headerValue($subject),
            $body,
            implode("\r\n", $headers)
        );
    }

    /**
     * Sends a password reset email.
     *
     * Отправляет письмо для сброса пароля.
     */
    public function sendPasswordReset(string $email, string $resetKey): bool
    {
        $body = str_replace(
            '{reset_key}',
            htmlspecialchars($resetKey, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8'),
            $this->resetBody
        );

        return $this->send($email, $this->resetSubject, $body);
    }

    /**
     * Sends an activation email with the confirmation token.
     *
     * Отправляет письмо активации с confirmation-токеном.
     */
    public function sendActivation(string $email, string $activationKey): bool
    {
        $body = str_replace(
            '{activation_key}',
            htmlspecialchars($activationKey, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8'),
            $this->activationBody
        );

        return $this->send($email, $this->activationSubject, $body);
    }

    /**
     * Strips CR/LF from header values to prevent header injection.
     *
     * Удаляет CR/LF из значений заголовков для защиты от header injection.
     */
    private function headerValue(string $value): string
    {
        return \str_replace(["\r", "\n"], '', $value);
    }
}
