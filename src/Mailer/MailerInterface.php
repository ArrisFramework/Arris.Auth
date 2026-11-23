<?php

namespace Arris\Auth\Mailer;

interface MailerInterface
{
    /**
     * Отправка email
     *
     * @param string $to Email получателя
     * @param string $subject Тема письма
     * @param string $body Тело письма (HTML)
     * @param string|null $from Email отправителя (опционально)
     * @param string|null $fromName Имя отправителя (опционально)
     * @return bool Успешность отправки
     */
    public function send(string $to, string $subject = '', string $body = '', string $alternative_body = '', ?string $from = null, ?string $fromName = null): bool;

    /**
     * Отправка письма для сброса пароля.
     *
     * @param string $email
     * @param string $resetKey
     * @return bool
     */
    public function sendPasswordReset(string $email, string $resetKey): bool;

    /**
     * Отправка письма активации.
     * $activationKey — opaque-токен, который затем передаётся в Auth::confirmUser().
     *
     * @param string $email
     * @param string $activationKey
     * @return bool
     */
    public function sendActivation(string $email, string $activationKey): bool;
}