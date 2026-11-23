# Подтверждение регистрации, сброс пароля, троттлинг

Таблицы `users_confirmations`, `users_resets`, `users_throttling`
оставлены в схеме для совместимости, но подтверждение email, сброс пароля и throttling
пока не реализованы. Их можно добавить отдельными методами, не меняя ядро.

# Кастомные валидаторы (пароль, мыло)

Добавлены методы в конструктор, но они нигде не вызываются.

## EMailValidator

Для валидатора емейла: https://github.com/PHPAuth/PHPAuth.EMailValidator

```php
use PHPAuth\EMailValidator;

$config = $config->setEmailValidator(static function ($email) {
    return \PHPAuth\EMailValidator::isValid($email);
});
```

```php
// composer require fgribreau/mailchecker (NB: 5* branch does not use namespaces)
$config = $config->setEMailValidator(static function ($email) {
    return MailChecker::isValid($email);
});
```

Internal (todo):

```php
if (is_callable($this->emailValidator) && !call_user_func_array($this->emailValidator, [ $email ])) {
    $this->addAttempt();
    $state['message'] = $this->__lang('email.address_in_banlist');

    return $state;
}
```

## Password Validator (setPasswordValidator())

```php
$config = $config->setPasswordValidator(static function($password) {
    $password_min_score = 3; // Minimum strength threshold
    // using "bjeavons/zxcvbn-php" library
    return (bool)((new Zxcvbn())->passwordStrength($password)['score'] >= $password_min_score);
});
```

internal (todo):

```php
private function isPasswordStrong(string $password): bool
{
    if (is_callable($this->passwordValidator)) {
        return ($this->passwordValidator)($password);
    }
    return true; // Default: always valid
}
```

# Mailer 

https://github.com/PHPAuth/PHPAuth/blob/master/README_CUSTOM_MAILER.md

