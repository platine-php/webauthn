<?php

declare(strict_types=1);

namespace Platine\Webauthn\Enum;

/**
 * @class UserVerificationType
 * @package Platine\Webauthn\Enum
 */
class UserVerificationType extends BaseEnum
{
    public const REQUIRED = 'required';
    public const PREFERRED = 'preferred';
    public const DISCOURAGED = 'discouraged';
}
