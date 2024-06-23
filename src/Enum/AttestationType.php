<?php

declare(strict_types=1);

namespace Platine\Webauthn\Enum;

/**
 * @class AttestationType
 * @package Platine\Webauthn\Enum
 */
class AttestationType extends BaseEnum
{
    public const NONE = 'none';
    public const DIRECT = 'direct';
    public const INDIRECT = 'indirect';
}
