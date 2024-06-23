<?php

declare(strict_types=1);

namespace Platine\Webauthn\Enum;

use ReflectionClass;

/**
 * @class BaseEnum
 * @package Platine\Webauthn\Enum
 */
class BaseEnum
{
    /**
     * Return this class all the enumerations
     * @return array<string, string>
     */
    public static function all(): array
    {
        $reflection = new ReflectionClass(static::class);

        return $reflection->getConstants();
    }
}
