<?php

declare(strict_types=1);

namespace Platine\Webauthn\Enum;

/**
 * @class KeyFormat
 * @package Platine\Webauthn\Enum
 */
class KeyFormat extends BaseEnum
{
    public const ANDROID_KEY = 'android-key';
    public const ANDROID_SAFETYNET = 'android-safetynet';
    public const APPLE = 'apple';
    public const FIDO_U2FA = 'fido-u2fa';
    public const NONE = 'none';
    public const PACKED = 'packed';
    public const TPM = 'tpm';
}
