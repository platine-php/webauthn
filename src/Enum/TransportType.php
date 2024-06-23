<?php

declare(strict_types=1);

namespace Platine\Webauthn\Enum;

/**
 * @class TransportType
 * @package Platine\Webauthn\Enum
 */
class TransportType extends BaseEnum
{
    public const NFC = 'nfc';
    public const BLE = 'ble';
    public const USB = 'usb';
    public const INTERNAL = 'internal';
}
