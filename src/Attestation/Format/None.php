<?php

declare(strict_types=1);

namespace Platine\Webauthn\Attestation\Format;

/**
 * @class None
 * @package Platine\Webauthn\Attestation\Format
 */
class None extends BaseFormat
{
    /**
    * {@inheritdoc}
    */
    public function validateAttestation(string $clientData): bool
    {
        return true;
    }
}
