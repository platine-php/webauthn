<?php

declare(strict_types=1);

namespace Platine\Webauthn;

use Platine\Stdlib\Config\AbstractConfiguration;

/**
 * @class WebauthnConfiguration
 * @package Platine\Webauthn
 */
class WebauthnConfiguration extends AbstractConfiguration
{
    /**
     * {@inheritdoc}
     */
    public function getValidationRules(): array
    {
        return [
            'reply_party_id' => 'string',
            'reply_party_name' => 'string',
            'reply_party_logo' => 'string',
            'timeout' => 'integer',
            'challenge_length' => 'integer',
            'transport_types' => 'array',
            'ignore_origins' => 'array',
        ];
    }

    /**
     * {@inheritdoc}
     */
    public function getDefault(): array
    {
        return [
            'reply_party_id' => 'localhost',
            'reply_party_name' => 'Platine App',
            'reply_party_logo' => '',
            'timeout' => 60,
            'challenge_length' => 32,
            'transport_types' => [
                'internal'
            ],
            'ignore_origins' => [
                'localhost'
            ],
        ];
    }
}
