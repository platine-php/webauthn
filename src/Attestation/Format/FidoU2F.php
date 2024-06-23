<?php

/**
 * Platine Webauth
 *
 * Platine Webauthn is the implementation of webauthn specifications
 *
 * This content is released under the MIT License (MIT)
 *
 * Copyright (c) 2020 Platine Webauth
 * Copyright (c) Jakob Bennemann <github@jakob-bennemann.de>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

declare(strict_types=1);

namespace Platine\Webauthn\Attestation\Format;

use Platine\Webauthn\Attestation\AuthenticatorData;
use Platine\Webauthn\Exception\WebauthnException;
use Platine\Webauthn\Helper\ByteBuffer;

/**
 * @class FidoU2F
 * @package Platine\Webauthn\Attestation\Format
 */
class FidoU2F extends BaseFormat
{
    /**
     * The algorithm used
     * @var int
     */
    protected int $algo = -7;

    /**
     * The signature
     * @var string
     */
    protected string $signature;

    /**
     * The X5C information
     * @var string
     */
    protected string $x5c;

    /**
     * Create new instance
     * @param array<string, mixed> $attestationData
     * @param AuthenticatorData $authenticatorData
     */
    public function __construct(
        array $attestationData,
        AuthenticatorData $authenticatorData
    ) {
        parent::__construct($attestationData, $authenticatorData);

        // check u2f data
        $attestationStatement = $this->attestationData['attStmt'];
        if (
            array_key_exists('alg', $attestationStatement) &&
            $attestationStatement['alg'] !== $this->algo
        ) {
            throw new WebauthnException(sprintf(
                'U2F only accepts algorithm -7 ("ES256"), got [%d]',
                $attestationStatement['alg']
            ));
        }

        if (
            ! array_key_exists('sig', $attestationStatement) ||
            ! $attestationStatement['sig'] instanceof ByteBuffer
        ) {
            throw new WebauthnException('No signature found');
        }

        if (
            ! array_key_exists('x5c', $attestationStatement) ||
            ! is_array($attestationStatement['x5c']) ||
            count($attestationStatement['x5c']) !== 1
        ) {
            throw new WebauthnException('Invalid X5C certificate');
        }

        if (! $attestationStatement['x5c'][0] instanceof ByteBuffer) {
            throw new WebauthnException('Invalid X5C certificate');
        }

        $this->signature = $attestationStatement['sig']->getBinaryString();
        $this->x5c = $attestationStatement['x5c'][0]->getBinaryString();
    }

    /**
    * {@inheritdoc}
    */
    public function getCertificatePem(): string
    {
        $pem = '-----BEGIN CERTIFICATE-----' . "\n";
        $pem .= chunk_split(base64_encode($this->x5c), 64, "\n");
        $pem = '-----END CERTIFICATE-----' . "\n";

        return $pem;
    }

    /**
    * {@inheritdoc}
    */
    public function validateAttestation(string $clientData): bool
    {
        $publicKey = openssl_pkey_get_public($this->getCertificatePem());

        if ($publicKey === false) {
            throw new WebauthnException(sprintf(
                'Invalid public key used, error: [%s]',
                openssl_error_string()
            ));
        }

        // Let verificationData be the concatenation of
        // (0x00 || rpIdHash || clientDataHash || credentialId || publicKeyU2F)
        $dataToVerify = "\x00";
        $dataToVerify .= $this->authenticatorData->getRelyingPartyIdHash();
        $dataToVerify .= $clientData;
        $dataToVerify .= $this->authenticatorData->getCredentialId();
        $dataToVerify .= $this->authenticatorData->getPublicKeyU2F();

        $coseAlgo = $this->getCoseAlgorithm($this->algo);
        if ($coseAlgo === null) {
            throw new WebauthnException(sprintf(
                'Invalid algorithm [%d]',
                $this->algo
            ));
        }

        return openssl_verify(
            $dataToVerify,
            $this->signature,
            $publicKey,
            $coseAlgo['openssl']
        ) === 1;
    }

    /**
    * {@inheritdoc}
    */
    public function validateRootCertificate(array $rootCertificates): bool
    {
        $chain = $this->createX5cChainFile();
        if ($chain !== null) {
            $rootCertificates[] = $chain;
        }

        $value = openssl_x509_checkpurpose(
            $this->getCertificatePem(),
            -1,
            $rootCertificates
        );

        if ($value === -1) {
            throw new WebauthnException(sprintf(
                'Error when validate root certificate, error message: [%s]',
                openssl_error_string()
            ));
        }

        // TODO phpstan complains so cast to bool
        return (bool) $value;
    }
}
