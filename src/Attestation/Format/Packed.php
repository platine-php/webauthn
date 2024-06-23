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
 * @class Packed
 * @package Platine\Webauthn\Attestation\Format
 */
class Packed extends BaseFormat
{
    /**
     * The algorithm used
     * @var int
     */
    protected int $algo;

    /**
     * The signature
     * @var string
     */
    protected string $signature;

    /**
     * The X5C information
     * @var string
     */
    protected string $x5c = '';

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
            ! array_key_exists('alg', $attestationStatement) ||
            $this->getCoseAlgorithm($attestationStatement['alg']) === null
        ) {
            throw new WebauthnException(sprintf(
                'Unsupported algorithm [%d]',
                $attestationStatement['alg']
            ));
        }

        if (
            ! array_key_exists('sig', $attestationStatement) ||
            ! $attestationStatement['sig'] instanceof ByteBuffer
        ) {
            throw new WebauthnException('No signature found');
        }

        $this->algo = $attestationStatement['alg'];
        $this->signature = $attestationStatement['sig']->getBinaryString();

        if (
            array_key_exists('x5c', $attestationStatement) &&
            is_array($attestationStatement['x5c']) &&
            count($attestationStatement['x5c']) > 0
        ) {
            // The attestation certificate attestnCert MUST be the first element in the array
            $attestCert = array_shift($attestationStatement['x5c']);
            if (! $attestCert instanceof ByteBuffer) {
                throw new WebauthnException('Invalid X5C certificate');
            }

            $this->x5c = $attestCert->getBinaryString();

            // Certificate chains
            foreach ($attestationStatement['x5c'] as $chain) {
                if ($chain instanceof ByteBuffer) {
                    $this->x5cChain[] = $chain->getBinaryString();
                }
            }
        }
    }

    /**
    * {@inheritdoc}
    */
    public function getCertificatePem(): ?string
    {
        if (empty($this->x5c)) {
            return null;
        }

        return $this->createCertificatePem($this->x5c);
    }

    /**
    * {@inheritdoc}
    */
    public function validateAttestation(string $clientData): bool
    {
        if (! empty($this->x5c)) {
            return $this->validateOverX5C($clientData);
        }

        return $this->validateSelfAttestation($clientData);
    }

    /**
    * {@inheritdoc}
    */
    public function validateRootCertificate(array $rootCertificates): bool
    {
        if (empty($this->x5c)) {
            return false;
        }

        $chain = $this->createX5cChainFile();
        if ($chain !== null) {
            $rootCertificates[] = $chain;
        }

        $value = openssl_x509_checkpurpose(
            // TODO phpstan complains so cast to string
            (string) $this->getCertificatePem(),
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

    /**
     * Validate if x5c is present
     * @param string $clientData
     * @return bool
     */
    protected function validateOverX5C(string $clientData): bool
    {
        // TODO phpstan complains so cast to string
        $publicKey = openssl_pkey_get_public((string) $this->getCertificatePem());

        if ($publicKey === false) {
            throw new WebauthnException(sprintf(
                'Invalid public key used, error: [%s]',
                openssl_error_string()
            ));
        }

        // Verify that sig is a valid signature over the concatenation of authenticatorData
        // and clientDataHash using the attestation public key in attestnCert
        // with the algorithm specified in alg.
        $dataToVerify = $this->authenticatorData->getBinary();
        $dataToVerify .= $clientData;

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
     * Validate if self attestation is used
     * @param string $clientData
     * @return bool
     */
    protected function validateSelfAttestation(string $clientData): bool
    {
        // Verify that sig is a valid signature over the concatenation of authenticatorData
        // and clientDataHash using the credential public key with alg.
        $dataToVerify = $this->authenticatorData->getBinary();
        $dataToVerify .= $clientData;

        $publicKey = $this->authenticatorData->getPublicKeyPEM();

        return openssl_verify(
            $dataToVerify,
            $this->signature,
            $publicKey,
            OPENSSL_ALGO_SHA256
        ) === 1;
    }
}
