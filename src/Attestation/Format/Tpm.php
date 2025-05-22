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
 * @class Tpm
 * @package Platine\Webauthn\Attestation\Format
 */
class Tpm extends BaseFormat
{
    public const TPM_GENERATED_VALUE = "\xFF\x54\x43\x47";
    public const TPM_ST_ATTEST_CERTIFY = "\x80\x17";

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
     * The certificate information
     * @var ByteBuffer
     */
    protected ByteBuffer $certInfo;

    /**
     * The public area information
     * @var ByteBuffer
     */
    protected ByteBuffer $pubArea;


    /**
     * The X5C information
     * @var string
     */
    protected string $x5c = '';

    /**
     * Create new instance
     * @param array<string|int, mixed> $attestationData
     * @param AuthenticatorData $authenticatorData
     */
    public function __construct(
        array $attestationData,
        AuthenticatorData $authenticatorData
    ) {
        parent::__construct($attestationData, $authenticatorData);

        // check packed data
        $attestationStatement = $this->attestationData['attStmt'];

        if (
            ! array_key_exists('ver', $attestationStatement) ||
            $attestationStatement['ver'] !== '2.0'
        ) {
            throw new WebauthnException(sprintf(
                'Invalid TPM version [%s]',
                $attestationStatement['ver']
            ));
        }

        if (
            ! array_key_exists('alg', $attestationStatement) ||
            $this->getCoseAlgorithm($attestationStatement['alg']) === null
        ) {
            throw new WebauthnException(sprintf(
                'Unsupported algorithm provided, got [%d]',
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
            ! array_key_exists('certInfo', $attestationStatement) ||
            ! $attestationStatement['certInfo'] instanceof ByteBuffer
        ) {
            throw new WebauthnException('No certificate information found');
        }

        if (
            ! array_key_exists('pubArea', $attestationStatement) ||
            ! $attestationStatement['pubArea'] instanceof ByteBuffer
        ) {
            throw new WebauthnException('No public area information found');
        }

        $this->algo = $attestationStatement['alg'];
        $this->signature = $attestationStatement['sig']->getBinaryString();
        $this->certInfo = $attestationStatement['certInfo'];
        $this->pubArea = $attestationStatement['pubArea'];

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
        } else {
            throw new WebauthnException('Invalid X5C certificate');
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
        return $this->validateOverX5C($clientData);
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

         // Verify that magic is set to TPM_GENERATED_VALUE.
        if ($this->certInfo->getBytes(0, 4) !== self::TPM_GENERATED_VALUE) {
            throw new WebauthnException('TPM magic value not the same TPM_GENERATED_VALUE');
        }

        // Verify that type is set to TPM_ST_ATTEST_CERTIFY.
        if ($this->certInfo->getBytes(4, 2) !== self::TPM_ST_ATTEST_CERTIFY) {
            throw new WebauthnException('TPM type value not the same TPM_ST_ATTEST_CERTIFY');
        }

        $offset = 6;
        /* variable not used */
        $qualifiedSigner = $this->getTPMLengthPrefix($this->certInfo, $offset);
        $extraData = $this->getTPMLengthPrefix($this->certInfo, $offset);
        $coseAlgo = $this->getCoseAlgorithm($this->algo);
        if ($coseAlgo === null) {
            throw new WebauthnException(sprintf(
                'Invalid algorithm [%d]',
                $this->algo
            ));
        }

        if ($extraData->getBinaryString() !== hash($coseAlgo['hash'], $dataToVerify, true)) {
            throw new WebauthnException('certInfo:extraData hash is invalid');
        }

        return openssl_verify(
            $this->certInfo->getBinaryString(),
            $this->signature,
            $publicKey,
            $coseAlgo['openssl']
        ) === 1;
    }

    /**
     * Return the TPM Prefix length byte buffer
     * @param ByteBuffer $buffer
     * @param int $offset
     * @return ByteBuffer
     */
    protected function getTPMLengthPrefix(ByteBuffer $buffer, int &$offset): ByteBuffer
    {
        $length = $buffer->getUint16Value($offset);
        $data = $buffer->getBytes($offset + 2, $length);

        $offset += (2 + $length);

        return new ByteBuffer($data);
    }
}
