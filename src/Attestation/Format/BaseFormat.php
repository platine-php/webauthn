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

use JsonSerializable;
use Platine\Webauthn\Attestation\AuthenticatorData;

/**
 * @class BaseFormat
 * @package Platine\Webauthn\Attestation\Format
 */
abstract class BaseFormat implements JsonSerializable
{
    /**
     * The X5C Chain data
     * @var array<string>
     */
    protected array $x5cChain = [];

    /**
     * The X5C temporary file
     * @var string|null
     */
    protected ?string $x5cTempFile = null;

    /**
     * Create new instance
     * @param array<string|int, mixed> $attestationData
     * @param AuthenticatorData $authenticatorData
     */
    public function __construct(
        protected array $attestationData,
        protected AuthenticatorData $authenticatorData
    ) {
    }

    /**
     * Destructor
     */
    public function __destruct()
    {
        // delete X.509 chain certificate file after use
        if ($this->x5cTempFile !== null && is_file($this->x5cTempFile)) {
            unlink($this->x5cTempFile);
        }
    }

    /**
     * Return the certificate chain
     * @return string|null
     */
    public function getCertificateChain(): ?string
    {
        if ($this->x5cTempFile !== null && is_file($this->x5cTempFile)) {
            return (string) file_get_contents($this->x5cTempFile);
        }

        return null;
    }

    /**
     * Return the certificate with PEM format
     * @return string|null
     */
    public function getCertificatePem(): ?string
    {
        // Child classes need overwrite it
        return null;
    }

    /**
     * Check the validity of the signature
     * @param string $clientData
     * @return bool
     */
    public function validateAttestation(string $clientData): bool
    {
        // Child classes need overwrite it

        return false;
    }

    /**
     * Validate the certificate against root certificates
     * @param array<string> $rootCertificates
     * @return bool
     */
    public function validateRootCertificate(array $rootCertificates): bool
    {
        // Child classes need overwrite it

        return false;
    }

    /**
    * {@inheritdoc}
    * @return mixed
    */
    public function jsonSerialize(): mixed
    {
        return get_object_vars($this);
    }

    /**
     * Create the certificate PEM format
     * @param string $x5c
     * @return string
     */
    protected function createCertificatePem(string $x5c): string
    {
        $pem = '-----BEGIN CERTIFICATE-----' . "\n";
        $pem .= chunk_split(base64_encode($x5c), 64, "\n");
        $pem .= '-----END CERTIFICATE-----' . "\n";

        return $pem;
    }

    /**
     * Create the X5C chain file
     * @return string|null the PEM file path if success
     */
    protected function createX5cChainFile(): ?string
    {
        $content = '';
        if (count($this->x5cChain) > 0) {
            foreach ($this->x5cChain as $x5c) {
                $pem = $this->createCertificatePem($x5c);
                $certInfo = openssl_x509_parse($pem);

                // check if issuer = subject (self signed)
                if (is_array($certInfo) && is_array($certInfo['issuer']) && is_array($certInfo['subject'])) {
                    $selfSigned = true;
                    foreach ($certInfo['issuer'] as $key => $value) {
                        if ($certInfo['subject'][$key] !== $value) {
                            $selfSigned = false;
                            break;
                        }
                    }

                    if ($selfSigned === false) {
                        $content .= "\n" . $pem . "\n";
                    }
                }
            }
        }

        if (!empty($content)) {
            $this->x5cTempFile = sprintf(
                '%s/x5c_chain_%s.pem',
                sys_get_temp_dir(),
                base_convert((string) rand(), 10, 36)
            );

            if (file_put_contents($this->x5cTempFile, $content) !== false) {
                return $this->x5cTempFile;
            }
        }

        return null;
    }

    /**
     * Return the COSE algorithm based on the given number
     * @param int $coseNumber
     * @return array<string, mixed>|null
     */
    protected function getCoseAlgorithm(int $coseNumber): ?array
    {
        // https://www.iana.org/assignments/cose/cose.xhtml#algorithms
        $maps = [
            [
                'hash' => 'SHA1',
                'openssl' => OPENSSL_ALGO_SHA1,
                'cose' => [
                    -65535,  // RS1
                ],
            ],
            [
                'hash' => 'SHA256',
                'openssl' => OPENSSL_ALGO_SHA256,
                'cose' => [
                    -257, // RS256
                    -37,  // PS256
                    -7,   // ES256
                    5,     // HMAC256
                ],
            ],
            [
                'hash' => 'SHA384',
                'openssl' => OPENSSL_ALGO_SHA384,
                'cose' => [
                    -258, // RS384
                    -38,  // PS384
                    -35,  // ES384
                    6,     // HMAC384
                ],
            ],
            [
                'hash' => 'SHA512',
                'openssl' => OPENSSL_ALGO_SHA512,
                'cose' => [
                    -259, // RS512
                    -39,  // PS512
                    -36,  // ES512
                    7,     // HMAC512
                ],
            ],
        ];

        foreach ($maps as $map) {
            if (in_array($coseNumber, $map['cose'], true)) {
                return [
                    'hash' => $map['hash'],
                    'openssl' => $map['openssl'],
                ];
            }
        }

        return null;
    }
}
