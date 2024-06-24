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

namespace Platine\Webauthn\Entity;

use JsonSerializable;
use Platine\Webauthn\Attestation\AuthenticatorData;
use Platine\Webauthn\Exception\WebauthnException;
use Platine\Webauthn\Helper\ByteBuffer;
use Platine\Webauthn\Helper\CborDecoder;

/**
 * @class CredentialPublicKey
 * @package Platine\Webauthn\Entity
 */
class CredentialPublicKey implements JsonSerializable
{
    /*
     * Cose encoded keys
     */
    public const COSE_KTY = 1;
    public const COSE_ALG = 3;

    public const EC2_ES256 = -7;
    public const EC2_P256 = 1;
    public const RSA_RS256 = -257;

    /*
     * Cose EC2 ES256 P-256 curve
     */
    public const COSE_CRV = -1;
    public const COSE_X = -2;
    public const COSE_Y = -3;

    /*
     * Cose RSA PS256
     */
    public const COSE_N = -1;
    public const COSE_E = -2;


    /**
     * The algorithm
     * @var int
     */
    protected int $alg;

    /**
     * The family of cryptographic algorithms used with the key.
     * @var int
     */
    protected int $kty;

    /**
     * The curve P-256
     * @var int|null
     */
    protected ?int $crv = null;

    /**
     * The x coordinate
     * @var string|null
     */
    protected ?string $x = null;

    /**
     * The y coordinate
     * @var string|null
     */
    protected ?string $y = null;

    /**
     * The RSA modulus
     * @var string|null
     */
    protected ?string $n = null;

    /**
     * The RSA public exponent
     * @var string|null
     */
    protected ?string $e = null;

    /**
     * Create new instance
     * @param string $binaryData
     * @param int $offset
     * @param int $endOffset
     */
    public function __construct(string $binaryData, int $offset, int &$endOffset)
    {
        $enc = CborDecoder::decodeInPlace($binaryData, $offset, $endOffset);

        // COSE key-encoded elliptic curve public key in EC2 format
        $this->kty = $enc[self::COSE_KTY];
        $this->alg = $enc[self::COSE_ALG];

        // Update properties
        $this->create($enc);
    }

    /**
     *
     * @return int
     */
    public function getAlg(): int
    {
        return $this->alg;
    }

    /**
     *
     * @return int
     */
    public function getKty(): int
    {
        return $this->kty;
    }

    /**
     *
     * @return int|null
     */
    public function getCrv(): ?int
    {
        return $this->crv;
    }

    /**
     *
     * @return string|null
     */
    public function getX(): ?string
    {
        return $this->x;
    }

    /**
     *
     * @return string|null
     */
    public function getY(): ?string
    {
        return $this->y;
    }

    /**
     *
     * @return string|null
     */
    public function getN(): ?string
    {
        return $this->n;
    }

    /**
     *
     * @return string|null
     */
    public function getE(): ?string
    {
        return $this->e;
    }

    /**
    * {@inheritdoc}
    * @return mixed
    */
    public function jsonSerialize()
    {
        return get_object_vars($this);
    }

    /**
     * Update properties based on the given data received
     * @param array<string, mixed> $enc
     * @return void
     */
    protected function create(array $enc): void
    {
        switch ($this->alg) {
            case self::EC2_ES256:
                $this->createES256($enc);
                break;
            case self::RSA_RS256:
                $this->createRSA256($enc);
                break;
        }
    }

    /**
     * Create for ES256
     * @param array<string|int, mixed> $enc
     * @return void
     */
    protected function createES256(array $enc): void
    {
        $this->crv = $enc[self::COSE_CRV];
        $this->x = $enc[self::COSE_X] instanceof ByteBuffer ? $enc[self::COSE_X]->getBinaryString() : null;
        $this->y = $enc[self::COSE_Y] instanceof ByteBuffer ? $enc[self::COSE_Y]->getBinaryString() : null;

        // remove encoded data
        unset($enc);

        // Validation
        if ($this->kty !== AuthenticatorData::EC2_TYPE) {
            throw new WebauthnException('Public key not in EC2 format');
        }

        if ($this->alg !== self::EC2_ES256) {
            throw new WebauthnException('The signature algorithm is not ES256');
        }

        if ($this->crv !== self::EC2_P256) {
            throw new WebauthnException('The curve is not P-256');
        }

        if (strlen((string) $this->x) !== 32) {
            throw new WebauthnException('Invalid X-coordinate provided');
        }

        if (strlen((string) $this->y) !== 32) {
            throw new WebauthnException('Invalid Y-coordinate provided');
        }
    }

    /**
     * Create for RSA256
     * @param array<string|int, mixed> $enc
     * @return void
     */
    protected function createRSA256(array $enc): void
    {
        $this->n = $enc[self::COSE_N] instanceof ByteBuffer ? $enc[self::COSE_N]->getBinaryString() : null;
        $this->e = $enc[self::COSE_E] instanceof ByteBuffer ? $enc[self::COSE_E]->getBinaryString() : null;

        // remove encoded data
        unset($enc);

        // Validation
        if ($this->kty !== AuthenticatorData::RSA_TYPE) {
            throw new WebauthnException('Public key not in RSA format');
        }

        if ($this->alg !== self::RSA_RS256) {
            throw new WebauthnException('The signature algorithm is not RS256');
        }

        if (strlen((string) $this->n) !== 256) {
            throw new WebauthnException('Invalid RSA modulus provided');
        }

        if (strlen((string) $this->e) !== 3) {
            throw new WebauthnException('Invalid RSA public exponent provided');
        }
    }
}
