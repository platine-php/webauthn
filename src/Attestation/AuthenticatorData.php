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

namespace Platine\Webauthn\Attestation;

use JsonSerializable;
use Platine\Webauthn\Entity\AttestedCredentialData;
use Platine\Webauthn\Entity\CredentialPublicKey;
use Platine\Webauthn\Entity\Flag;
use Platine\Webauthn\Exception\WebauthnException;
use Platine\Webauthn\Helper\CborDecoder;

/**
 * @class AuthenticatorData
 * @package Platine\Webauthn\Attestation
 */
class AuthenticatorData implements JsonSerializable
{
    public const EC2_TYPE = 2;
    public const RSA_TYPE = 3;

    /**
     * The binary raw data
     * @var string
     */
    protected string $binary;

    /**
     * The relying party ID hash
     * @var string
     */
    protected string $relyingPartyIdHash;

    /**
     * The authenticator data flag
     * @var Flag
     */
    protected Flag $flag;

    /**
     * The extension data
     * @var array<string, mixed>
     */
    protected array $extensionData = [];

    /**
     * The signature count
     * @var int
     */
    protected int $signatureCount = 0;

    /**
     * The attested credential data
     * @var AttestedCredentialData|null
     */
    protected ?AttestedCredentialData $attestedCredentialData = null;

    /**
     * Create new instance
     * @param string $binary
     */
    public function __construct(string $binary)
    {
        if (strlen($binary) < 37) {
            throw new WebauthnException('Invalid authenticator data provided');
        }

        $this->binary = $binary;

        // Read infos from binary
        // https://www.w3.org/TR/webauthn/#sec-authenticator-data

        $this->relyingPartyIdHash = substr($binary, 0, 32);

        // flags (1 byte)
        $this->createFlags();

        // signature counter: 32-bit unsigned big-endian integer.
        $signatureCount = unpack('Nsigncount', substr($this->binary, 33, 4));
        if ($signatureCount === false) {
            throw new WebauthnException('Can not unpack signature counter data');
        }

        $this->signatureCount = (int) $signatureCount['signcount'];

        $offset = 37;
        // https://www.w3.org/TR/webauthn/#sec-attested-credential-data
        if ($this->flag->isAttestedDataIncluded()) {
            $this->createAttestedData($offset);
        }

        if ($this->flag->isExtensionDataIncluded()) {
            $this->createExtensionData($offset);
        }
    }

    /**
     * Authenticator Attestation Globally Unique Identifier (AAGUID), a unique number
     * that identifies the model of the authenticator (not the specific instance
     * of the authenticator)
     * The AAGUID may be 0 if the user is using a old u2f device and/or if
     * the browser is using the FIDO-U2F format.
     *
     * @return string
     */
    public function getAaguid(): string
    {
        if ($this->attestedCredentialData === null) {
            throw new WebauthnException('Credential data not included in authenticator data');
        }

        return $this->attestedCredentialData->getAaguid();
    }

    /**
     *
     * @return string
     */
    public function getRelyingPartyIdHash(): string
    {
        return $this->relyingPartyIdHash;
    }

    /**
     *
     * @return int
     */
    public function getSignatureCount(): int
    {
        return $this->signatureCount;
    }

    /**
     *
     * @return bool
     */
    public function isUserPresent(): bool
    {
        return $this->flag->isUserPresent();
    }

    /**
     *
     * @return bool
     */
    public function isUserVerified(): bool
    {
        return $this->flag->isUserVerified();
    }


    /**
     * Return the public key in U2F format
     * @return string
     */
    public function getPublicKeyU2F(): string
    {
        if ($this->attestedCredentialData === null) {
            throw new WebauthnException('Credential data not included in authenticator data');
        }

        return "\x04" // ECC uncompressed
            . sprintf(
                '%s%s',
                $this->attestedCredentialData->getCredentialPublicKey()->getX(),
                $this->attestedCredentialData->getCredentialPublicKey()->getY()
            );
    }

    /**
     * Return the public key in PEM format
     * @return string
     */
    public function getPublicKeyPEM(): string
    {
        if ($this->attestedCredentialData === null) {
            throw new WebauthnException('Credential data not included in authenticator data');
        }

        // Distinguished Encoding Rules (DER)
        $der = null;
        $kty = $this->attestedCredentialData->getCredentialPublicKey()->getKty();
        switch ($kty) {
            case self::EC2_TYPE:
                $der = $this->getEC2DER();
                break;
            case self::RSA_TYPE:
                $der = $this->getRSADER();
                break;
            default:
                throw new WebauthnException(sprintf('Invalid key type [%d]', $kty));
        }

        $pem = '-----BEGIN PUBLIC KEY-----' . "\n";
        $pem .= chunk_split(base64_encode($der), 64, "\n");
        $pem .= '-----END PUBLIC KEY-----' . "\n";

        return $pem;
    }

    /**
     * Return the credential ID
     * @return string
     */
    public function getCredentialId(): string
    {
        if ($this->attestedCredentialData === null) {
            throw new WebauthnException('Credential data not included in authenticator data');
        }

        return $this->attestedCredentialData->getCredentialId();
    }

    /**
     * Return the binary data
     * @return string
     */
    public function getBinary(): string
    {
        return $this->binary;
    }

    /**
     *
     * @return array<string, mixed>
     */
    public function getExtensionData(): array
    {
        return $this->extensionData;
    }

    /**
     *
     * @return AttestedCredentialData|null
     */
    public function getAttestedCredentialData(): ?AttestedCredentialData
    {
        return $this->attestedCredentialData;
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
     * Return the EC2 Distinguished Encoding Rules (DER)
     * @return string
     */
    protected function getEC2DER(): string
    {
        return $this->getDERSequence(
            $this->getDERSequence(
                $this->getDEROid("\x2A\x86\x48\xCE\x3D\x02\x01") . // OID 1.2.840.10045.2.1 ecPublicKey
                $this->getDEROid("\x2A\x86\x48\xCE\x3D\x03\x01\x07") // 1.2.840.10045.3.1.7 prime256v1
            ) .
            $this->getDERBitString($this->getPublicKeyU2F())
        );
    }

    /**
     * Return the RSA Distinguished Encoding Rules (DER)
     * @return string
     */
    protected function getRSADER(): string
    {
        if ($this->attestedCredentialData === null) {
            throw new WebauthnException('Credential data not included in authenticator data');
        }

        return $this->getDERSequence(
            $this->getDERSequence(
                $this->getDEROid("\x2A\x86\x48\x86\xF7\x0D\x01\x01\x01") . // OID 1.2.840.113549.1.1.1 rsaEncryption
                $this->getDERNullValue()
            ) .
            $this->getDERBitString(
                $this->getDERSequence(
                    $this->getDERUnsignedInteger(
                        (string) $this->attestedCredentialData->getCredentialPublicKey()->getN()
                    ) .
                    $this->getDERUnsignedInteger(
                        (string) $this->attestedCredentialData->getCredentialPublicKey()->getE()
                    )
                )
            )
        );
    }

    /**
     * Create the extension data
     * @param int $offset
     * @return void
     */
    protected function createExtensionData(int &$offset): void
    {
        $data = substr($this->binary, $offset);

        $extensionData = CborDecoder::decode($data);

        if (! is_array($extensionData)) {
            throw new WebauthnException('Invalid extension data');
        }

        $this->extensionData = $extensionData;
    }

    /**
     * Create the attested data
     * @param int $offset
     * @return void
     */
    protected function createAttestedData(int &$offset): void
    {
        $attestedData = new AttestedCredentialData($this->binary);

        // set end offset
        $offset = 55 + $attestedData->getLength();

        // Create credential public key
        $credentialPublicKey = new CredentialPublicKey(
            $this->binary,
            55 + $attestedData->getLength(),
            $offset
        );
        $attestedData->setCredentialPublicKey($credentialPublicKey);

        $this->attestedCredentialData = $attestedData;
    }

    /**
     * Create flags
     * @return void
     */
    protected function createFlags(): void
    {
        $flags = unpack('Cflags', substr($this->binary, 32, 1));
        if ($flags === false) {
            throw new WebauthnException('Can not unpack flags data');
        }

        $this->flag = new Flag((int) $flags['flags']);
    }

    /**
     * Return Distinguished Encoding Rules (DER) length
     * @param int $length
     * @return string
     */
    protected function getDERLength(int $length): string
    {
        if ($length < 128) {
            return chr($length);
        }

        $byteLength = '';
        while ($length > 0) {
            $byteLength = chr($length % 256) . $byteLength;

            $length = intdiv($length, 256);
        }

        return chr(0x80 | strlen($byteLength)) . $byteLength;
    }

    /**
     * Return Distinguished Encoding Rules (DER) OID
     * @param string $encoded
     * @return string
     */
    protected function getDEROid(string $encoded): string
    {
        return "\x06" . $this->getDERLength(strlen($encoded)) . $encoded;
    }

    /**
     * Return Distinguished Encoding Rules (DER) sequence
     * @param string $contents
     * @return string
     */
    protected function getDERSequence(string $contents): string
    {
        return "\x30" . $this->getDERLength(strlen($contents)) . $contents;
    }

    /**
     * Return Distinguished Encoding Rules (DER) bit string
     * @param string $bytes
     * @return string
     */
    protected function getDERBitString(string $bytes): string
    {
        return "\x03" . $this->getDERLength(strlen($bytes) + 1) . "\x00" . $bytes;
    }

    /**
     * Return Distinguished Encoding Rules (DER) null value
     * @return string
     */
    protected function getDERNullValue(): string
    {
        return "\x05\x00";
    }

    /**
     * Return Distinguished Encoding Rules (DER) unsigned integer
     * @param string $bytes
     * @return string
     */
    protected function getDERUnsignedInteger(string $bytes): string
    {
        $length = strlen($bytes);
        // Remove leading zero bytes
        for ($i = 0; $i < ($length - 1); $i++) {
            if (ord($bytes[$i]) !== 0) {
                break;
            }
        }

        if ($i !== 0) {
            $bytes = substr($bytes, $i);
        }

        // If most significant bit is set, prefix with another zero
        // to prevent it being seen as negative number
        if ((ord($bytes[0]) & 0x80) !== 0) {
            $bytes = "\x00" . $bytes;
        }

        return "\x02" . $this->getDERLength(strlen($bytes)) . $bytes;
    }
}
