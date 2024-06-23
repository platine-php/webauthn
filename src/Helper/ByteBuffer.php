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

namespace Platine\Webauthn\Helper;

use Exception;
use JsonSerializable;
use Platine\Webauthn\Exception\WebauthnException;
use Platine\Stdlib\Helper\Json;
use Serializable;

/**
 * @class ByteBuffer
 * @package Platine\Webauthn\Helper
 */
class ByteBuffer implements JsonSerializable, Serializable
{
    /**
     * Whether to use Base64 URL encoding
     * @var bool
     */
    protected bool $useBase64UrlEncoding = false;

    /**
     * The data
     * @var string
     */
    protected string $data;

    /**
     * The data length
     * @var int
     */
    protected int $length = 0;

    /**
     * Create new instance
     * @param string $binaryData
     */
    public function __construct(string $binaryData)
    {
        $this->data = (string)$binaryData;
        $this->length = strlen($binaryData);
    }

    /**
     * Create a ByteBuffer from a base64 URL encoded string
     * @param string $str
     * @return self
     */
    public static function fromBase64Url(string $str): self
    {
        $data = self::base64UrlDecode($str);

        return new self($data);
    }

    /**
     * Create a ByteBuffer from a hexadecimal string
     * @param string $str
     * @return self
     */
    public static function fromHex(string $str): self
    {
        $binary = hex2bin($str);
        if ($binary === false) {
            throw new WebauthnException('Invalid hex string for bytes buffer');
        }

        return new self($binary);
    }

    /**
     * create a random Byte Buffer
     * @param int<1, max> $length
     * @return self
     */
    public static function randomBuffer(int $length): self
    {
        if (function_exists('random_bytes')) {
            return new self(random_bytes($length));
        }

        if (function_exists('openssl_random_pseudo_bytes')) {
            $bytes = openssl_random_pseudo_bytes($length);
            if ($bytes === false) {
                throw new WebauthnException('cannot generate random bytes using openssl for bytes buffer');
            }

            return new self($bytes);
        }

        throw new WebauthnException('cannot generate random bytes for bytes buffer');
    }

    /**
     * Return the buffer bytes
     * @param int $offset
     * @param int $length
     * @return string
     */
    public function getBytes(int $offset, int $length): string
    {
        if ($offset < 0 || $length < 0 || ($offset + $length) > $this->length) {
            throw new WebauthnException(sprintf(
                'Invalid offset [%d] or length [%d] for bytes buffer',
                $offset,
                $length
            ));
        }

        return substr($this->data, $offset, $length);
    }

    /**
     * Return the byte value of the given offset
     * @param int $offset
     * @return int
     */
    public function getByteValue(int $offset): int
    {
        if ($offset < 0 || $offset >= $this->length) {
            throw new WebauthnException(sprintf(
                'Invalid offset [%d] for bytes buffer',
                $offset
            ));
        }

        return ord(substr($this->data, $offset, 1));
    }

    /**
     * Return the Uint16 value of the given offset
     * @param int $offset
     * @return int
     */
    public function getUint16Value(int $offset): int
    {
        if ($offset < 0 || ($offset + 2) > $this->length) {
            throw new WebauthnException(sprintf(
                'Invalid offset [%d] for bytes buffer',
                $offset
            ));
        }

        $data = unpack('n', $this->data, $offset);
        if ($data === false) {
            throw new WebauthnException('Can not unpack data for bytes buffer');
        }

        return $data[1];
    }

    /**
     * Return the Uint32 value of the given offset
     * @param int $offset
     * @return int
     */
    public function getUint32Value(int $offset): int
    {
        if ($offset < 0 || ($offset + 4) > $this->length) {
            throw new WebauthnException(sprintf(
                'Invalid offset [%d] for bytes buffer',
                $offset
            ));
        }

        $data = unpack('N', $this->data, $offset);
        if ($data === false) {
            throw new WebauthnException('Can not unpack data for bytes buffer');
        }

        // Signed integer overflow causes signed negative numbers
        if ($data[1] < 0) {
            throw new WebauthnException('Value out of integer range for bytes buffer');
        }

        return $data[1];
    }

    /**
     * Return the Uint64 value of the given offset
     * @param int $offset
     * @return int
     */
    public function getUint64Value(int $offset): int
    {
        if (PHP_INT_SIZE < 8) {
            throw new WebauthnException('64-bit values not supported by this system');
        }

        if ($offset < 0 || ($offset + 8) > $this->length) {
            throw new WebauthnException(sprintf(
                'Invalid offset [%d] for bytes buffer',
                $offset
            ));
        }

        $data = unpack('J', $this->data, $offset);
        if ($data === false) {
            throw new WebauthnException('Can not unpack data for bytes buffer');
        }

        // Signed integer overflow causes signed negative numbers
        if ($data[1] < 0) {
            throw new WebauthnException('Value out of integer range for bytes buffer');
        }

        return $data[1];
    }

    /**
     * Return the half float value
     * @param int $offset
     * @return float
     */
    public function getHalfFloatValue(int $offset): float
    {
        //FROM spec pseudo decode_half(unsigned char *halfp)
        $half = $this->getUint16Value($offset);

        $exp = ($half >> 10) & 0x1f;
        $mant = $half & 0x3ff;

        if ($exp === 0) {
            $val = $mant * (2 ** -24);
        } elseif ($exp !== 31) {
            $val = ($mant + 1024) * (2 ** ($exp - 25));
        } else {
            $val = ($mant === 0) ? INF : NAN;
        }

        return ($half & 0x8000) ? -$val : $val;
    }

    /**
     * Return the float value of the given offset
     * @param int $offset
     * @return float
     */
    public function getFloatValue(int $offset): float
    {
        if ($offset < 0 || ($offset + 4) > $this->length) {
            throw new WebauthnException(sprintf(
                'Invalid offset [%d] for bytes buffer',
                $offset
            ));
        }

        $data = unpack('G', $this->data, $offset);
        if ($data === false) {
            throw new WebauthnException('Can not unpack data for bytes buffer');
        }

        return $data[1];
    }

    /**
     * Return the double value of the given offset
     * @param int $offset
     * @return float
     */
    public function getDoubleValue(int $offset): float
    {
        if ($offset < 0 || ($offset + 8) > $this->length) {
            throw new WebauthnException(sprintf(
                'Invalid offset [%d] for bytes buffer',
                $offset
            ));
        }

        $data = unpack('E', $this->data, $offset);
        if ($data === false) {
            throw new WebauthnException('Can not unpack data for bytes buffer');
        }

        return $data[1];
    }

    /**
     * Return the hexadecimal
     * @return string
     */
    public function getHexValue(): string
    {
        return bin2hex($this->data);
    }

    /**
     * Whether the buffer is empty
     * @return bool
     */
    public function isEmpty(): bool
    {
        return $this->length === 0;
    }

    /**
     * Whether two buffers are equal
     * @param ByteBuffer $data
     * @return bool
     */
    public function isEqual(ByteBuffer $data): bool
    {
        return $this->data === $data->getBinaryString();
    }

    /**
     * Return the json data
     * @param int $options
     * @return array<mixed>|object
     */
    public function getJson(int $options = 0)
    {
        try {
            $data = Json::decode($this->getBinaryString(), false, 512, $options);
        } catch (Exception $ex) {
            throw new WebauthnException($ex->getMessage());
        }

        return $data;
    }

    /**
     * Return the length
     * @return int
     */
    public function getLength(): int
    {
        return $this->length;
    }

        /**
     * Return the binary string
     * @return string
     */
    public function getBinaryString(): string
    {
        return $this->data;
    }

    /**
     *
     * @return bool
     */
    public function isUseBase64UrlEncoding(): bool
    {
        return $this->useBase64UrlEncoding;
    }

    /**
     *
     * @param bool $useBase64UrlEncoding
     * @return $this
     */
    public function useBase64UrlEncoding(bool $useBase64UrlEncoding): self
    {
        $this->useBase64UrlEncoding = $useBase64UrlEncoding;
        return $this;
    }

    /**
    * {@inheritdoc}
    * @return mixed
    */
    public function jsonSerialize()
    {
        if ($this->useBase64UrlEncoding) {
            return self::base64UrlEncode($this->data);
        }

        return sprintf(
            '=?BINARY?B?%s?=',
            base64_encode($this->data)
        );
    }

    /**
    * {@inheritdoc}
    * @return string|null
    */
    public function serialize(): ?string
    {
        return serialize($this->data);
    }

    /**
    * {@inheritdoc}
    * $param string $data
    */
    public function unserialize($data): void
    {
        $value = unserialize($data);
        if ($value === false) {
            throw new WebauthnException('Can not unserialize the data');
        }
        $this->data = $value;
        $this->length = strlen($this->data);
    }

    /**
     * Return string representation
     * @return string
     */
    public function __toString(): string
    {
        return $this->getHexValue();
    }

    /**
     * PHP 8 deprecates Serializable Interface if we don't defined this method
     * @param array<string, mixed> $data
     * @return void
     */
    public function __unserialize(array $data)
    {
        if (isset($data['data'])) {
            $value = unserialize($data['data']);
            if ($value === false) {
                throw new WebauthnException('Can not unserialize the data');
            }

            $this->data = $value;
            $this->length = strlen($this->data);
        }
    }

    /**
     * PHP 8 deprecates Serializable Interface if we don't defined this method
     * @return array<string, mixed>
     */
    public function __serialize(): array
    {
        return [
            'data' => serialize($this->data),
        ];
    }

    /**
     * Base 64 URL decoding
     * @param string $str
     * @return string
     */
    protected static function base64UrlDecode(string $str): string
    {
        $data = sprintf(
            '%s%s',
            strtr($str, '-_', '+/'),
            str_repeat('=', 3 - (3 + strlen($str)) % 4)
        );

        return base64_decode($data);
    }

    /**
     * Base 64 URL encoding
     * @param string $str
     * @return string
     */
    protected static function base64UrlEncode(string $str): string
    {
        return rtrim(strtr($str, '+/', '-_'), '=');
    }
}
