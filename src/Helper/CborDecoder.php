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

use Platine\Webauthn\Exception\WebauthnException;

/**
 * @class CborDecoder
 * @package Platine\Webauthn\Helper
 */
class CborDecoder
{
    public const CBOR_MAJOR_UNSIGNED_INT = 0;
    public const CBOR_MAJOR_NEGATIVE_INT = 1;
    public const CBOR_MAJOR_BYTE_STRING = 2;
    public const CBOR_MAJOR_TEXT_STRING = 3;
    public const CBOR_MAJOR_ARRAY = 4;
    public const CBOR_MAJOR_MAP = 5;
    public const CBOR_MAJOR_TAG = 6;
    public const CBOR_MAJOR_FLOAT_SIMPLE = 7;

    /**
     * Decode the given data
     * @param ByteBuffer|string $data
     * @return mixed
     */
    public static function decode($data)
    {
        if (is_string($data)) {
            $data = new ByteBuffer($data);
        }

        $offset = 0;
        $result = self::parseItem($data, $offset);
        if ($offset !== $data->getLength()) {
            throw new WebauthnException(sprintf(
                'There still unsed bytes [%d] after parse data',
                abs($offset - $data->getLength())
            ));
        }

        return $result;
    }

    /**
     * Decode the data using custom start and end offset
     * @param ByteBuffer|string $data
     * @param int $startoffset
     * @param int|null $endOffset
     * @return mixed
     */
    public static function decodeInPlace($data, int $startoffset, ?int $endOffset = null)
    {
        if (is_string($data)) {
            $data = new ByteBuffer($data);
        }

        $offset = $startoffset;
        $result = self::parseItem($data, $offset);
        $endOffset = $offset;

        return $result;
    }

    /**
     * Parse the item in the given offset
     * @param ByteBuffer $buffer
     * @param int $offset
     * @return mixed
     */
    protected static function parseItem(ByteBuffer $buffer, int &$offset)
    {
        $first = $buffer->getByteValue($offset++);
        $type = $first >> 5;
        $value = $first & 0b11111;
        if ($type === self::CBOR_MAJOR_FLOAT_SIMPLE) {
            return self::parseSimpleFloat($value, $buffer, $offset);
        }

        $val = self::extractLength($value, $buffer, $offset);

        return self::parseItemData($type, $val, $buffer, $offset);
    }

    /**
     * Parse the simple float value
     * @param int $value
     * @param ByteBuffer $buffer
     * @param int $offset
     * @return mixed
     */
    protected static function parseSimpleFloat(int $value, ByteBuffer $buffer, int &$offset)
    {
        switch ($value) {
            case 24:
                $value = $buffer->getByteValue($offset);
                $offset++;
                return self::parseSimplevalue($value);

            case 25:
                $floatValue = $buffer->getHalfFloatValue($offset);
                $offset += 2;

                return $floatValue;

            case 26:
                $floatValue = $buffer->getFloatValue($offset);
                $offset += 4;

                return $floatValue;

            case 27:
                $floatValue = $buffer->getDoubleValue($offset);
                $offset += 8;

                return $floatValue;

            case 28:
            case 29:
            case 30:
                throw new WebauthnException(sprintf('Reserved value [%d] used', $value));

            case 31:
                throw new WebauthnException(sprintf('Indefinite value [%d] length is not supported', $value));
        }

        return self::parseSimplevalue($value);
    }

    /**
     * Parse simple value
     * @param int $value
     * @return bool|null
     */
    protected static function parseSimplevalue(int $value): ?bool
    {
        if ($value === 20) {
            return false;
        }

        if ($value === 21) {
            return true;
        }

        if ($value === 23) {
            return null;
        }

        throw new WebauthnException(sprintf('Unsupported simple value [%d]', $value));
    }

    /**
     * Parse the item data
     * @param int $type
     * @param int $value
     * @param ByteBuffer $buffer
     * @param int $offset
     * @return mixed
     */
    protected static function parseItemData(int $type, int $value, ByteBuffer $buffer, int &$offset)
    {
        switch ($type) {
            case self::CBOR_MAJOR_UNSIGNED_INT:
                return $value;

            case self::CBOR_MAJOR_NEGATIVE_INT:
                return -1 - $value;

            case self::CBOR_MAJOR_BYTE_STRING:
                $data = $buffer->getBytes($offset, $value);
                $offset += $value;
                return new ByteBuffer($data); // bytes

            case self::CBOR_MAJOR_TEXT_STRING:
                $data = $buffer->getBytes($offset, $value);
                $offset += $value;
                return $data; // UTF-8

            case self::CBOR_MAJOR_ARRAY:
                return self::parseArray($buffer, $offset, $value);

            case self::CBOR_MAJOR_MAP:
                return self::parseMap($buffer, $offset, $value);

            case self::CBOR_MAJOR_TAG:
                return self::parseItem($buffer, $offset); // 1 embedded data item
        }

        throw new WebauthnException(sprintf('Unsupported major type [%d]', $type));
    }

    /**
     * Parse an array of values
     * @param ByteBuffer $buffer
     * @param int $offset
     * @param int $count
     * @return array<mixed>
     */
    protected static function parseArray(ByteBuffer $buffer, int &$offset, int $count): array
    {
        $arr = [];
        for ($i = 0; $i < $count; $i++) {
            $arr[] = self::parseItem($buffer, $offset);
        }

        return $arr;
    }

    /**
     * Parse map of values
     * @param ByteBuffer $buffer
     * @param int $offset
     * @param int $count
     * @return array<string|int, mixed>
     */
    protected static function parseMap(ByteBuffer $buffer, int &$offset, int $count): array
    {
        $maps = [];
        for ($i = 0; $i < $count; $i++) {
            $key = self::parseItem($buffer, $offset);
            $value = self::parseItem($buffer, $offset);
            if (!is_int($key) && !is_string($key)) {
                throw new WebauthnException('Can only use integer or string for map key');
            }

            $maps[$key] = $value;
        }

        return $maps;
    }

    /**
     *
     * @param int $value
     * @param ByteBuffer $buffer
     * @param int $offset
     * @return int
     */
    protected static function extractLength(int $value, ByteBuffer $buffer, int &$offset): int
    {
        switch ($value) {
            case 24:
                $value = $buffer->getByteValue($offset);
                $offset++;
                break;

            case 25:
                $value = $buffer->getUint16Value($offset);
                $offset += 2;
                break;

            case 26:
                $value = $buffer->getUint32Value($offset);
                $offset += 4;
                break;

            case 27:
                $value = $buffer->getUint64Value($offset);
                $offset += 8;
                break;

            case 28:
            case 29:
            case 30:
                throw new WebauthnException(sprintf('Reserved value [%d] used', $value));

            case 31:
                throw new WebauthnException(sprintf('Indefinite value [%d] length is not supported', $value));
        }

        return $value;
    }
}
