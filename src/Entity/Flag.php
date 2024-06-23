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

/**
 * @class Flag
 * @package Platine\Webauthn\Entity
 */
class Flag implements JsonSerializable
{
    /**
     * The bit 0
     * @var bool
     */
    protected bool $bit0 = false;

    /**
     * The bit 1
     * @var bool
     */
    protected bool $bit1 = false;

    /**
     * The bit 2
     * @var bool
     */
    protected bool $bit2 = false;

    /**
     * The bit 3
     * @var bool
     */
    protected bool $bit3 = false;

    /**
     * The bit 4
     * @var bool
     */
    protected bool $bit4 = false;

    /**
     * The bit 5
     * @var bool
     */
    protected bool $bit5 = false;

    /**
     * The bit 6
     * @var bool
     */
    protected bool $bit6 = false;

    /**
     * The bit 7
     * @var bool
     */
    protected bool $bit7 = false;

    /**
     * User present flag
     * @var bool
     */
    protected bool $userPresent = false;

    /**
     * User verified flag
     * @var bool
     */
    protected bool $userVerified = false;

    /**
     * The flag for attested data include
     * @var bool
     */
    protected bool $attestedDataIncluded = false;

    /**
     * The flag for extension data include
     * @var bool
     */
    protected bool $extensionDataIncluded = false;

    /**
     * Create new instance
     * @param int $binaryFlag
     */
    public function __construct(int $binaryFlag)
    {
        $this->bit0 = !! ($binaryFlag & 1);
        $this->bit1 = !! ($binaryFlag & 2);
        $this->bit2 = !! ($binaryFlag & 4);
        $this->bit3 = !! ($binaryFlag & 8);
        $this->bit4 = !! ($binaryFlag & 16);
        $this->bit5 = !! ($binaryFlag & 32);
        $this->bit6 = !! ($binaryFlag & 64);
        $this->bit7 = !! ($binaryFlag & 128);

        $this->userPresent = $this->bit0;
        $this->userVerified = $this->bit2;
        $this->attestedDataIncluded = $this->bit6;
        $this->extensionDataIncluded = $this->bit7;
    }

    /**
     *
     * @return bool
     */
    public function isBit0(): bool
    {
        return $this->bit0;
    }

    /**
     *
     * @return bool
     */
    public function isBit1(): bool
    {
        return $this->bit1;
    }

    /**
     *
     * @return bool
     */
    public function isBit2(): bool
    {
        return $this->bit2;
    }

    /**
     *
     * @return bool
     */
    public function isBit3(): bool
    {
        return $this->bit3;
    }

    /**
     *
     * @return bool
     */
    public function isBit4(): bool
    {
        return $this->bit4;
    }

    /**
     *
     * @return bool
     */
    public function isBit5(): bool
    {
        return $this->bit5;
    }

    /**
     *
     * @return bool
     */
    public function isBit6(): bool
    {
        return $this->bit6;
    }

    /**
     *
     * @return bool
     */
    public function isBit7(): bool
    {
        return $this->bit7;
    }

    /**
     *
     * @return bool
     */
    public function isUserPresent(): bool
    {
        return $this->userPresent;
    }

    /**
     *
     * @return bool
     */
    public function isUserVerified(): bool
    {
        return $this->userVerified;
    }

    /**
     *
     * @return bool
     */
    public function isAttestedDataIncluded(): bool
    {
        return $this->attestedDataIncluded;
    }

    /**
     *
     * @return bool
     */
    public function isExtensionDataIncluded(): bool
    {
        return $this->extensionDataIncluded;
    }

    /**
    * {@inheritdoc}
    * @return mixed
    */
    public function jsonSerialize()
    {
        return get_object_vars($this);
    }
}
