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
use Platine\Webauthn\Helper\ByteBuffer;

/**
 * @class BaseCredential
 * @package Platine\Webauthn\Entity
 */
abstract class BaseCredential implements JsonSerializable
{
    /**
     * The type
     * @var string
     */
    protected string $type = 'public-key';

    /**
     * The id
     * @var ByteBuffer
     */
    protected ByteBuffer $id;

    /**
     * The supported transport to use
     * @var array<string>
     */
    protected array $transports = [];

    /**
     * Create new instance
     * @param ByteBuffer|string $id
     * @param array<string> $transports
     */
    public function __construct(ByteBuffer|string $id, array $transports = [])
    {
        if (is_string($id)) {
            $id = new ByteBuffer($id);
        }

        $this->id = $id;
        $this->transports = $transports;
    }


    /**
     *
     * @return string
     */
    public function getType(): string
    {
        return $this->type;
    }


    /**
     *
     * @return ByteBuffer
     */
    public function getId(): ByteBuffer
    {
        return $this->id;
    }

    /**
     *
     * @return array<string>
     */
    public function getTransports(): array
    {
        return $this->transports;
    }

    /**
    * {@inheritdoc}
    * @return mixed
    */
    public function jsonSerialize(): mixed
    {
        return get_object_vars($this);
    }
}
