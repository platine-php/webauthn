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
 * @class UserInfo
 * @package Platine\Webauthn\Entity
 */
class UserInfo implements JsonSerializable
{
    /**
     * The id
     * @var ByteBuffer
     */
    protected ByteBuffer $id;

    /**
     * The user name
     * @var string
     */
    protected string $name;

    /**
     * The user display name
     * @var string
     */
    protected string $displayName;

    /**
     *
     * @param ByteBuffer|string $id
     * @param string $name
     * @param string $displayName
     */
    public function __construct($id, string $name, string $displayName)
    {
        if (is_string($id)) {
            $id = new ByteBuffer($id);
        }

        $this->id = $id;
        $this->name = $name;
        $this->displayName = $displayName;
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
     * @return string
     */
    public function getName(): string
    {
        return $this->name;
    }

    /**
     *
     * @return string
     */
    public function getDisplayName(): string
    {
        return $this->displayName;
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
