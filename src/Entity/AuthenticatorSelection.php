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
use Platine\Webauthn\Enum\UserVerificationType;

/**
 * @class AuthenticatorSelection
 * @package Platine\Webauthn\Entity
 */
class AuthenticatorSelection implements JsonSerializable
{
    /**
     * The authenticator attachment
     * @var string
     */
    protected string $authenticatorAttachment = 'platform';

    /**
     * The resident key type
     * @var string
     */
    protected string $residentKey;

    /**
     * require resident key
     * @var bool
     */
    protected bool $requireResidentKey = false;

    /**
     * The user verification type
     * @var string
     */
    protected string $userVerification;

    /**
     * Create new instance
     * @param string $userVerificationType
     * @param bool $requireResidentKey
     * @param bool $crossPlatform
     */
    public function __construct(
        string $userVerificationType,
        bool $requireResidentKey = false,
        bool $crossPlatform = false
    ) {
        $this->requireResidentKey = $requireResidentKey;
        $this->residentKey = UserVerificationType::DISCOURAGED;

        $this->userVerification = $userVerificationType;
        if ($requireResidentKey) {
            $this->residentKey = $userVerificationType;
        }

        if ($crossPlatform) {
            $this->authenticatorAttachment = 'cross-platform';
        }
    }

    /**
     *
     * @return string
     */
    public function getAuthenticatorAttachment(): string
    {
        return $this->authenticatorAttachment;
    }

    /**
     *
     * @return string
     */
    public function getResidentKey(): string
    {
        return $this->residentKey;
    }

    /**
     *
     * @return bool
     */
    public function isRequireResidentKey(): bool
    {
        return $this->requireResidentKey;
    }

    /**
     *
     * @return string
     */
    public function getUserVerification(): string
    {
        return $this->userVerification;
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
