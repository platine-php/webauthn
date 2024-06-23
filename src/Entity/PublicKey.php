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
 * @class PublicKey
 * @package Platine\Webauthn\Entity
 */
class PublicKey implements JsonSerializable
{
    /**
     * Default timeout
     * @var int
     */
    protected int $timeout = 60 * 1000;

    /**
     * The public key credential parameters
     * @var PublicKeyCredentialParam[]
     */
    protected array $publicKeyCredentialParams = [];

    /**
     * The AuthenticatorSelection
     * @var AuthenticatorSelection
     */
    protected AuthenticatorSelection $authenticatorSelection;

    /**
     * The RelyingParty
     * @var RelyingParty
     */
    protected RelyingParty $relyingParty;

    /**
     * The UserInfo
     * @var UserInfo
     */
    protected UserInfo $userInfo;

    /**
     * The challenge to use
     * @var ByteBuffer
     */
    protected ByteBuffer $challenge;

    /**
     * The credentials to exclude
     * @var UserCredential[]
     */
    protected array $excludeCredentials = [];

    /**
     * The credentials to allow
     * @var PublicKeyAuthParam[]
     */
    protected array $allowCredentials = [];

    /**
     * The extensions
     * @var array<string, mixed>
     */
    protected array $extensions = ['exts' => true];

    /**
     * The attestation to use
     * @var string
     */
    protected string $attestation;

    /**
     * The relying party id. This is used only for login
     * @var string
     */
    protected string $relyingPartyId = '';

    /**
     * The user verification type. This is used only for login
     * @var string
     */
    protected string $userVerificationType = '';


    /**
     * Add default public keys
     * @return $this
     */
    public function addPublicKeys(): self
    {
        $this->publicKeyCredentialParams = [
            new PublicKeyCredentialParam(-7),
            new PublicKeyCredentialParam(-257),
        ];
        return $this;
    }

    /**
     * Return the timeout in milliseconds
     * @return int
     */
    public function getTimeout(): int
    {
        return $this->timeout;
    }

    /**
     *
     * @return PublicKeyCredentialParam[]
     */
    public function getPublicKeyCredentialParams(): array
    {
        return $this->publicKeyCredentialParams;
    }

    /**
     *
     * @return AuthenticatorSelection
     */
    public function getAuthenticatorSelection(): AuthenticatorSelection
    {
        return $this->authenticatorSelection;
    }

    /**
     *
     * @return RelyingParty
     */
    public function getRelyingParty(): RelyingParty
    {
        return $this->relyingParty;
    }

    /**
     *
     * @return UserInfo
     */
    public function getUserInfo(): UserInfo
    {
        return $this->userInfo;
    }

    /**
     *
     * @return ByteBuffer
     */
    public function getChallenge(): ByteBuffer
    {
        return $this->challenge;
    }

    /**
     *
     * @return UserCredential[]
     */
    public function getExcludeCredentials(): array
    {
        return $this->excludeCredentials;
    }

    /**
     *
     * @return PublicKeyAuthParam[]
     */
    public function getAllowCredentials(): array
    {
        return $this->allowCredentials;
    }

    /**
     *
     * @return array<string, mixed>
     */
    public function getExtensions(): array
    {
        return $this->extensions;
    }

    /**
     *
     * @return string
     */
    public function getAttestation(): string
    {
        return $this->attestation;
    }

    /**
     *
     * @return string
     */
    public function getRelyingPartyId(): string
    {
        return $this->relyingPartyId;
    }

    /**
     *
     * @return string
     */
    public function getUserVerificationType(): string
    {
        return $this->userVerificationType;
    }

    /**
     * Set the timeout (in second)
     * @param int $timeout
     * @return $this
     */
    public function setTimeout(int $timeout): self
    {
        $this->timeout = $timeout * 1000;
        return $this;
    }

    /**
     *
     * @param PublicKeyCredentialParam[] $publicKeyCredentialParams
     * @return $this
     */
    public function setPublicKeyCredentialParams(array $publicKeyCredentialParams): self
    {
        $this->publicKeyCredentialParams = $publicKeyCredentialParams;
        return $this;
    }

    /**
     *
     * @param AuthenticatorSelection $authenticatorSelection
     * @return $this
     */
    public function setAuthenticatorSelection(AuthenticatorSelection $authenticatorSelection): self
    {
        $this->authenticatorSelection = $authenticatorSelection;
        return $this;
    }

    /**
     *
     * @param RelyingParty $relyingParty
     * @return $this
     */
    public function setRelyingParty(RelyingParty $relyingParty): self
    {
        $this->relyingParty = $relyingParty;
        return $this;
    }

    /**
     *
     * @param UserInfo $userInfo
     * @return $this
     */
    public function setUserInfo(UserInfo $userInfo): self
    {
        $this->userInfo = $userInfo;
        return $this;
    }

    /**
     *
     * @param ByteBuffer|string $challenge
     * @return $this
     */
    public function setChallenge($challenge): self
    {
        if (is_string($challenge)) {
            $challenge = new ByteBuffer($challenge);
        }

        $this->challenge = $challenge;
        return $this;
    }

    /**
     *
     * @param UserCredential[] $excludeCredentials
     * @return $this
     */
    public function setExcludeCredentials(array $excludeCredentials): self
    {
        $this->excludeCredentials = $excludeCredentials;
        return $this;
    }

    /**
     *
     * @param PublicKeyAuthParam[] $allowCredentials
     * @return $this
     */
    public function setAllowCredentials(array $allowCredentials): self
    {
        $this->allowCredentials = $allowCredentials;
        return $this;
    }

    /**
     * TODO: This is currently not used
     * @return $this
     */
    public function setExtensions(): self
    {
        $this->extensions['exts'] = true;

        return $this;
    }

    /**
     *
     * @param string $attestation
     * @return $this
     */
    public function setAttestation(string $attestation): self
    {
        $this->attestation = $attestation;
        return $this;
    }

    /**
     *
     * @param string $relyingPartyId
     * @return $this
     */
    public function setRelyingPartyId(string $relyingPartyId): self
    {
        $this->relyingPartyId = $relyingPartyId;
        return $this;
    }

    /**
     *
     * @param string $userVerificationType
     * @return $this
     */
    public function setUserVerificationType(string $userVerificationType): self
    {
        $this->userVerificationType = $userVerificationType;
        return $this;
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
