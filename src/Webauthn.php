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

namespace Platine\Webauthn;

use Exception;
use Platine\Http\Uri;
use Platine\Stdlib\Helper\Json;
use Platine\Stdlib\Helper\Path;
use Platine\Webauthn\Attestation\AttestationData;
use Platine\Webauthn\Attestation\AuthenticatorData;
use Platine\Webauthn\Entity\AuthenticatorSelection;
use Platine\Webauthn\Entity\PublicKey;
use Platine\Webauthn\Entity\PublicKeyAuthParam;
use Platine\Webauthn\Entity\RelyingParty;
use Platine\Webauthn\Entity\UserCredential;
use Platine\Webauthn\Entity\UserInfo;
use Platine\Webauthn\Enum\AttestationType;
use Platine\Webauthn\Enum\KeyFormat;
use Platine\Webauthn\Enum\TransportType;
use Platine\Webauthn\Exception\WebauthnException;
use Platine\Webauthn\Helper\ByteBuffer;

/**
 * @class Webauthn
 * @package Platine\Webauthn
 */
class Webauthn
{
    /**
     * The attestation data formats
     * @var array<string>
     */
    protected array $formats = [];

    /**
     * The challenge to use
     * @var ByteBuffer|null
     */
    protected ?ByteBuffer $challenge = null;

    /**
     * The signature counter
     * @var int
     */
    protected int $signatureCounter = 0;

    /**
     * The relying party entity
     * @var RelyingParty
     */
    protected RelyingParty $relyingParty;

    /**
     * The certificates files path
     * @var array<string>
     */
    protected array $certificates = [];

    /**
     * The configuration instance
     * @var WebauthnConfiguration
     */
    protected WebauthnConfiguration $config;

    /**
     * Create new instance
     * @param WebauthnConfiguration $config
     * @param array<string> $allowedFormats
     */
    public function __construct(WebauthnConfiguration $config, array $allowedFormats = [])
    {
        if (! function_exists('openssl_open')) {
            throw new WebauthnException('OpenSSL module not installed in this platform');
        }

        if (! in_array('SHA256', array_map('strtoupper', openssl_get_md_methods()))) {
            throw new WebauthnException('SHA256 is not supported by this OpenSSL installation');
        }

        $this->config = $config;
        $this->formats = $this->normalizeFormats($allowedFormats);

        $this->relyingParty = new RelyingParty(
            $config->get('relying_party_id'),
            $config->get('relying_party_name'),
            $config->get('relying_party_logo')
        );
    }

    /**
     * Add a root certificate to verify new registrations
     * @param string $path
     * @return $this
     */
    public function addRootCertificate(string $path): self
    {
        $this->certificates[] = Path::realPath($path);

        return $this;
    }

    /**
     * Return the parameters to be used for the registration
     * @param string $userId
     * @param string $userName
     * @param string $userDisplayName
     * @param string $userVerificationType
     * @param bool $crossPlatformAttachment
     * @param array<string> $excludeCredentialIds
     * @param bool $withoutAttestation
     * @return PublicKey
     */
    public function getRegistrationParams(
        string $userId,
        string $userName,
        string $userDisplayName,
        string $userVerificationType,
        bool $crossPlatformAttachment = false,
        array $excludeCredentialIds = [],
        bool $withoutAttestation = false
    ): PublicKey {
        $excludeCredentials = [];
        foreach ($excludeCredentialIds as $id) {
            $hex = hex2bin($id);
            if ($hex === false) {
                throw new WebauthnException(sprintf('Can not convert credential id [%s] to binary', $id));
            }

            $excludeCredentials[] = new UserCredential(
                new ByteBuffer($hex),
                array_values(TransportType::all())
            );
        }

        $attestation = AttestationType::INDIRECT;
        if (count($this->certificates) > 0) {
            $attestation = AttestationType::DIRECT;
        }

        if ($withoutAttestation) {
            $attestation = AttestationType::NONE;
        }

        $relyingParty = new RelyingParty(
            $this->config->get('relying_party_id'),
            $this->config->get('relying_party_name'),
            $this->config->get('relying_party_logo')
        );

        $userInfo = new UserInfo(
            new ByteBuffer($userId),
            $userName,
            $userDisplayName
        );

        $authenticatorSelection = new AuthenticatorSelection(
            $userVerificationType,
            false,
            $crossPlatformAttachment
        );

        $publicKey = (new PublicKey())
                      ->setUserInfo($userInfo)
                      ->setRelyingParty($relyingParty)
                      ->setAuthenticatorSelection($authenticatorSelection)
                      ->setExcludeCredentials($excludeCredentials)
                      ->setChallenge($this->createChallenge())
                      ->setTimeout($this->config->get('timeout'))
                      ->setExtensions()
                      ->addPublicKeys()
                      ->setAttestation($attestation);

        return $publicKey;
    }

    /**
     * Return the authentication parameters
     * @param string $userVerificationType
     * @param array<string> $credentialIds
     * @return PublicKey
     */
    public function getAuthenticationParams(
        string $userVerificationType,
        array $credentialIds = []
    ): PublicKey {
        $allowedCredentials = [];
        foreach ($credentialIds as $id) {
            $hex = hex2bin($id);
            if ($hex === false) {
                throw new WebauthnException(sprintf('Can not convert credential id [%s] to binary', $id));
            }

            $allowedCredentials[] = new PublicKeyAuthParam(
                new ByteBuffer($hex),
                $this->config->get('transport_types')
            );
        }

        $publicKey = (new PublicKey())
                      ->setRelyingPartyId($this->relyingParty->getId())
                      ->setAllowCredentials($allowedCredentials)
                      ->setChallenge($this->createChallenge())
                      ->setTimeout($this->config->get('timeout'))
                      ->setUserVerificationType($userVerificationType);

        return $publicKey;
    }

    /**
     * Process the user registration
     * @param string $clientDataJson
     * @param string $attestationObject
     * @param string|ByteBuffer $challenge
     * @param bool $requireUserVerification
     * @param bool $requireUserPresent
     * @param bool $failIfRootCertificateMismatch
     * @return array<string, mixed>
     */
    public function processRegistration(
        string $clientDataJson,
        string $attestationObject,
        $challenge,
        bool $requireUserVerification = false,
        bool $requireUserPresent = true,
        bool $failIfRootCertificateMismatch = true
    ): array {
        $clientDataHash = hash('sha256', $clientDataJson, true);
        if (is_string($challenge)) {
            $challenge =  new ByteBuffer($challenge);
        }

        // security: https://www.w3.org/TR/webauthn/#registering-a-new-credential
        try {
            // 2. Let C, the client data claimed as collected during the credential creation,
            // be the result of running an implementation-specific JSON parser on JSONtext.
            $clientData = Json::decode($clientDataJson);
        } catch (Exception $ex) {
            throw new WebauthnException(sprintf('Invalid client data provided, [%s]', $ex->getMessage()));
        }

        // 3. Verify that the value of C.type is webauthn.create.
        if (! isset($clientData->type) || $clientData->type !== 'webauthn.create') {
            throw new WebauthnException('Invalid client type provided');
        }

        // 4. Verify that the value of C.challenge matches the challenge that was
        // sent to the authenticator in the create() call.
        if (
            ! isset($clientData->challenge) ||
            ByteBuffer::fromBase64Url($clientData->challenge)->getBinaryString() !== $challenge->getBinaryString()
        ) {
            throw new WebauthnException('Invalid challenge provided');
        }

        // 5. Verify that the value of C.origin matches the Relying Party's origin.
        if (! isset($clientData->origin) || $this->checkOrigin($clientData->origin) === false) {
            throw new WebauthnException('Invalid origin provided');
        }

        $attestation = new AttestationData($attestationObject, $this->formats);

        // 9. Verify that the RP ID hash in authData is indeed the SHA-256
        // hash of the RP ID expected by the RP.
        if ($attestation->validateRelyingPartyIdHash($this->relyingParty->getHashId()) === false) {
            throw new WebauthnException('Invalid relying party id hash provided');
        }

        // 14. Verify that attStmt is a correct attestation statement, conveying
        // a valid attestation signature
        if ($attestation->validateAttestation($clientDataHash) === false) {
            throw new WebauthnException('Invalid certificate signature');
        }

        // 15. If validation is successful, obtain a list of acceptable trust anchors
        $isRootValid = count($this->certificates) > 0
                ? $attestation->validateRootCertificate($this->certificates)
                : false;

        if ($failIfRootCertificateMismatch && count($this->certificates) > 0 && $isRootValid === false) {
            throw new WebauthnException('Invalid root certificate');
        }

        // 10. Verify that the User Present bit of the flags in authData is set.
        $userPresent = $attestation->getAuthenticatorData()->isUserPresent();
        if ($requireUserPresent && $userPresent === false) {
            throw new WebauthnException('User is not present during authentication');
        }

        // 11. If user verification is required for this registration, verify
        // that the User Verified bit of the flags in authData is set.
        $userVerified = $attestation->getAuthenticatorData()->isUserVerified();
        if ($requireUserVerification && $userVerified === false) {
            throw new WebauthnException('User is not verified during authentication');
        }

        $signCount = $attestation->getAuthenticatorData()->getSignatureCount();
        if ($signCount > 0) {
            $this->signatureCounter = $signCount;
        }

        // prepare data to store for future logins
        $data = [
            'rp_id' => $this->relyingParty->getId(),
            'attestation_format' => $attestation->getFormatName(),
            'credential_id' => bin2hex($attestation->getAuthenticatorData()->getCredentialId()),
            'credential_public_key' => $attestation->getAuthenticatorData()->getPublicKeyPEM(),
            'certificate_chain' => $attestation->getCertificateChain(),
            'certificate' => $attestation->getCertificatePem(),
            'certificate_issuer' => $attestation->getCertificateIssuer(),
            'certificate_subject' => $attestation->getCertificateSubject(),
            'root_certificate_valid' => $isRootValid,
            'signature_counter' => $this->signatureCounter,
            'aaguid' => bin2hex($attestation->getAuthenticatorData()->getAaguid()),
            'user_present' => $userPresent,
            'user_verified' => $userVerified,
        ];


        return $data;
    }

    /**
     * Process the user authentication
     * @param string $clientDataJson
     * @param string $authenticatorData
     * @param string $signature
     * @param string $credentialPublicKey
     * @param ByteBuffer|string $challenge
     * @param int|null $previousSignatureCount
     * @param bool $requireUserVerification
     * @param bool $requireUserPresent
     * @return bool
     */
    public function processAuthentication(
        string $clientDataJson,
        string $authenticatorData,
        string $signature,
        string $credentialPublicKey,
        $challenge,
        ?int $previousSignatureCount = null,
        bool $requireUserVerification = false,
        bool $requireUserPresent = true
    ): bool {
        if (is_string($challenge)) {
            $challenge =  new ByteBuffer($challenge);
        }
        $clientDataHash = hash('sha256', $clientDataJson, true);
        $authenticator = new AuthenticatorData($authenticatorData);
        try {
            // 5. Let JSON text be the result of running UTF-8 decode on the value of cData.
            $clientData = Json::decode($clientDataJson);
        } catch (Exception $ex) {
            throw new WebauthnException(sprintf('Invalid client data provided, [%s]', $ex->getMessage()));
        }

        // https://www.w3.org/TR/webauthn/#verifying-assertion

        // 1. If the allowCredentials option was given when this authentication ceremony was initiated,
        //    verify that credential.id identifies one of the public key credentials
        //    that were listed in allowCredentials.
        //    -> TO BE VERIFIED BY IMPLEMENTATION

        // 2. If credential.response.userHandle is present, verify that the user identified
        //    by this value is the owner of the public key credential identified by credential.id.
        //    -> TO BE VERIFIED BY IMPLEMENTATION

        // 3. Using credential’s id attribute (or the corresponding rawId, if base64url encoding is
        //    inappropriate for your use case),
        //    look up the corresponding credential public key.
        //    -> TO BE LOOKED UP BY IMPLEMENTATION

        // 7. Verify that the value of C.type is the string webauthn.get.
        if (! isset($clientData->type) || $clientData->type !== 'webauthn.get') {
            throw new WebauthnException('Invalid client type provided');
        }

        // 8. Verify that the value of C.challenge matches the challenge that was sent to the
        //    authenticator in the PublicKeyCredentialRequestOptions passed to the get() call.
        if (
            ! isset($clientData->challenge) ||
            ByteBuffer::fromBase64Url($clientData->challenge)->getBinaryString() !== $challenge->getBinaryString()
        ) {
            throw new WebauthnException('Invalid challenge provided');
        }

        // 9. Verify that the value of C.origin matches the Relying Party's origin.
        if (! isset($clientData->origin) || $this->checkOrigin($clientData->origin) === false) {
            throw new WebauthnException('Invalid origin provided');
        }

        // 11. Verify that the rpIdHash in authData is the SHA-256 hash
        // of the RP ID expected by the Relying Party.
        if ($authenticator->getRelyingPartyIdHash() !== $this->relyingParty->getHashId()) {
            throw new WebauthnException('Invalid relying party id hash provided');
        }

        // 12. Verify that the User Present bit of the flags in authData is set
        if ($requireUserPresent && $authenticator->isUserPresent() === false) {
            throw new WebauthnException('User is not present during authentication');
        }

        // 13. If user verification is required for this assertion, verify that
        // the User Verified bit of the flags in authData is set.
        if ($requireUserVerification && $authenticator->isUserVerified() === false) {
            throw new WebauthnException('User is not verified during authentication');
        }

        // 14. Verify the values of the client extension outputs
        // TODO    (extensions not implemented)

        // 16. Using the credential public key looked up in step 3, verify
        // that sig is a valid signature over the binary
        //  concatenation of authData and hash.
        $dataToVerify = '';
        $dataToVerify .= $authenticatorData;
        $dataToVerify .= $clientDataHash;

        $publicKey = openssl_pkey_get_public($credentialPublicKey);
        if ($publicKey === false) {
            throw new WebauthnException('Invalid public key provided');
        }

        if (
            openssl_verify(
                $dataToVerify,
                $signature,
                $publicKey,
                OPENSSL_ALGO_SHA256
            ) !== 1
        ) {
            throw new WebauthnException('Invalid signature provided');
        }

        $signatureCount = $authenticator->getSignatureCount();
        if ($signatureCount !== 0) {
            $this->signatureCounter = $signatureCount;
        }

        // 17. If either of the signature counter value authData.signCount or
        //     previous signature count is non-zero, and if authData.signCount
        //     less than or equal to previous signature count, it's a signal
        //     that the authenticator may be cloned
        if ($previousSignatureCount !== null) {
            if ($signatureCount !== 0 || $previousSignatureCount !== 0) {
                if ($previousSignatureCount >= $signatureCount) {
                    throw new WebauthnException('Invalid signature counter provided');
                }
            }
        }

        return true;
    }

    /**
     * Return the challenge
     * @return ByteBuffer|null
     */
    public function getChallenge(): ?ByteBuffer
    {
        return $this->challenge;
    }


    /**
     * Check the given origin
     * @param string $origin
     * @return bool
     */
    protected function checkOrigin(string $origin): bool
    {
        // https://www.w3.org/TR/webauthn/#rp-id

        // The origin's scheme must be https and not be ignored/whitelisted
        $url = new Uri($origin);
        if (
            ! in_array($this->relyingParty->getId(), $this->config->get('ignore_origins')) &&
            $url->getScheme() !== 'https'
        ) {
            return false;
        }

        // The RP ID must be equal to the origin's effective domain, or a registrable
        // domain suffix of the origin's effective domain.
        return preg_match('/' . preg_quote($this->relyingParty->getId()) . '$/i', $url->getHost()) === 1;
    }

    /**
     * Create the challenge if not yet created
     * @return ByteBuffer
     */
    protected function createChallenge(): ByteBuffer
    {
        if ($this->challenge === null) {
            $length = $this->config->get('challenge_length');
            $this->challenge = ByteBuffer::randomBuffer($length);
        }

        return $this->challenge;
    }

    /**
     * Normalize the formats
     * @param array<string> $formats
     * @return array<string>
     */
    protected function normalizeFormats(array $formats): array
    {
        $supportedFormats = KeyFormat::all();
        if (count($formats) === 0) {
            return $supportedFormats;
        }

        $desiredFormats = array_filter($formats, function ($entry) use ($supportedFormats) {
            return in_array($entry, $supportedFormats);
        });

        if (count($desiredFormats) > 0) {
            return $desiredFormats;
        }

        return $supportedFormats;
    }
}
