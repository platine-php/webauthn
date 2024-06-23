<?php

declare(strict_types=1);

namespace Platine\Webauthn\Entity;

use JsonSerializable;
use Platine\Webauthn\Exception\WebauthnException;

/**
 * @class AttestedCredentialData
 * @package Platine\Webauthn\Entity
 */
class AttestedCredentialData implements JsonSerializable
{
    /**
     * The AAGUID of the authenticator
     * @var string
     */
    protected string $aaguid;

    /**
     * The credential id. Byte length L of Credential ID,
     * 16-bit unsigned big-endian integer.
     * @var string
     */
    protected string $credentialId;

    /**
     * The credential public key
     * @var CredentialPublicKey
     */
    protected CredentialPublicKey $credentialPublicKey;

    /**
     * The length
     * @var int
     */
    protected int $length;

    /**
     * Create new instance
     * @param string $binaryData
     */
    public function __construct(string $binaryData)
    {
        if (strlen($binaryData) <= 55) {
            throw new WebauthnException('Attested credential data should be present but is missing');
        }

        $this->aaguid = substr($binaryData, 37, 16);

        $lengthData = unpack('nlength', substr($binaryData, 53, 2));
        if ($lengthData === false) {
            throw new WebauthnException('Can not unpack[nlength] data');
        }
        $length = $lengthData['length'];

        $this->credentialId = substr($binaryData, 55, $length);
        $this->length = $length;
    }

    /**
     *
     * @return int
     */
    public function getLength(): int
    {
        return $this->length;
    }


    /**
     * Set credential Public key
     * @param CredentialPublicKey $credentialPublicKey
     * @return $this
     */
    public function setCredentialPublicKey(CredentialPublicKey $credentialPublicKey): self
    {
        $this->credentialPublicKey = $credentialPublicKey;
        return $this;
    }


    /**
     *
     * @return string
     */
    public function getAaguid(): string
    {
        return $this->aaguid;
    }

    /**
     *
     * @return string
     */
    public function getCredentialId(): string
    {
        return $this->credentialId;
    }

    /**
     *
     * @return CredentialPublicKey
     */
    public function getCredentialPublicKey(): CredentialPublicKey
    {
        return $this->credentialPublicKey;
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
