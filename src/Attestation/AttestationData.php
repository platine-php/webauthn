<?php

declare(strict_types=1);

namespace Platine\Webauthn\Attestation;

use JsonSerializable;
use Platine\Webauthn\Attestation\Format\BaseFormat;
use Platine\Webauthn\Attestation\Format\FidoU2F;
use Platine\Webauthn\Attestation\Format\None;
use Platine\Webauthn\Attestation\Format\Packed;
use Platine\Webauthn\Attestation\Format\Tpm;
use Platine\Webauthn\Enum\KeyFormat;
use Platine\Webauthn\Exception\WebauthnException;
use Platine\Webauthn\Helper\ByteBuffer;
use Platine\Webauthn\Helper\CborDecoder;

/**
 * @class AttestationData
 * @package Platine\Webauthn\Attestation
 */
class AttestationData implements JsonSerializable
{
    /**
     * The AuthenticatorData instance
     * @var AuthenticatorData
     */
    protected AuthenticatorData $authenticatorData;

    /**
     * The attestation format
     * @var BaseFormat|FidoU2F|None|Packed
     */
    protected $format;

    /**
     * The attestation format name
     * @var string
     */
    protected string $formatName;

    /**
     * Create new instance
     * @param string $binary
     * @param array<string> $allowedFormats
     */
    public function __construct(string $binary, array $allowedFormats)
    {
        $enc = CborDecoder::decode($binary);

        if (! is_array($enc) || ! array_key_exists('fmt', $enc) || ! is_string($enc['fmt'])) {
            throw new WebauthnException('Invalid attestation format provided');
        }

        if (! array_key_exists('attStmt', $enc) || ! is_array($enc['attStmt'])) {
            throw new WebauthnException('Invalid attestation format provided (attStmt not available)');
        }

        if (! array_key_exists('authData', $enc) || ! $enc['authData'] instanceof ByteBuffer) {
            throw new WebauthnException('Invalid attestation format provided (authData not available)');
        }

        $this->formatName = $enc['fmt'];
        $this->authenticatorData = new AuthenticatorData($enc['authData']->getBinaryString());

        if (! in_array($this->formatName, $allowedFormats)) {
            throw new WebauthnException(sprintf(
                'Invalid attestation format [%s], allowed [%s]',
                $this->formatName,
                implode(', ', $allowedFormats)
            ));
        }

        // Create attestation format based on the provided format name
        $this->createAttestationFormat($enc);
    }

    /**
     *
     * @return AuthenticatorData
     */
    public function getAuthenticatorData(): AuthenticatorData
    {
        return $this->authenticatorData;
    }

    /**
     *
     * @return BaseFormat|FidoU2F|None|Packed
     */
    public function getFormat()
    {
        return $this->format;
    }

    /**
     *
     * @return string
     */
    public function getFormatName(): string
    {
        return $this->formatName;
    }

    /**
     * Return the certificate chain
     * @return string|null
     */
    public function getCertificateChain(): ?string
    {
        return $this->format->getCertificateChain();
    }

    /**
     * Return the certificate with PEM format
     * @return string|null
     */
    public function getCertificatePem(): ?string
    {
        return $this->format->getCertificatePem();
    }

    /**
     * Check the validity of the signature
     * @param string $clientData
     * @return bool
     */
    public function validateAttestation(string $clientData): bool
    {
        return $this->format->validateAttestation($clientData);
    }

    /**
     * Validate the certificate against root certificates
     * @param array<string> $rootCertificates
     * @return bool
     */
    public function validateRootCertificate(array $rootCertificates): bool
    {
        return $this->format->validateRootCertificate($rootCertificates);
    }

    /**
     * Validate the reply party id hash
     * @param string $id
     * @return bool
     */
    public function validateReplyPartyIdHash(string $id): bool
    {
        return $this->authenticatorData->getReplyPartyIdHash() === $id;
    }

    /**
     * Return the certificate issuer
     * @return string
     */
    public function getCertificateIssuer(): string
    {
        return $this->getCertificateInfo('issuer');
    }

    /**
     * Return the certificate subject
     * @return string
     */
    public function getCertificateSubject(): string
    {
        return $this->getCertificateInfo('subject');
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
     * Return the certificate info
     * @param string $type can be "issuer", "subject"
     * @return string
     */
    protected function getCertificateInfo(string $type): string
    {
        $pem = $this->getCertificatePem();
        if ($pem === null) {
            return '';
        }
        $result = '';
        $certInfo = openssl_x509_parse($pem);
        if (is_array($certInfo) && array_key_exists($type, $certInfo) && is_array($certInfo[$type])) {
            $cn = $certInfo[$type]['CN'] ?? '';
            $o = $certInfo[$type]['O'] ?? '';
            $ou = $certInfo[$type]['OU'] ?? '';

            if (!empty($cn)) {
                $result .= $cn;
            }

            if (!empty($result) && (!empty($o) || !empty($ou))) {
                $result .= sprintf(' (%s)', trim($o . ' ' . $ou),);
            } else {
                $result .= trim($o . ' ' . $ou);
            }
        }

        return $result;
    }

    /**
     * Create the attestation format
     * @param array<string, mixed> $enc the encoded data
     * @return void
     */
    protected function createAttestationFormat(array $enc): void
    {
        switch ($this->formatName) {
            case KeyFormat::FIDO_U2FA:
                $this->format = new FidoU2F($enc, $this->authenticatorData);
                break;
            case KeyFormat::NONE:
                $this->format = new None($enc, $this->authenticatorData);
                break;
            case KeyFormat::PACKED:
                $this->format = new Packed($enc, $this->authenticatorData);
                break;
            case KeyFormat::TPM:
                $this->format = new Tpm($enc, $this->authenticatorData);
                break;
            default:
                throw new WebauthnException(sprintf(
                    'The attestation format [%s] is not supported yet, please implement it',
                    $this->formatName,
                ));
        }
    }
}
