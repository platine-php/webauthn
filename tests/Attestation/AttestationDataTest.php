<?php

declare(strict_types=1);

namespace Platine\Test\Webauthn\Attestation;

use Platine\Dev\PlatineTestCase;
use Platine\Webauthn\Attestation\AttestationData;
use Platine\Webauthn\Attestation\AuthenticatorData;
use Platine\Webauthn\Attestation\Format\FidoU2F;
use Platine\Webauthn\Attestation\Format\None;
use Platine\Webauthn\Attestation\Format\Packed;
use Platine\Webauthn\Attestation\Format\Tpm;
use Platine\Webauthn\Enum\KeyFormat;
use Platine\Webauthn\Exception\WebauthnException;
use Platine\Webauthn\Helper\ByteBuffer;

use function Platine\Test\Fixture\Webauthn\getCborAttestationDataTestData;

/**
 * AttestationData class tests
 *
 * @group core
 * @group webauth
 */
class AttestationDataTest extends PlatineTestCase
{
    public function testConstructNone(): void
    {
        $data = getCborAttestationDataTestData();
        $o = new AttestationData($data, ['none']);

        $this->assertTrue($o->validateAttestation('foo')); // Format is "none"
        $this->assertFalse($o->validateRootCertificate(['foo'])); // Format is "none"
        $this->assertFalse($o->validateRelyingPartyIdHash('foo')); // Format is "none"
        $this->assertEquals('', $o->getCertificateIssuer());
        $this->assertEquals('', $o->getCertificateSubject());
        $this->assertEquals('none', $o->getFormatName());
        $this->assertNull($o->getCertificateChain());
        $this->assertInstanceOf(None::class, $o->getFormat());
        $this->assertInstanceOf(AuthenticatorData::class, $o->getAuthenticatorData());
    }

    public function testConstructFido(): void
    {
        $data = getCborAttestationDataTestData();
        $o = new AttestationData($data, KeyFormat::all());

        $this->setPropertyValue(AttestationData::class, $o, 'formatName', KeyFormat::FIDO_U2FA);

        $this->runPrivateProtectedMethod(
            $o,
            'createAttestationFormat',
            [
                [
                    'attStmt' => ['sig' => new ByteBuffer('123'), 'x5c' => [new ByteBuffer('123')]],
                ],
                KeyFormat::all()
            ]
        );

        $this->assertEquals('fido-u2fa', $o->getFormatName());
        $this->assertInstanceOf(FidoU2F::class, $o->getFormat());
    }

    public function testConstructPacked(): void
    {
        $data = getCborAttestationDataTestData();
        $o = new AttestationData($data, KeyFormat::all());

        $this->setPropertyValue(AttestationData::class, $o, 'formatName', KeyFormat::PACKED);

        $this->runPrivateProtectedMethod(
            $o,
            'createAttestationFormat',
            [
                [
                    'attStmt' => ['alg' => -7, 'sig' => new ByteBuffer('123'), 'x5c' => [new ByteBuffer('123')]],
                ],
                KeyFormat::all()
            ]
        );

        $this->assertEquals('packed', $o->getFormatName());
        $this->assertInstanceOf(Packed::class, $o->getFormat());
    }

    public function testConstructTpm(): void
    {
        $data = getCborAttestationDataTestData();
        $o = new AttestationData($data, KeyFormat::all());

        $this->setPropertyValue(AttestationData::class, $o, 'formatName', KeyFormat::TPM);

        $this->runPrivateProtectedMethod(
            $o,
            'createAttestationFormat',
            [
                [
                    'attStmt' => [
                        'ver' => '2.0',
                        'alg' => -7,
                        'sig' => new ByteBuffer('123'),
                        'certInfo' => new ByteBuffer('123'),
                        'pubArea' => new ByteBuffer('123'),
                        'x5c' => [new ByteBuffer('123')]
                    ],
                ],
                KeyFormat::all()
            ]
        );

        $this->assertEquals('tpm', $o->getFormatName());
        $this->assertInstanceOf(Tpm::class, $o->getFormat());
    }

    public function testConstructdAttestationFormatNotSupported(): void
    {
        $data = getCborAttestationDataTestData();
        $o = new AttestationData($data, KeyFormat::all());

        $this->setPropertyValue(AttestationData::class, $o, 'formatName', KeyFormat::APPLE);

        $this->expectException(WebauthnException::class);
        $this->runPrivateProtectedMethod(
            $o,
            'createAttestationFormat',
            [
                [
                    'attStmt' => [
                        'ver' => '2.0',
                        'alg' => -7,
                        'sig' => new ByteBuffer('123'),
                        'certInfo' => new ByteBuffer('123'),
                        'pubArea' => new ByteBuffer('123'),
                        'x5c' => [new ByteBuffer('123')]
                    ],
                ],
                KeyFormat::all()
            ]
        );
    }

    public function testConstructInvalidAttestationFormat(): void
    {
        $data = getCborAttestationDataTestData();

        $this->expectException(WebauthnException::class);
        $o = new AttestationData($data, []);
    }

    public function testConstructInvalidBinaryData(): void
    {
        $data = base64_decode('omFhAWFiAg==');

        $this->expectException(WebauthnException::class);
        $o = new AttestationData($data, []);
    }

    public function testConstructMissingAuthData(): void
    {
        $data = base64_decode('omNmbXRkbm9uZWdhdHRTdG10ggEC');

        $this->expectException(WebauthnException::class);
        $o = new AttestationData($data, []);
    }

    public function testConstructMissingAttStmt(): void
    {
        $data = base64_decode('oWNmbXRkbm9uZQ==');

        $this->expectException(WebauthnException::class);
        $o = new AttestationData($data, []);
    }

    public function testGetCertificateInfo(): void
    {
        global $mock_openssl_x509_parse_to_value;

        $mock_openssl_x509_parse_to_value = [
            'issuer' => [
                'CN' => 'Platine Framework',
                'O' => 'Platine',
                'OU' => 'R&D',
            ]
        ];
        $data = getCborAttestationDataTestData();
        $o = new AttestationData($data, KeyFormat::all());

        $this->setPropertyValue(AttestationData::class, $o, 'formatName', KeyFormat::FIDO_U2FA);

        $this->runPrivateProtectedMethod(
            $o,
            'createAttestationFormat',
            [
                [
                    'attStmt' => ['sig' => new ByteBuffer('123'), 'x5c' => [new ByteBuffer('123')]],
                ],
                KeyFormat::all()
            ]
        );

        $resFull = $this->runPrivateProtectedMethod(
            $o,
            'getCertificateInfo',
            ['issuer']
        );
        $this->assertEquals('Platine Framework (Platine R&D)', $resFull);

        $mock_openssl_x509_parse_to_value = [
            'issuer' => [
                'O' => 'Platine',
                'OU' => 'R&D',
            ]
        ];

        $resPartial = $this->runPrivateProtectedMethod(
            $o,
            'getCertificateInfo',
            ['issuer']
        );
        $this->assertEquals('Platine R&D', $resPartial);
    }

    public function testJson(): void
    {
        $data = getCborAttestationDataTestData();
        $o = new AttestationData($data, ['none']);

        $json = $o->jsonSerialize();

        $this->assertCount(3, $json);
    }
}
