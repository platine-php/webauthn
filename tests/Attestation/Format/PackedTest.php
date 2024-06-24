<?php

declare(strict_types=1);

namespace Platine\Test\Webauthn\Attestation\Format;

use Platine\Dev\PlatineTestCase;
use Platine\Webauthn\Attestation\AuthenticatorData;
use Platine\Webauthn\Attestation\Format\Packed;
use Platine\Webauthn\Exception\WebauthnException;
use Platine\Webauthn\Helper\ByteBuffer;

/**
 * Packed class tests
 *
 * @group core
 * @group webauth
 */
class PackedTest extends PlatineTestCase
{
    public function testConstruct(): void
    {
        $data = [
            'attStmt' => ['alg' => -7, 'sig' => new ByteBuffer('123'), 'x5c' => [new ByteBuffer('123'), new ByteBuffer('123')]],
        ];
        $authenticatorData = $this->getMockInstance(AuthenticatorData::class);
        $o = new Packed($data, $authenticatorData);

        $this->assertCommandOutput(
            '-----BEGIN CERTIFICATE-----
MTIz
-----END CERTIFICATE-----
',
            $o->getCertificatePem()
        );
    }

    public function testConstructWithoutx5c(): void
    {
        $data = [
            'attStmt' => ['alg' => -7, 'sig' => new ByteBuffer('123')],
        ];
        $authenticatorData = $this->getMockInstance(AuthenticatorData::class);
        $o = new Packed($data, $authenticatorData);

        $this->assertNull($o->getCertificatePem());
        $this->assertFalse($o->validateRootCertificate(['123']));
    }


    public function testConstructInvalidAglo(): void
    {
        $data = [
            'attStmt' => ['alg' => 37, 'sig' => new ByteBuffer('123'), 'x5c' => [new ByteBuffer('123')]],
        ];
        $authenticatorData = $this->getMockInstance(AuthenticatorData::class);
        $this->expectException(WebauthnException::class);
        $o = new Packed($data, $authenticatorData);
    }

    public function testConstructInvalidSignature(): void
    {
        $data = [
            'attStmt' => ['alg' => -7, 'sig' => '', 'x5c' => [new ByteBuffer('123')]],
        ];
        $authenticatorData = $this->getMockInstance(AuthenticatorData::class);
        $this->expectException(WebauthnException::class);
        $o = new Packed($data, $authenticatorData);
    }

    public function testConstructX5CNotByteBuffer(): void
    {
        $data = [
            'attStmt' => ['alg' => -7, 'sig' => new ByteBuffer('123'), 'x5c' => [1]],
        ];
        $authenticatorData = $this->getMockInstance(AuthenticatorData::class);
        $this->expectException(WebauthnException::class);
        $o = new Packed($data, $authenticatorData);
    }

    public function testValidateAttestationWithoutX5C(): void
    {
        global $mock_openssl_verify_to_value;
        $data = [
            'attStmt' => ['alg' => -7, 'sig' => new ByteBuffer('123')],
        ];
        $authenticatorData = $this->getMockInstance(AuthenticatorData::class, [
            'getBinary' => '123',
            'getPublicKeyPEM' => '123',
        ]);
        $o = new Packed($data, $authenticatorData);

        $mock_openssl_verify_to_value = 1;
        $this->assertTrue($o->validateAttestation('123'));
    }

    public function testValidateAttestationX5CInvalidPem(): void
    {
        global  $mock_openssl_pkey_get_public_to_value;
        $data = [
            'attStmt' => ['alg' => -7, 'sig' => new ByteBuffer('123'), 'x5c' => [new ByteBuffer('123')]],
        ];
        $authenticatorData = $this->getMockInstance(AuthenticatorData::class, [
            'getBinary' => '123',
            'getPublicKeyPEM' => '123',
        ]);
        $o = new Packed($data, $authenticatorData);

        $mock_openssl_pkey_get_public_to_value = false;

        $this->expectException(WebauthnException::class);
        $o->validateAttestation('123');
    }

    public function testValidateAttestationX5CInvalidCoseAlg(): void
    {
        global  $mock_openssl_pkey_get_public_to_value;
        $data = [
            'attStmt' => ['alg' => -7, 'sig' => new ByteBuffer('123'), 'x5c' => [new ByteBuffer('123')]],
        ];
        $authenticatorData = $this->getMockInstance(AuthenticatorData::class, [
            'getBinary' => '123',
            'getPublicKeyPEM' => '123',
        ]);
        $o = new Packed($data, $authenticatorData);

        $mock_openssl_pkey_get_public_to_value = 'yyyy';

        $this->setPropertyValue(Packed::class, $o, 'algo', 898);
        $this->expectException(WebauthnException::class);
        $o->validateAttestation('123');
    }

    public function testValidateAttestationX5CSuccess(): void
    {
        global  $mock_openssl_pkey_get_public_to_value, $mock_openssl_verify_to_value;
        $data = [
            'attStmt' => ['alg' => -7, 'sig' => new ByteBuffer('123'), 'x5c' => [new ByteBuffer('123')]],
        ];
        $authenticatorData = $this->getMockInstance(AuthenticatorData::class, [
            'getBinary' => '123',
            'getPublicKeyPEM' => '123',
        ]);
        $o = new Packed($data, $authenticatorData);

        $mock_openssl_pkey_get_public_to_value = 'yyyy';
        $mock_openssl_verify_to_value = 1;

        $this->assertTrue($o->validateAttestation('123'));
    }

    public function testValidateRootCertificateInvalidCertificate(): void
    {
        global $mock_openssl_x509_checkpurpose_to_value, $mock_openssl_x509_parse_to_value;
        $data = [
            'attStmt' => ['alg' => -7, 'sig' => new ByteBuffer('123'), 'x5c' => [new ByteBuffer('123')]],
        ];
        $authenticatorData = $this->getMockInstance(AuthenticatorData::class, [
            'getBinary' => '123',
            'getPublicKeyPEM' => '123',
        ]);
        $o = new Packed($data, $authenticatorData);

        $mock_openssl_x509_checkpurpose_to_value = -1;
        $this->setPropertyValue(Packed::class, $o, 'x5cChain', ['foobar']);

        $mock_openssl_x509_parse_to_value = [
            'issuer' => [
                'O' => 'Platine',
                'OU' => 'R&D',
            ],
            'subject' => [
                'O' => 'Platine Org',
                'OU' => 'Dev',
            ]
        ];

        $this->expectException(WebauthnException::class);
        $o->validateRootCertificate(['123']);
    }

    public function testValidateRootCertificateSuccess(): void
    {
        global $mock_openssl_x509_checkpurpose_to_value;
        $data = [
            'attStmt' => ['alg' => -7, 'sig' => new ByteBuffer('123'), 'x5c' => [new ByteBuffer('123')]],
        ];
        $authenticatorData = $this->getMockInstance(AuthenticatorData::class, [
            'getBinary' => '123',
            'getPublicKeyPEM' => '123',
        ]);
        $o = new Packed($data, $authenticatorData);

        $mock_openssl_x509_checkpurpose_to_value = true;

        $this->assertTrue($o->validateRootCertificate(['123']));
    }
}
