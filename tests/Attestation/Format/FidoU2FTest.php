<?php

declare(strict_types=1);

namespace Platine\Test\Webauthn\Attestation\Format;

use org\bovigo\vfs\vfsStream;
use Platine\Dev\PlatineTestCase;
use Platine\Test\Fixture\Webauthn\MyBaseFormat;
use Platine\Webauthn\Attestation\AuthenticatorData;
use Platine\Webauthn\Attestation\Format\FidoU2F;
use Platine\Webauthn\Exception\WebauthnException;
use Platine\Webauthn\Helper\ByteBuffer;

/**
 * FidoU2F class tests
 *
 * @group core
 * @group webauth
 */
class FidoU2FTest extends PlatineTestCase
{
    protected $vfsRoot;
    protected $vfsTestPath;

    protected function setUp(): void
    {
        parent::setUp();

        //need setup for each test
        $this->vfsRoot = vfsStream::setup();
        $this->vfsTestPath = vfsStream::newDirectory('tests')->at($this->vfsRoot);
    }

    public function testConstruct(): void
    {
        $data = [
            'attStmt' => ['sig' => new ByteBuffer('123'), 'x5c' => [new ByteBuffer('123')]],
        ];
        $authenticatorData = $this->getMockInstance(AuthenticatorData::class);
        $o = new FidoU2F($data, $authenticatorData);

        $this->assertCommandOutput(
            '-----BEGIN CERTIFICATE-----
MTIz
-----END CERTIFICATE-----
',
            $o->getCertificatePem()
        );
    }

    public function testConstructInvalidAglo(): void
    {
        $data = [
            'attStmt' => ['alg' => 999, 'sig' => new ByteBuffer('123'), 'x5c' => [new ByteBuffer('123')]],
        ];
        $authenticatorData = $this->getMockInstance(AuthenticatorData::class);
        $this->expectException(WebauthnException::class);
        $o = new FidoU2F($data, $authenticatorData);
    }

    public function testConstructInvalidSignature(): void
    {
        $data = [
            'attStmt' => ['sig' => '', 'x5c' => [new ByteBuffer('123')]],
        ];
        $authenticatorData = $this->getMockInstance(AuthenticatorData::class);
        $this->expectException(WebauthnException::class);
        $o = new FidoU2F($data, $authenticatorData);
    }

    public function testConstructX5CNotByteBuffer(): void
    {
        $data = [
            'attStmt' => ['sig' => new ByteBuffer('123'), 'x5c' => [1]],
        ];
        $authenticatorData = $this->getMockInstance(AuthenticatorData::class);
        $this->expectException(WebauthnException::class);
        $o = new FidoU2F($data, $authenticatorData);
    }

    public function testConstructX5CEmpty(): void
    {
        $data = [
            'attStmt' => ['sig' => new ByteBuffer('123'), 'x5c' => []],
        ];
        $authenticatorData = $this->getMockInstance(AuthenticatorData::class);
        $this->expectException(WebauthnException::class);
        $o = new FidoU2F($data, $authenticatorData);
    }

    public function testValidateAttestationInvalidCertificatePem(): void
    {
        global $mock_openssl_pkey_get_public_to_value;
        $data = [
            'attStmt' => ['sig' => new ByteBuffer('123'), 'x5c' => [new ByteBuffer('123')]],
        ];
        $authenticatorData = $this->getMockInstance(AuthenticatorData::class);
        $o = new FidoU2F($data, $authenticatorData);

        $mock_openssl_pkey_get_public_to_value = false;

        $this->expectException(WebauthnException::class);
        $o->validateAttestation('123');
    }

    public function testValidateRootCertificateInvalidCertificate(): void
    {
        global $mock_openssl_x509_checkpurpose_to_value, $mock_openssl_x509_parse_to_value;
        $data = [
            'attStmt' => ['sig' => new ByteBuffer('123'), 'x5c' => [new ByteBuffer('123')]],
        ];
        $authenticatorData = $this->getMockInstance(AuthenticatorData::class);
        $o = new FidoU2F($data, $authenticatorData);

        $mock_openssl_x509_checkpurpose_to_value = -1;
        $this->setPropertyValue(FidoU2F::class, $o, 'x5cChain', ['foobar']);

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
            'attStmt' => ['sig' => new ByteBuffer('123'), 'x5c' => [new ByteBuffer('123')]],
        ];
        $authenticatorData = $this->getMockInstance(AuthenticatorData::class);
        $o = new FidoU2F($data, $authenticatorData);

        $mock_openssl_x509_checkpurpose_to_value = true;

        $this->assertTrue($o->validateRootCertificate(['123']));
    }

    public function testValidateAttestationInvalidCoseAlgo(): void
    {
        global $mock_openssl_pkey_get_public_to_value;
        $data = [
            'attStmt' => ['sig' => new ByteBuffer('123'), 'x5c' => [new ByteBuffer('123')]],
        ];
        $authenticatorData = $this->getMockInstance(AuthenticatorData::class, [
            'getRelyingPartyIdHash' => '123',
            'getCredentialId' => '123',
            'getPublicKeyU2F' => '123',
        ]);
        $o = new FidoU2F($data, $authenticatorData);

        $this->setPropertyValue(FidoU2F::class, $o, 'algo', 9999);


        $mock_openssl_pkey_get_public_to_value = 'yyyyy';
        $this->expectException(WebauthnException::class);
        $o->validateAttestation('123');
    }

    public function testValidateAttestationSuccess(): void
    {
        global $mock_openssl_pkey_get_public_to_value, $mock_openssl_verify_to_value;
        $data = [
            'attStmt' => ['sig' => new ByteBuffer('123'), 'x5c' => [new ByteBuffer('123')]],
        ];
        $authenticatorData = $this->getMockInstance(AuthenticatorData::class, [
            'getRelyingPartyIdHash' => '123',
            'getCredentialId' => '123',
            'getPublicKeyU2F' => '123',
        ]);
        $o = new FidoU2F($data, $authenticatorData);

        $mock_openssl_pkey_get_public_to_value = 'yyyyy';
        $mock_openssl_verify_to_value = 1;

        $this->assertTrue($o->validateAttestation('123'));
    }

    public function testJson(): void
    {
        $data = [
            'attStmt' => ['sig' => new ByteBuffer('123'), 'x5c' => [new ByteBuffer('123')]],
        ];
        $authenticatorData = $this->getMockInstance(AuthenticatorData::class);
        $o = new FidoU2F($data, $authenticatorData);

        $json = $o->jsonSerialize();

        $this->assertCount(7, $json);
    }

    public function testBaseFormatValidateAttestion(): void
    {
        $data = [
            'attStmt' => ['sig' => new ByteBuffer('123'), 'x5c' => [new ByteBuffer('123')]],
        ];
        $authenticatorData = $this->getMockInstance(AuthenticatorData::class);
        $o = new MyBaseFormat($data, $authenticatorData);

        $this->assertFalse($o->validateAttestation('123'));
    }

    public function testBaseFormatgGtCertificateChain(): void
    {
        $data = [
            'attStmt' => ['sig' => new ByteBuffer('123'), 'x5c' => [new ByteBuffer('123')]],
        ];
        $authenticatorData = $this->getMockInstance(AuthenticatorData::class);
        $o = new MyBaseFormat($data, $authenticatorData);

        $file = $this->createVfsFile('cert.pem', $this->vfsTestPath, 'foobar');

        $this->setPropertyValue(MyBaseFormat::class, $o, 'x5cTempFile', $file->url());

        $this->assertEquals('foobar', $o->getCertificateChain());
    }
}
