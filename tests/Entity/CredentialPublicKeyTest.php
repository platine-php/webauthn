<?php

declare(strict_types=1);

namespace Platine\Test\Webauthn\Entity;

use Platine\Dev\PlatineTestCase;
use Platine\Webauthn\Attestation\AuthenticatorData;
use Platine\Webauthn\Entity\CredentialPublicKey;
use Platine\Webauthn\Exception\WebauthnException;
use Platine\Webauthn\Helper\ByteBuffer;

use function Platine\Test\Fixture\Webauthn\getCborAuthenticatorDataTestData;

/**
 * CredentialPublicKey class tests
 *
 * @group core
 * @group webauth
 */
class CredentialPublicKeyTest extends PlatineTestCase
{
    public function testConstructRsa(): void
    {
        $data = getCborAuthenticatorDataTestData();
        $endOffset = 87;
        $o = new CredentialPublicKey($data, 87, $endOffset);

        $this->assertEquals(CredentialPublicKey::RSA_RS256, $o->getAlg());
    }

    public function testCreateRsaInvalidKty(): void
    {
        $data = getCborAuthenticatorDataTestData();
        $endOffset = 87;
        $o = new CredentialPublicKey($data, 87, $endOffset);

        $this->setPropertyValue(CredentialPublicKey::class, $o, 'kty', 1000);

        $this->expectException(WebauthnException::class);
        $this->runPrivateProtectedMethod($o, 'createRSA256', [[-1 => 0, -2 => 0]]);
    }

    public function testCreateRsaInvalidAlgo(): void
    {
        $data = getCborAuthenticatorDataTestData();
        $endOffset = 87;
        $o = new CredentialPublicKey($data, 87, $endOffset);

        $this->setPropertyValue(CredentialPublicKey::class, $o, 'alg', 1000);

        $this->expectException(WebauthnException::class);
        $this->runPrivateProtectedMethod($o, 'createRSA256', [[-1 => 0, -2 => 0]]);
    }

    public function testCreateRsaInvalidN(): void
    {
        $data = getCborAuthenticatorDataTestData();
        $endOffset = 87;
        $o = new CredentialPublicKey($data, 87, $endOffset);

        $this->expectException(WebauthnException::class);
        $this->runPrivateProtectedMethod($o, 'createRSA256', [[-1 => 0, -2 => 0]]);
    }

    public function testCreateRsaInvalidE(): void
    {
        $data = getCborAuthenticatorDataTestData();
        $endOffset = 87;
        $o = new CredentialPublicKey($data, 87, $endOffset);

        $this->expectException(WebauthnException::class);
        $this->runPrivateProtectedMethod($o, 'createRSA256', [[-1 => new ByteBuffer(str_repeat('q', 256)), -2 => 0]]);
    }

    public function testCreateESInvalidKty(): void
    {
        $data = getCborAuthenticatorDataTestData();
        $endOffset = 87;
        $o = new CredentialPublicKey($data, 87, $endOffset);

        $this->setPropertyValue(CredentialPublicKey::class, $o, 'kty', 1000);
        $this->setPropertyValue(CredentialPublicKey::class, $o, 'alg', CredentialPublicKey::EC2_ES256);

        $this->expectException(WebauthnException::class);
        $this->runPrivateProtectedMethod($o, 'create', [[-1 => 0, -2 => 0, -3 => 0]]);
    }

    public function testCreateESInvalidAlgo(): void
    {
        $data = getCborAuthenticatorDataTestData();
        $endOffset = 87;
        $o = new CredentialPublicKey($data, 87, $endOffset);

        $this->setPropertyValue(CredentialPublicKey::class, $o, 'kty', AuthenticatorData::EC2_TYPE);
        $this->setPropertyValue(CredentialPublicKey::class, $o, 'alg', 1000);

        $this->expectException(WebauthnException::class);
        $this->runPrivateProtectedMethod($o, 'createES256', [[-1 => 0, -2 => 0, -3 => 0]]);
    }

    public function testCreateESInvalidCurve(): void
    {
        $data = getCborAuthenticatorDataTestData();
        $endOffset = 87;
        $o = new CredentialPublicKey($data, 87, $endOffset);

        $this->setPropertyValue(CredentialPublicKey::class, $o, 'kty', AuthenticatorData::EC2_TYPE);
        $this->setPropertyValue(CredentialPublicKey::class, $o, 'alg', CredentialPublicKey::EC2_ES256);

        $this->expectException(WebauthnException::class);
        $this->runPrivateProtectedMethod($o, 'createES256', [[-1 => 0, -2 => 0, -3 => 0]]);
    }

    public function testCreateESInvalidXCoordinate(): void
    {
        $data = getCborAuthenticatorDataTestData();
        $endOffset = 87;
        $o = new CredentialPublicKey($data, 87, $endOffset);

        $this->setPropertyValue(CredentialPublicKey::class, $o, 'kty', AuthenticatorData::EC2_TYPE);
        $this->setPropertyValue(CredentialPublicKey::class, $o, 'alg', CredentialPublicKey::EC2_ES256);

        $this->expectException(WebauthnException::class);
        $this->runPrivateProtectedMethod($o, 'createES256', [[-1 => CredentialPublicKey::EC2_P256, -2 => 0, -3 => 0]]);
    }

    public function testCreateESInvalidYCoordinate(): void
    {
        $data = getCborAuthenticatorDataTestData();
        $endOffset = 87;
        $o = new CredentialPublicKey($data, 87, $endOffset);

        $this->setPropertyValue(CredentialPublicKey::class, $o, 'kty', AuthenticatorData::EC2_TYPE);
        $this->setPropertyValue(CredentialPublicKey::class, $o, 'alg', CredentialPublicKey::EC2_ES256);

        $this->expectException(WebauthnException::class);
        $this->runPrivateProtectedMethod(
            $o,
            'createES256',
            [
                [
                    -1 => CredentialPublicKey::EC2_P256,
                    -2 => new ByteBuffer(str_repeat('q', 32)),
                    -3 => 0
                ]
            ]
        );
    }

    public function testCreateESSuccess(): void
    {
        $data = getCborAuthenticatorDataTestData();
        $endOffset = 87;
        $o = new CredentialPublicKey($data, 87, $endOffset);

        $this->setPropertyValue(CredentialPublicKey::class, $o, 'kty', AuthenticatorData::EC2_TYPE);
        $this->setPropertyValue(CredentialPublicKey::class, $o, 'alg', CredentialPublicKey::EC2_ES256);

        $this->runPrivateProtectedMethod(
            $o,
            'create',
            [
                [
                    -1 => CredentialPublicKey::EC2_P256,
                    -2 => new ByteBuffer(str_repeat('q', 32)),
                    -3 => new ByteBuffer(str_repeat('q', 32)),
                ]
            ]
        );

        $this->assertEquals(CredentialPublicKey::EC2_P256, $o->getCrv());
    }


    public function testJson(): void
    {
        $data = getCborAuthenticatorDataTestData();
        $endOffset = 87;
        $o = new CredentialPublicKey($data, 87, $endOffset);

        $json = $o->jsonSerialize();

        $this->assertCount(7, $json);
    }
}
