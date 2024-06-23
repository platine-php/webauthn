<?php

declare(strict_types=1);

namespace Platine\Test\Webauthn\Attestation;

use Platine\Dev\PlatineTestCase;
use Platine\Webauthn\Attestation\AuthenticatorData;
use Platine\Webauthn\Entity\AttestedCredentialData;
use Platine\Webauthn\Entity\CredentialPublicKey;
use Platine\Webauthn\Exception\WebauthnException;

use function Platine\Test\Fixture\Webauthn\getCborAuthenticatorDataTestData;
use function Platine\Test\Fixture\Webauthn\getPublicKeyPemTestData;

/**
 * AuthenticatorData class tests
 *
 * @group core
 * @group webauth
 */
class AuthenticatorDataTest extends PlatineTestCase
{
    public function testConstructor(): void
    {
        $binary = getCborAuthenticatorDataTestData();

        $o = new AuthenticatorData($binary);

        $this->assertTrue($o->isUserPresent());
        $this->assertTrue($o->isUserVerified());
        $this->assertEquals(0, $o->getSignatureCount());
        $this->assertCommandOutput(
            getPublicKeyPemTestData(),
            $o->getPublicKeyPEM()
        );

        $this->assertEquals('04', bin2hex($o->getPublicKeyU2F()));
        $this->assertEquals(
            '5b9f3e676deabc693d8c3d6be559cb8a91c919316a8b375dd22c385d4c123184',
            bin2hex($o->getCredentialId())
        );

        $this->assertEquals(
            '49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d97634'
                . '50000000008987058cadc4b81b6e130de50dcbe9600205b9f3e676deabc6'
                . '93d8c3d6be559cb8a91c919316a8b375dd22c385d4c123184a401030339'
                . '010020590100ab2a7f9b13fae1d2df33c1d2e5ad3d43be6131360d17cc38'
                . '78e1b8dc268deb6a4b78826d7c56b2e37ec29809ee2ce88a3ac09c0d961'
                . '124404eda6646180237609c579ee9b8a92274eb0b1740cd2c49d8d5991'
                . '2c30080d418cbb7e679923f086ea550d65d179a74f3f5567aaee36e2d'
                . '4786361f2d0a0942d35d2edef22972086681f043e83f133221eb413a8d5'
                . '269424d2d00e511259d4205166521a880507a0fcfd439a86be7bbf4b08'
                . 'ffd0a378edf39154a9bf5fa45bf7b8775422f4b90c8dea94bb390b104'
                . '509fcc554e458f04161417875aa7973dc4f305655364e734cf06a66bd'
                . 'e5094bae17a7ebf1edb5cf03b40ce6d6235fbaa7c4dfc1ee662009b5a'
                . 'd92143010001',
            bin2hex($o->getBinary())
        );

        $this->assertEquals(
            '08987058cadc4b81b6e130de50dcbe96',
            bin2hex($o->getAaguid())
        );

        $this->assertEquals(
            '49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d9763',
            bin2hex($o->getRelyingPartyIdHash())
        );
    }

    public function testConstructorInvalidBinaryLength(): void
    {
        $this->expectException(WebauthnException::class);
        (new AuthenticatorData('dddd'));
    }

    public function testConstructorCannotGetFlagsDetail(): void
    {
        global $mock_unpack_to_array;
        $mock_unpack_to_array = ['Cflags' => false];

        $binary = getCborAuthenticatorDataTestData();
        $this->expectException(WebauthnException::class);
        $o = new AuthenticatorData($binary);
    }

    public function testConstructorCannotGetSignatureCounter(): void
    {
        global $mock_unpack_to_array;
        $mock_unpack_to_array = [
            'Cflags' => ['flags' => 345],
            'Nsigncount' => false,
        ];

        $binary = getCborAuthenticatorDataTestData();
        $this->expectException(WebauthnException::class);
        $o = new AuthenticatorData($binary);
    }

    /**
     * @dataProvider attestedCredentialDataNotSetDataProvider
     * @param string $method
     * @param array<mixed> $params
     * @return void
     */
    public function testAttestedCredentialDataNotSet(string $method, array $params = []): void
    {
        $o = new AuthenticatorData(base64_decode('SZYN5YgOjGh0NBcPZHZgW4/krrmihjLHmVzzuoMdl2MFAAAAAQ=='));

        $this->expectException(WebauthnException::class);
        $o->{$method}(...$params);
    }

    public function testCreateExtensionDataInvalidResult(): void
    {
        global $mock_substr_to_value;
        $mock_substr_to_value = base64_decode('Y3RuaA==');

        $binary = getCborAuthenticatorDataTestData();

        $o = new AuthenticatorData($binary);
        $offset = 0;
        $this->expectException(WebauthnException::class);
        $this->runPrivateProtectedMethod($o, 'createExtensionData', [&$offset]);
    }

    public function testCreateExtensionDataSuccess(): void
    {
        global $mock_substr_to_value;
        $mock_substr_to_value = base64_decode('omFhAWFiAg==');
        $binary = getCborAuthenticatorDataTestData();

        $o = new AuthenticatorData($binary);
        $offset = 0;

        $this->runPrivateProtectedMethod($o, 'createExtensionData', [&$offset]);
        $extensionData = $o->getExtensionData();
        $this->assertIsArray($extensionData);
        $this->assertCount(2, $extensionData);
        $this->assertArrayHasKey('a', $extensionData);
        $this->assertArrayHasKey('b', $extensionData);
        $this->assertEquals(1, $extensionData['a']);
        $this->assertEquals(2, $extensionData['b']);
    }

    public function testGetDERUnsignedIntegerRemoveLeftZero(): void
    {
        $binary = getCborAuthenticatorDataTestData();

        $o = new AuthenticatorData($binary);
        $res = $this->runPrivateProtectedMethod($o, 'getDERUnsignedInteger', ["\0" . '1000']);
        $this->assertEquals('0203313030', bin2hex($res));
    }

    public function testGetRSADERMissingAttestedData(): void
    {
        $binary = getCborAuthenticatorDataTestData();

        $o = new AuthenticatorData($binary);
        $this->setPropertyValue(AuthenticatorData::class, $o, 'attestedCredentialData', null);

        $this->expectException(WebauthnException::class);
        $this->runPrivateProtectedMethod($o, 'getRSADER', []);
    }

    public function testGetEC2DER(): void
    {
        $binary = getCborAuthenticatorDataTestData();

        $o = new AuthenticatorData($binary);

        $res = $this->runPrivateProtectedMethod($o, 'getEC2DER', []);
        $this->assertEquals(
            '3019301306072a8648ce3d020106082a8648ce3d03010703020004',
            bin2hex($res)
        );
    }

    public function testGetPublicKeyPEMInvalidKTV(): void
    {
        $binary = getCborAuthenticatorDataTestData();

        $o = new AuthenticatorData($binary);
        $credentialPublicKey = $this->getMockInstance(CredentialPublicKey::class, [
            'getKty' => 12345,
        ]);
        $attestedCredentialData = $this->getMockInstance(AttestedCredentialData::class, [
            'getCredentialPublicKey' => $credentialPublicKey,
        ]);

        $this->setPropertyValue(
            AuthenticatorData::class,
            $o,
            'attestedCredentialData',
            $attestedCredentialData
        );

        $this->assertEquals($attestedCredentialData, $o->getAttestedCredentialData());

        $this->expectException(WebauthnException::class);
        $res = $o->getPublicKeyPEM();
        $this->assertEquals('3019301306072a8648ce3d020106082a8648ce3d03010703020004', bin2hex($res));
    }

    public function testGetPublicKeyPEMEC2(): void
    {
        $binary = getCborAuthenticatorDataTestData();

        $o = new AuthenticatorData($binary);
        $credentialPublicKey = $this->getMockInstance(CredentialPublicKey::class, [
            'getKty' => AuthenticatorData::EC2_TYPE,
        ]);
        $attestedCredentialData = $this->getMockInstance(AttestedCredentialData::class, [
            'getCredentialPublicKey' => $credentialPublicKey,
        ]);

        $this->setPropertyValue(
            AuthenticatorData::class,
            $o,
            'attestedCredentialData',
            $attestedCredentialData
        );

       // $this->expectException(WebauthnException::class);
        $res = $o->getPublicKeyPEM();
        $this->assertCommandOutput(
            '-----BEGIN PUBLIC KEY-----
MBkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDAgAE
-----END PUBLIC KEY-----
',
            $res
        );
    }

    public function testJson(): void
    {
        $binary = getCborAuthenticatorDataTestData();

        $o = new AuthenticatorData($binary);

        $json = $o->jsonSerialize();

        $this->assertCount(6, $json);
    }

    /**
     * Data provider for "testAttestedCredentialDataNotSet"
     * @return array<int, mixed>
     */
    public function attestedCredentialDataNotSetDataProvider(): array
    {
        return [
          [
              'getAaguid',
              [],
          ],
          [
              'getPublicKeyU2F',
              [],
          ],
          [
              'getPublicKeyPEM',
              [],
          ],
          [
              'getCredentialId',
              [],
          ],
        ];
    }
}
