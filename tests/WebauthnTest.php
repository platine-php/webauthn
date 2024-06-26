<?php

declare(strict_types=1);

namespace Platine\Test\Webauthn;

use org\bovigo\vfs\vfsStream;
use Platine\Dev\PlatineTestCase;
use Platine\Webauthn\Attestation\AttestationData;
use Platine\Webauthn\Attestation\AuthenticatorData;
use Platine\Webauthn\Entity\PublicKey;
use Platine\Webauthn\Entity\RelyingParty;
use Platine\Webauthn\Enum\KeyFormat;
use Platine\Webauthn\Enum\UserVerificationType;
use Platine\Webauthn\Exception\WebauthnException;
use Platine\Webauthn\Webauthn;
use Platine\Webauthn\WebauthnConfiguration;

use function Platine\Test\Fixture\Webauthn\getAuthClientDataJson;
use function Platine\Test\Fixture\Webauthn\getCborAttestationDataTestData;
use function Platine\Test\Fixture\Webauthn\getCborAuthenticatorDataTestData;
use function Platine\Test\Fixture\Webauthn\getCborRegistrationAttestationDataTestData;
use function Platine\Test\Fixture\Webauthn\getRegistrationClientDataJson;

/**
 * Webauthn class tests
 *
 * @group core
 * @group webauth
 */
class WebauthnTest extends PlatineTestCase
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

    public function testConstructorDefault(): void
    {
        $cfg = new WebauthnConfiguration([]);
        $o = new Webauthn($cfg);

        $this->assertInstanceOf(
            WebauthnConfiguration::class,
            $this->getPropertyValue(Webauthn::class, $o, 'config')
        );
        $this->assertInstanceOf(Webauthn::class, $o);
        $this->assertNull($o->getChallenge());
    }

    public function testConstructorMissingOpenSSL(): void
    {
        global $mock_function_exists_to_false;
        $mock_function_exists_to_false = true;

        $this->expectException(WebauthnException::class);
        $cfg = new WebauthnConfiguration([]);
        $o = new Webauthn($cfg);
    }

    public function testConstructorMissingOpenSSLSha256(): void
    {
        global $mock_openssl_get_md_methods_to_empty;
        $mock_openssl_get_md_methods_to_empty = true;

        $this->expectException(WebauthnException::class);
        $cfg = new WebauthnConfiguration([]);
        $o = new Webauthn($cfg);
    }

    public function testConstructorCustomFormats(): void
    {
        $cfg = new WebauthnConfiguration([]);
        $o = new Webauthn($cfg, [KeyFormat::ANDROID_KEY]);

        $this->assertInstanceOf(
            WebauthnConfiguration::class,
            $this->getPropertyValue(Webauthn::class, $o, 'config')
        );
        $this->assertInstanceOf(Webauthn::class, $o);

        $formats = $this->getPropertyValue(Webauthn::class, $o, 'formats');
        $this->assertCount(1, $formats);
        $this->assertEquals(KeyFormat::ANDROID_KEY, $formats[0]);
    }


    public function testConstructFormatNotSupported(): void
    {
        $cfg = new WebauthnConfiguration([]);
        $o = new Webauthn($cfg, ['foobar']);

        $formats = $this->getPropertyValue(Webauthn::class, $o, 'formats');
        $this->assertCount(7, $formats);
    }

    public function testAddRootCertificate(): void
    {
        global $mock_realpath_to_foodir;

        $mock_realpath_to_foodir = true;
        $cfg = new WebauthnConfiguration([]);
        $o = new Webauthn($cfg);

        $file1 = $this->createVfsFile('cert1.pem', $this->vfsTestPath, 'CERT1');
        $file2 = $this->createVfsFile('cert2.pem', $this->vfsTestPath, 'CERT2');

        $o->addRootCertificate($file1->url());
        $o->addRootCertificate([$file2->url()]);

        $paths = $this->getPropertyValue(Webauthn::class, $o, 'certificates');
        $this->assertCount(2, $paths);
    }

    public function testGetRegistrationParams(): void
    {
        global $mock_random_bytes_to_value,
                $mock_function_exists_byte_buffer,
                $mock_realpath_to_foodir;

        $mock_random_bytes_to_value = 'foo';
        $mock_function_exists_byte_buffer = true;
        $mock_realpath_to_foodir = true;

        $cfg = new WebauthnConfiguration([]);
        $o = new Webauthn($cfg);

        $file1 = $this->createVfsFile('cert1.pem', $this->vfsTestPath, 'CERT1');

        $o->addRootCertificate($file1->url());

        $publicKey = $o->getRegistrationParams(
            '1',
            'tnh',
            'Tony',
            UserVerificationType::PREFERRED,
            false,
            ['1111'],
            true
        );
        $this->assertInstanceOf(PublicKey::class, $publicKey);
        $this->assertEquals(60000, $publicKey->getTimeout());
        $this->assertEquals('none', $publicKey->getAttestation());
        $this->assertEquals('', $publicKey->getUserVerificationType());
        $this->assertEquals('random_bytes_32', $publicKey->getChallenge()->getBinaryString());
    }

    public function testGetRegistrationParamsExcludeCredentialFailedHextobin(): void
    {
        global $mock_random_bytes_to_value,
                $mock_function_exists_byte_buffer,
                $mock_hex2bin_to_false;

        $mock_random_bytes_to_value = 'foo';
        $mock_function_exists_byte_buffer = true;
        $mock_hex2bin_to_false = true;

        $cfg = new WebauthnConfiguration([]);
        $o = new Webauthn($cfg);

        $this->expectException(WebauthnException::class);
        $o->getRegistrationParams(
            '1',
            'tnh',
            'Tony',
            UserVerificationType::PREFERRED,
            false,
            ['1'],
            true
        );
    }


    public function testAuthenticationParams(): void
    {
        global $mock_random_bytes_to_value,
                $mock_function_exists_byte_buffer;

        $mock_random_bytes_to_value = 'foo';
        $mock_function_exists_byte_buffer = true;

        $cfg = new WebauthnConfiguration([]);
        $o = new Webauthn($cfg);

        $publicKey = $o->getAuthenticationParams(
            UserVerificationType::REQUIRED,
            ['1111'],
        );
        $this->assertInstanceOf(PublicKey::class, $publicKey);
        $this->assertEquals(60000, $publicKey->getTimeout());
        $this->assertEquals('', $publicKey->getAttestation());
        $this->assertEquals('required', $publicKey->getUserVerificationType());
        $this->assertEquals('localhost', $publicKey->getRelyingPartyId());
        $this->assertEquals('random_bytes_32', $publicKey->getChallenge()->getBinaryString());
    }

    public function testAuthenticationParamsAllowCredentialFailedHextobin(): void
    {
        global $mock_random_bytes_to_value,
                $mock_function_exists_byte_buffer,
                $mock_hex2bin_to_false;

        $mock_random_bytes_to_value = 'foo';
        $mock_function_exists_byte_buffer = true;
        $mock_hex2bin_to_false = true;

        $cfg = new WebauthnConfiguration([]);
        $o = new Webauthn($cfg);

        $this->expectException(WebauthnException::class);
        $o->getAuthenticationParams(
            UserVerificationType::REQUIRED,
            ['1111'],
        );
    }

    public function testProcessRegistrationInvalidClientJson(): void
    {
        $cfg = new WebauthnConfiguration([]);
        $o = new Webauthn($cfg);

        $challenge = 'foochallenge';
        $clientDataJson = '{f';
        $attestationObject = getCborAttestationDataTestData();

        $this->expectException(WebauthnException::class);
        $o->processRegistration(
            $clientDataJson,
            $attestationObject,
            $challenge,
            false,
            true,
            true
        );
    }

    public function testProcessRegistrationInvalidChallenge(): void
    {
        $cfg = new WebauthnConfiguration([]);
        $o = new Webauthn($cfg);

        $challenge = 'foochallenge';
        $clientDataJson = getRegistrationClientDataJson();
        $attestationObject = getCborAttestationDataTestData();

        $this->expectException(WebauthnException::class);
        $o->processRegistration(
            $clientDataJson,
            $attestationObject,
            $challenge,
            false,
            true,
            true
        );
    }

    public function testProcessRegistrationInvalidOrigin(): void
    {
        $cfg = new WebauthnConfiguration([]);
        $o = new Webauthn($cfg);

        $challenge = base64_decode('KXODAvwL2IfhAu8t0fEKcJ9E96sHMkhi8pFIzo675i8');
        $clientDataJson = base64_decode(
            'eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiS1hPREF2d0wySW'
                . 'ZoQXU4dDBmRUtjSjlFOTZzSE1raGk4cEZJem82NzVpOCIsIm9yaWdpbiI6'
                . 'Imh0dHA6Ly9sb2NhbGhvc3QuY29tIiwiY3Jvc3NPcmlnaW4iOmZhbHNlfQ'
        );
        $attestationObject = getCborAttestationDataTestData();

        $this->expectException(WebauthnException::class);
        $o->processRegistration(
            $clientDataJson,
            $attestationObject,
            $challenge,
            false,
            true,
            true
        );
    }

    public function testProcessRegistrationInvalidOriginScheme(): void
    {
        $cfg = new WebauthnConfiguration([
            'relying_party_id' => 'platine.com'
        ]);
        $o = new Webauthn($cfg);

        $challenge = base64_decode('KXODAvwL2IfhAu8t0fEKcJ9E96sHMkhi8pFIzo675i8');
        $clientDataJson = base64_decode(
            'eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiS1hPREF2d0wy'
                . 'SWZoQXU4dDBmRUtjSjlFOTZzSE1raGk4cEZJem82NzVpOCIsIm9yaWdpbi'
                . 'I6Imh0dHA6Ly9wbGF0aW5lLmNvbSIsImNyb3NzT3JpZ2luIjpmYWxzZX0'
        );
        $attestationObject = getCborAttestationDataTestData();

        $this->expectException(WebauthnException::class);
        $o->processRegistration(
            $clientDataJson,
            $attestationObject,
            $challenge,
            false,
            true,
            true
        );
    }

    public function testProcessRegistrationInvalidRelyingId(): void
    {
        $cfg = new WebauthnConfiguration([]);
        $o = new Webauthn($cfg);

        $relyingParty = $this->getMockInstance(RelyingParty::class, [
            'getHashId' => '1',
            'getId' => 'localhost',
        ]);
        $this->setPropertyValue(Webauthn::class, $o, 'relyingParty', $relyingParty);
        $challenge = base64_decode('rB8+2+FiHg9N4SC6lGgLu53fhszdE1/NJZZx/wQqBzA=');
        $clientDataJson = getRegistrationClientDataJson();
        $attestationObject = getCborAttestationDataTestData();

        $this->expectException(WebauthnException::class);
        $o->processRegistration(
            $clientDataJson,
            $attestationObject,
            $challenge,
            false,
            true,
            true
        );
    }

    public function testProcessRegistrationInvalidClientDataProvided(): void
    {
        $cfg = new WebauthnConfiguration([]);
        $o = new Webauthn($cfg);

        $relyingParty = $this->getMockInstance(RelyingParty::class, [
            'getHashId' => '1',
            'getId' => 'localhost',
        ]);
        $this->setPropertyValue(Webauthn::class, $o, 'relyingParty', $relyingParty);
        $challenge = base64_decode('rB8+2+FiHg9N4SC6lGgLu53fhszdE1/NJZZx/wQqBzA=');
        $clientDataJson = getRegistrationClientDataJson();
        $attestationObject = getCborAttestationDataTestData();

        $this->expectException(WebauthnException::class);
        $o->processRegistration(
            $clientDataJson,
            $attestationObject,
            $challenge,
            false,
            true,
            true
        );
    }

    public function testProcessRegistrationInvalidRootCertificate(): void
    {
        global $mock_realpath_to_foodir;

        $mock_realpath_to_foodir = true;

        $cfg = new WebauthnConfiguration([]);
        $o = new Webauthn($cfg);

        $file1 = $this->createVfsFile('cert1.pem', $this->vfsTestPath, 'CERT1');

        $o->addRootCertificate($file1->url());


        $challenge = base64_decode('rB8+2+FiHg9N4SC6lGgLu53fhszdE1/NJZZx/wQqBzA=');
        $clientDataJson = getRegistrationClientDataJson();
        $attestationObject = getCborAttestationDataTestData();

        $this->expectException(WebauthnException::class);
        $o->processRegistration(
            $clientDataJson,
            $attestationObject,
            $challenge,
            false,
            true,
            true
        );
    }

    public function testProcessRegistrationInvalidClientType(): void
    {
        $cfg = new WebauthnConfiguration([]);
        $o = new Webauthn($cfg);

        $challenge = 'foochallenge';
        $clientDataJson = getAuthClientDataJson();
        $attestationObject = getCborAttestationDataTestData();

        $this->expectException(WebauthnException::class);
        $o->processRegistration(
            $clientDataJson,
            $attestationObject,
            $challenge,
            false,
            true,
            true
        );
    }

    public function testProcessRegistrationUserIsNotPresent(): void
    {
        global $mock_unpack_to_array;

        $mock_unpack_to_array = [
            'Cflags' => ['flags' => 24]
        ];

        $cfg = new WebauthnConfiguration([]);
        $o = new Webauthn($cfg);

        $challenge = base64_decode('rB8+2+FiHg9N4SC6lGgLu53fhszdE1/NJZZx/wQqBzA=');
        $clientDataJson = getRegistrationClientDataJson();
        $attestationObject = getCborRegistrationAttestationDataTestData();

        $this->expectException(WebauthnException::class);
        $o->processRegistration(
            $clientDataJson,
            $attestationObject,
            $challenge,
            false,
            true,
            true
        );
    }

    public function testProcessRegistrationUserIsNotVerified(): void
    {
        global $mock_unpack_to_array;

        $mock_unpack_to_array = [
            'Cflags' => ['flags' => 65]
        ];

        $cfg = new WebauthnConfiguration([]);
        $o = new Webauthn($cfg);

        $challenge = base64_decode('rB8+2+FiHg9N4SC6lGgLu53fhszdE1/NJZZx/wQqBzA=');
        $clientDataJson = getRegistrationClientDataJson();
        $attestationObject = getCborRegistrationAttestationDataTestData();

        $this->expectException(WebauthnException::class);
        $o->processRegistration(
            $clientDataJson,
            $attestationObject,
            $challenge,
            true,
            true,
            true
        );
    }

    public function testProcessRegistrationInvalidCertificateSignature(): void
    {
        $rp = $this->getMockInstance(RelyingParty::class);
        $authData = $this->getMockInstance(AuthenticatorData::class);
        $attesData = $this->getMockInstance(AttestationData::class, [
            'getAuthenticatorData' => $authData,
            'validateRelyingPartyIdHash' => true,
        ]);

        $o = $this->getMockInstance(Webauthn::class, [
            'createAttestationData' => $attesData,
            'checkOrigin' => true,
        ], [
            'processRegistration',
        ]);
        $this->setPropertyValue(Webauthn::class, $o, 'relyingParty', $rp);

        $challenge = base64_decode('rB8+2+FiHg9N4SC6lGgLu53fhszdE1/NJZZx/wQqBzA=');
        $clientDataJson = getRegistrationClientDataJson();
        $attestationObject = getCborRegistrationAttestationDataTestData();

        $this->expectException(WebauthnException::class);
        $o->processRegistration(
            $clientDataJson,
            $attestationObject,
            $challenge,
            true,
            true,
            true
        );
    }

    public function testProcessRegistrationSuccess(): void
    {
        global $mock_unpack_to_array;

        $mock_unpack_to_array = [
            'Nsigncount' => ['signcount' => 24]
        ];
        $cfg = new WebauthnConfiguration([]);
        $o = new Webauthn($cfg);

        $challenge = base64_decode('rB8+2+FiHg9N4SC6lGgLu53fhszdE1/NJZZx/wQqBzA=');
        $clientDataJson = getRegistrationClientDataJson();
        $attestationObject = getCborRegistrationAttestationDataTestData();

        $data = $o->processRegistration(
            $clientDataJson,
            $attestationObject,
            $challenge,
            false,
            true,
            true
        );
        $this->assertCount(13, $data);
        $this->assertEquals('localhost', $data['rp_id']);
        $this->assertEquals('none', $data['attestation_format']);
        $this->assertEquals('95d8dc552da5cb3f45328a0a3c413360ec639d12c31c25293d5cdf71f94aa8fb', $data['credential_id']);
        $this->assertNotEmpty($data['credential_public_key']);
        $this->assertNull($data['cert_chain']);
        $this->assertNull($data['cert']);
        $this->assertEquals('', $data['cert_issuer']);
        $this->assertEquals('', $data['cert_subject']);
        $this->assertFalse($data['is_root_cert_valid']);
        $this->assertEquals(24, $data['signature_counter']);
        $this->assertEquals('00000000000000000000000000000000', $data['aaguid']);
        $this->assertTrue($data['is_user_present']);
        $this->assertTrue($data['is_user_verified']);
    }

    public function testProcessAuthInvalidClientJson(): void
    {
        $cfg = new WebauthnConfiguration([]);
        $o = new Webauthn($cfg);

        $challenge = 'foochallenge';
        $signature = 'signature';
        $credentialPublicKey = 'credentialPublicKey';
        $clientDataJson = '{f';
        $authenticatorData = getCborAuthenticatorDataTestData();

        $this->expectException(WebauthnException::class);
        $o->processAuthentication(
            $clientDataJson,
            $authenticatorData,
            $signature,
            $credentialPublicKey,
            $challenge,
            null,
            true,
            true
        );
    }

    public function testProcessAuthInvalidClientType(): void
    {
        $cfg = new WebauthnConfiguration([]);
        $o = new Webauthn($cfg);

        $challenge = 'foochallenge';
        $signature = 'signature';
        $credentialPublicKey = 'credentialPublicKey';
        $clientDataJson = getRegistrationClientDataJson();
        $authenticatorData = getCborAuthenticatorDataTestData();

        $this->expectException(WebauthnException::class);
        $o->processAuthentication(
            $clientDataJson,
            $authenticatorData,
            $signature,
            $credentialPublicKey,
            $challenge,
            null,
            true,
            true
        );
    }

    public function testProcessAuthInvalidChallenge(): void
    {
        $cfg = new WebauthnConfiguration([]);
        $o = new Webauthn($cfg);

        $challenge = 'foochallenge';
        $signature = 'signature';
        $credentialPublicKey = 'credentialPublicKey';
        $clientDataJson = getAuthClientDataJson();
        $authenticatorData = getCborAuthenticatorDataTestData();

        $this->expectException(WebauthnException::class);
        $o->processAuthentication(
            $clientDataJson,
            $authenticatorData,
            $signature,
            $credentialPublicKey,
            $challenge,
            null,
            true,
            true
        );
    }

    public function testProcessAuthInvalidOrigin(): void
    {
        $cfg = new WebauthnConfiguration([
            'relying_party_id' => 'platine.com'
        ]);
        $o = new Webauthn($cfg);

        $challenge = base64_decode('HWE2iUXeza6DQSL23+SgTpgh4N/z9OJfopSU6w6J3u8');
        $signature = 'signature';
        $credentialPublicKey = 'credentialPublicKey';
        $clientDataJson = getAuthClientDataJson();
        $authenticatorData = getCborAuthenticatorDataTestData();

        $this->expectException(WebauthnException::class);
        $o->processAuthentication(
            $clientDataJson,
            $authenticatorData,
            $signature,
            $credentialPublicKey,
            $challenge,
            null,
            true,
            true
        );
    }

    public function testProcessAuthInvalidRelyingPartidIdHash(): void
    {
        $cfg = new WebauthnConfiguration([]);
        $o = new Webauthn($cfg);

        $relyingParty = $this->getMockInstance(RelyingParty::class, [
            'getHashId' => '1',
            'getId' => 'localhost',
        ]);
        $this->setPropertyValue(Webauthn::class, $o, 'relyingParty', $relyingParty);

        $challenge = base64_decode('HWE2iUXeza6DQSL23+SgTpgh4N/z9OJfopSU6w6J3u8');
        $signature = 'signature';
        $credentialPublicKey = 'credentialPublicKey';
        $clientDataJson = getAuthClientDataJson();
        $authenticatorData = getCborAuthenticatorDataTestData();

        $this->expectException(WebauthnException::class);
        $o->processAuthentication(
            $clientDataJson,
            $authenticatorData,
            $signature,
            $credentialPublicKey,
            $challenge,
            null,
            true,
            true
        );
    }

    public function testProcessAuthUserIsNotPresent(): void
    {
        global $mock_openssl_pkey_get_public_to_value,
                $mock_openssl_verify_to_value,
                $mock_unpack_to_array;

        $mock_unpack_to_array = [
            'Cflags' => ['flags' => 24]
        ];
        $mock_openssl_pkey_get_public_to_value = true;
        $mock_openssl_verify_to_value = 1;

        $cfg = new WebauthnConfiguration([]);
        $o = new Webauthn($cfg);

        $challenge = base64_decode('HWE2iUXeza6DQSL23+SgTpgh4N/z9OJfopSU6w6J3u8');
        $signature = 'signature';
        $credentialPublicKey = 'credentialPublicKey';
        $clientDataJson = getAuthClientDataJson();
        $authenticatorData = getCborAuthenticatorDataTestData();

        $this->expectException(WebauthnException::class);
        $o->processAuthentication(
            $clientDataJson,
            $authenticatorData,
            $signature,
            $credentialPublicKey,
            $challenge,
            null,
            true,
            true
        );
    }

    public function testProcessAuthUserIsNotVerified(): void
    {
        global $mock_openssl_pkey_get_public_to_value,
                $mock_openssl_verify_to_value,
                $mock_unpack_to_array;

        $mock_unpack_to_array = [
            'Cflags' => ['flags' => 65]
        ];
        $mock_openssl_pkey_get_public_to_value = true;
        $mock_openssl_verify_to_value = 1;

        $cfg = new WebauthnConfiguration([]);
        $o = new Webauthn($cfg);

        $challenge = base64_decode('HWE2iUXeza6DQSL23+SgTpgh4N/z9OJfopSU6w6J3u8');
        $signature = 'signature';
        $credentialPublicKey = 'credentialPublicKey';
        $clientDataJson = getAuthClientDataJson();
        $authenticatorData = getCborAuthenticatorDataTestData();

        $this->expectException(WebauthnException::class);
        $o->processAuthentication(
            $clientDataJson,
            $authenticatorData,
            $signature,
            $credentialPublicKey,
            $challenge,
            null,
            true,
            true
        );
    }

    public function testProcessAuthInvalidSignature(): void
    {
        global $mock_openssl_pkey_get_public_to_value, $mock_openssl_verify_to_value;

        $mock_openssl_pkey_get_public_to_value = true;
        $mock_openssl_verify_to_value = -1;

        $cfg = new WebauthnConfiguration([]);
        $o = new Webauthn($cfg);

        $challenge = base64_decode('HWE2iUXeza6DQSL23+SgTpgh4N/z9OJfopSU6w6J3u8');
        $signature = 'signature';
        $credentialPublicKey = 'credentialPublicKey';
        $clientDataJson = getAuthClientDataJson();
        $authenticatorData = getCborAuthenticatorDataTestData();

        $this->expectException(WebauthnException::class);
        $o->processAuthentication(
            $clientDataJson,
            $authenticatorData,
            $signature,
            $credentialPublicKey,
            $challenge,
            null,
            true,
            true
        );
    }

    public function testProcessAuthInvalidPublickKey(): void
    {
        $cfg = new WebauthnConfiguration([]);
        $o = new Webauthn($cfg);

        $challenge = base64_decode('HWE2iUXeza6DQSL23+SgTpgh4N/z9OJfopSU6w6J3u8');
        $signature = 'signature';
        $credentialPublicKey = 'credentialPublicKey';
        $clientDataJson = getAuthClientDataJson();
        $authenticatorData = getCborAuthenticatorDataTestData();

        $this->expectException(WebauthnException::class);
        $o->processAuthentication(
            $clientDataJson,
            $authenticatorData,
            $signature,
            $credentialPublicKey,
            $challenge,
            null,
            true,
            true
        );
    }
    public function testProcessAuthInvalidSignatureCounter(): void
    {
        global $mock_openssl_pkey_get_public_to_value, $mock_openssl_verify_to_value;

        $mock_openssl_pkey_get_public_to_value = true;
        $mock_openssl_verify_to_value = 1;

        $rp = $this->getMockInstance(RelyingParty::class);
        $authData = $this->getMockInstance(AuthenticatorData::class, [
            'isUserPresent' => true,
            'isUserVerified' => true,
            'getSignatureCount' => 1,
        ]);

        $o = $this->getMockInstance(Webauthn::class, [
            'createAuthenticatorData' => $authData,
            'checkOrigin' => true,
        ], [
            'processAuthentication',
        ]);
        $this->setPropertyValue(Webauthn::class, $o, 'relyingParty', $rp);

        $challenge = base64_decode('HWE2iUXeza6DQSL23+SgTpgh4N/z9OJfopSU6w6J3u8');
        $signature = 'signature';
        $credentialPublicKey = 'credentialPublicKey';
        $clientDataJson = getAuthClientDataJson();
        $authenticatorData = getCborAuthenticatorDataTestData();

        $this->expectException(WebauthnException::class);
        $o->processAuthentication(
            $clientDataJson,
            $authenticatorData,
            $signature,
            $credentialPublicKey,
            $challenge,
            4,
            true,
            true
        );
    }

    public function testProcessAuthSuccess(): void
    {
        global $mock_openssl_pkey_get_public_to_value, $mock_openssl_verify_to_value;

        $mock_openssl_pkey_get_public_to_value = true;
        $mock_openssl_verify_to_value = 1;

        $cfg = new WebauthnConfiguration([]);
        $o = new Webauthn($cfg);

        $challenge = base64_decode('HWE2iUXeza6DQSL23+SgTpgh4N/z9OJfopSU6w6J3u8');
        $signature = 'signature';
        $credentialPublicKey = 'credentialPublicKey';
        $clientDataJson = getAuthClientDataJson();
        $authenticatorData = getCborAuthenticatorDataTestData();

        $res = $o->processAuthentication(
            $clientDataJson,
            $authenticatorData,
            $signature,
            $credentialPublicKey,
            $challenge,
            null,
            true,
            true
        );

        $this->assertTrue($res);
        $this->assertEquals(0, $o->getSignatureCounter());
    }
}
