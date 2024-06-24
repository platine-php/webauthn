<?php

declare(strict_types=1);

namespace Platine\Test\Webauthn\Attestation\Format;

use Platine\Dev\PlatineTestCase;
use Platine\Webauthn\Attestation\AuthenticatorData;
use Platine\Webauthn\Attestation\Format\Tpm;
use Platine\Webauthn\Exception\WebauthnException;
use Platine\Webauthn\Helper\ByteBuffer;

/**
 * Tpm class tests
 *
 * @group core
 * @group webauth
 */
class TpmTest extends PlatineTestCase
{
    public function testConstruct(): void
    {
        $data = [
            'attStmt' => [
                'ver' => '2.0',
                'alg' => -7,
                'sig' => new ByteBuffer('123'),
                'certInfo' => new ByteBuffer('123'),
                'pubArea' => new ByteBuffer('123'),
                'x5c' => [new ByteBuffer('123'), new ByteBuffer('123')]
            ],
        ];
        $authenticatorData = $this->getMockInstance(AuthenticatorData::class);
        $o = new Tpm($data, $authenticatorData);

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
            'attStmt' => [
                'ver' => '2.0',
                'alg' => 87,
                'sig' => new ByteBuffer('123'),
                'certInfo' => new ByteBuffer('123'),
                'pubArea' => new ByteBuffer('123'),
                'x5c' => [new ByteBuffer('123')]
            ],
        ];
        $authenticatorData = $this->getMockInstance(AuthenticatorData::class);
        $this->expectException(WebauthnException::class);
        $o = new Tpm($data, $authenticatorData);
    }

    public function testConstructInvalidVersion(): void
    {
        $data = [
            'attStmt' => [
                'ver' => '12.0',
                'alg' => -7,
                'sig' => new ByteBuffer('123'),
                'certInfo' => new ByteBuffer('123'),
                'pubArea' => new ByteBuffer('123'),
                'x5c' => [new ByteBuffer('123')]
            ],
        ];
        $authenticatorData = $this->getMockInstance(AuthenticatorData::class);
        $this->expectException(WebauthnException::class);
        $o = new Tpm($data, $authenticatorData);
    }

    public function testConstructInvalidSignature(): void
    {
        $data = [
            'attStmt' => [
                'ver' => '2.0',
                'alg' => -7,
                'sig' => null,
                'certInfo' => new ByteBuffer('123'),
                'pubArea' => new ByteBuffer('123'),
                'x5c' => [new ByteBuffer('123')]
            ],
        ];
        $authenticatorData = $this->getMockInstance(AuthenticatorData::class);
        $this->expectException(WebauthnException::class);
        $o = new Tpm($data, $authenticatorData);
    }

    public function testConstructInvalidCertInfo(): void
    {
        $data = [
            'attStmt' => [
                'ver' => '2.0',
                'alg' => -7,
                'sig' => new ByteBuffer('123'),
                'pubArea' => new ByteBuffer('123'),
                'x5c' => [new ByteBuffer('123')]
            ],
        ];
        $authenticatorData = $this->getMockInstance(AuthenticatorData::class);
        $this->expectException(WebauthnException::class);
        $o = new Tpm($data, $authenticatorData);
    }

    public function testConstructInvalidPubArea(): void
    {
        $data = [
            'attStmt' => [
                'ver' => '2.0',
                'alg' => -7,
                'sig' => new ByteBuffer('123'),
                'certInfo' => new ByteBuffer('123'),
                'x5c' => [new ByteBuffer('123')]
            ],
        ];
        $authenticatorData = $this->getMockInstance(AuthenticatorData::class);
        $this->expectException(WebauthnException::class);
        $o = new Tpm($data, $authenticatorData);
    }

    public function testConstructMissingX5C(): void
    {
        $data = [
            'attStmt' => [
                'ver' => '2.0',
                'alg' => -7,
                'sig' => new ByteBuffer('123'),
                'certInfo' => new ByteBuffer('123'),
                'pubArea' => new ByteBuffer('123'),
            ],
        ];
        $authenticatorData = $this->getMockInstance(AuthenticatorData::class);
        $this->expectException(WebauthnException::class);
        $o = new Tpm($data, $authenticatorData);
    }

    public function testConstructInvalidFirstX5C(): void
    {
        $data = [
            'attStmt' => [
                'ver' => '2.0',
                'alg' => -7,
                'sig' => new ByteBuffer('123'),
                'certInfo' => new ByteBuffer('123'),
                'pubArea' => new ByteBuffer('123'),
                'x5c' => [1],
            ],
        ];
        $authenticatorData = $this->getMockInstance(AuthenticatorData::class);
        $this->expectException(WebauthnException::class);
        $o = new Tpm($data, $authenticatorData);
    }

    public function testGetCertificatePemEmptyX5C(): void
    {
        $data = [
            'attStmt' => [
                'ver' => '2.0',
                'alg' => -7,
                'sig' => new ByteBuffer('123'),
                'certInfo' => new ByteBuffer('123'),
                'pubArea' => new ByteBuffer('123'),
                'x5c' => [new ByteBuffer('123'), new ByteBuffer('123')]
            ],
        ];
        $authenticatorData = $this->getMockInstance(AuthenticatorData::class);
        $o = new Tpm($data, $authenticatorData);

        $this->setPropertyValue(Tpm::class, $o, 'x5c', '');

        $this->assertNull($o->getCertificatePem());
    }

    public function testValidateAttestationInvalidExtractDataHash(): void
    {
        global $mock_openssl_verify_to_value,$mock_openssl_pkey_get_public_to_value;
        $data = [
            'attStmt' => [
                'ver' => '2.0',
                'alg' => -7,
                'sig' => new ByteBuffer('123'),
                'certInfo' => new ByteBuffer("\xFF\x54\x43\x47\x80\x17" . str_repeat('u', 60200)),
                'pubArea' => new ByteBuffer('123'),
                'x5c' => [new ByteBuffer('123'), new ByteBuffer('123')]
            ],
        ];
        $authenticatorData = $this->getMockInstance(AuthenticatorData::class, [
            'getBinary' => '123',
            'getPublicKeyPEM' => '123',
        ]);
        $o = new Tpm($data, $authenticatorData);

        $mock_openssl_pkey_get_public_to_value = 'hhh';
        $mock_openssl_verify_to_value = 1;

        $this->expectException(WebauthnException::class);
        $o->validateAttestation('123');
    }

    public function testValidateAttestationInvalidTPMGeneratedValue(): void
    {
        global $mock_openssl_verify_to_value,$mock_openssl_pkey_get_public_to_value;
        $data = [
            'attStmt' => [
                'ver' => '2.0',
                'alg' => -7,
                'sig' => new ByteBuffer('123'),
                'certInfo' => new ByteBuffer("\xFF\x54\x43" . str_repeat('a', 67)),
                'pubArea' => new ByteBuffer('123'),
                'x5c' => [new ByteBuffer('123'), new ByteBuffer('123')]
            ],
        ];
        $authenticatorData = $this->getMockInstance(AuthenticatorData::class, [
            'getBinary' => '123',
            'getPublicKeyPEM' => '123',
        ]);
        $o = new Tpm($data, $authenticatorData);

        $mock_openssl_pkey_get_public_to_value = 'hhh';
        $mock_openssl_verify_to_value = 1;

        $this->expectException(WebauthnException::class);
        $o->validateAttestation('123');
    }

    public function testValidateAttestationInvalidTPMStAttestCertify(): void
    {
        global $mock_openssl_verify_to_value,$mock_openssl_pkey_get_public_to_value;
        $data = [
            'attStmt' => [
                'ver' => '2.0',
                'alg' => -7,
                'sig' => new ByteBuffer('123'),
                'certInfo' => new ByteBuffer("\xFF\x54\x43\x47" . str_repeat('a', 67)),
                'pubArea' => new ByteBuffer('123'),
                'x5c' => [new ByteBuffer('123'), new ByteBuffer('123')]
            ],
        ];
        $authenticatorData = $this->getMockInstance(AuthenticatorData::class, [
            'getBinary' => '123',
            'getPublicKeyPEM' => '123',
        ]);
        $o = new Tpm($data, $authenticatorData);

        $mock_openssl_pkey_get_public_to_value = 'hhh';
        $mock_openssl_verify_to_value = 1;

        $this->expectException(WebauthnException::class);
        $o->validateAttestation('123');
    }

    public function testValidateAttestationInvalidCoseAlgo(): void
    {
        global $mock_openssl_verify_to_value,$mock_openssl_pkey_get_public_to_value;
        $data = [
            'attStmt' => [
                'ver' => '2.0',
                'alg' => -7,
                'sig' => new ByteBuffer('123'),
                'certInfo' => new ByteBuffer("\xFF\x54\x43\x47\x80\x17" . str_repeat('u', 60200)),
                'pubArea' => new ByteBuffer('123'),
                'x5c' => [new ByteBuffer('123'), new ByteBuffer('123')]
            ],
        ];
        $authenticatorData = $this->getMockInstance(AuthenticatorData::class, [
            'getBinary' => '123',
            'getPublicKeyPEM' => '123',
        ]);
        $o = new Tpm($data, $authenticatorData);
        $this->setPropertyValue(Tpm::class, $o, 'algo', 89);

        $mock_openssl_pkey_get_public_to_value = 'hhh';
        $mock_openssl_verify_to_value = 1;

        $this->expectException(WebauthnException::class);
        $o->validateAttestation('123');
    }

    public function testValidateAttestationSuccess(): void
    {
        global $mock_openssl_verify_to_value,$mock_openssl_pkey_get_public_to_value, $mock_hash_to_value;
        $data = [
            'attStmt' => [
                'ver' => '2.0',
                'alg' => -7,
                'sig' => new ByteBuffer('123'),
                'certInfo' => new ByteBuffer("\xFF\x54\x43\x47\x80\x17" . str_repeat('u', 60200)),
                'pubArea' => new ByteBuffer('123'),
                'x5c' => [new ByteBuffer('123'), new ByteBuffer('123')]
            ],
        ];
        $authenticatorData = $this->getMockInstance(AuthenticatorData::class, [
            'getBinary' => '123',
            'getPublicKeyPEM' => '123',
        ]);
        $o = new Tpm($data, $authenticatorData);

        $mock_openssl_pkey_get_public_to_value = 'hhh';
        $mock_openssl_verify_to_value = 1;
        $mock_hash_to_value = str_repeat('u', 30069);

        $this->assertTrue($o->validateAttestation('123'));
    }

    public function testValidateAttestationX5CInvalidPem(): void
    {
        global  $mock_openssl_pkey_get_public_to_value;
        $data = [
            'attStmt' => [
                'ver' => '2.0',
                'alg' => -7,
                'sig' => new ByteBuffer('123'),
                'certInfo' => new ByteBuffer('123'),
                'pubArea' => new ByteBuffer('123'),
                'x5c' => [new ByteBuffer('123'), new ByteBuffer('123')]
            ],
        ];
        $authenticatorData = $this->getMockInstance(AuthenticatorData::class, [
            'getBinary' => '123',
            'getPublicKeyPEM' => '123',
        ]);
        $o = new Tpm($data, $authenticatorData);

        $mock_openssl_pkey_get_public_to_value = false;

        $this->expectException(WebauthnException::class);
        $o->validateAttestation('123');
    }

    public function testValidateRootCertificateInvalidCertificate(): void
    {
        global $mock_openssl_x509_checkpurpose_to_value, $mock_openssl_x509_parse_to_value;
        $data = [
            'attStmt' => [
                'ver' => '2.0',
                'alg' => -7,
                'sig' => new ByteBuffer('123'),
                'certInfo' => new ByteBuffer('123'),
                'pubArea' => new ByteBuffer('123'),
                'x5c' => [new ByteBuffer('123'), new ByteBuffer('123')]
            ],
        ];
        $authenticatorData = $this->getMockInstance(AuthenticatorData::class, [
            'getBinary' => '123',
            'getPublicKeyPEM' => '123',
        ]);
        $o = new Tpm($data, $authenticatorData);

        $mock_openssl_x509_checkpurpose_to_value = -1;
        $this->setPropertyValue(Tpm::class, $o, 'x5cChain', ['foobar']);

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
            'attStmt' => [
                'ver' => '2.0',
                'alg' => -7,
                'sig' => new ByteBuffer('123'),
                'certInfo' => new ByteBuffer('123'),
                'pubArea' => new ByteBuffer('123'),
                'x5c' => [new ByteBuffer('123'), new ByteBuffer('123')]
            ],
        ];
        $authenticatorData = $this->getMockInstance(AuthenticatorData::class, [
            'getBinary' => '123',
            'getPublicKeyPEM' => '123',
        ]);
        $o = new Tpm($data, $authenticatorData);

        $mock_openssl_x509_checkpurpose_to_value = true;

        $this->assertTrue($o->validateRootCertificate(['123']));
    }

    public function testValidateRootCertificateEmptyX5C(): void
    {
        global $mock_openssl_x509_checkpurpose_to_value;
        $data = [
            'attStmt' => [
                'ver' => '2.0',
                'alg' => -7,
                'sig' => new ByteBuffer('123'),
                'certInfo' => new ByteBuffer('123'),
                'pubArea' => new ByteBuffer('123'),
                'x5c' => [new ByteBuffer('123'), new ByteBuffer('123')]
            ],
        ];
        $authenticatorData = $this->getMockInstance(AuthenticatorData::class, [
            'getBinary' => '123',
            'getPublicKeyPEM' => '123',
        ]);
        $o = new Tpm($data, $authenticatorData);

        $mock_openssl_x509_checkpurpose_to_value = true;
        $this->setPropertyValue(Tpm::class, $o, 'x5c', '');

        $this->assertFalse($o->validateRootCertificate(['123']));
    }
}
