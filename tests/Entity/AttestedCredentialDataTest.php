<?php

declare(strict_types=1);

namespace Platine\Test\Webauthn\Entity;

use Platine\Dev\PlatineTestCase;
use Platine\Webauthn\Entity\AttestedCredentialData;
use Platine\Webauthn\Exception\WebauthnException;

use function Platine\Test\Fixture\Webauthn\getCborAuthenticatorDataTestData;

/**
 * AttestedCredentialData class tests
 *
 * @group core
 * @group webauth
 */
class AttestedCredentialDataTest extends PlatineTestCase
{
    public function testConstructInvalidBinaryLength(): void
    {
        $this->expectException(WebauthnException::class);
        (new AttestedCredentialData('dd'));
    }

    public function testConstructCannotGetLength(): void
    {
        global $mock_unpack_to_array;
        $mock_unpack_to_array = ['nlength' => false];

        $binary = getCborAuthenticatorDataTestData();

        $this->expectException(WebauthnException::class);
        $o = new AttestedCredentialData($binary);
    }

    public function testJson(): void
    {
        $binary = getCborAuthenticatorDataTestData();

        $o = new AttestedCredentialData($binary);

        $json = $o->jsonSerialize();

        $this->assertCount(3, $json);
    }
}
