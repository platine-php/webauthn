<?php

declare(strict_types=1);

namespace Platine\Test\Webauthn\Entity;

use Platine\Dev\PlatineTestCase;
use Platine\Webauthn\Entity\AuthenticatorSelection;
use Platine\Webauthn\Enum\UserVerificationType;
use Platine\Webauthn\Helper\ByteBuffer;

/**
 * AuthenticatorSelection class tests
 *
 * @group core
 * @group webauth
 */
class AuthenticatorSelectionTest extends PlatineTestCase
{
    public function testConstructCrossPlatform(): void
    {
        $o = new AuthenticatorSelection(UserVerificationType::PREFERRED, true, true);

        $this->assertEquals('cross-platform', $o->getAuthenticatorAttachment());
        $this->assertEquals('preferred', $o->getResidentKey());
        $this->assertEquals('preferred', $o->getUserVerification());

        $json = $o->jsonSerialize();

        $this->assertCount(4, $json);
        $this->assertArrayHasKey('authenticatorAttachment', $json);
        $this->assertArrayHasKey('residentKey', $json);
        $this->assertArrayHasKey('requireResidentKey', $json);
        $this->assertArrayHasKey('userVerification', $json);

        $this->assertTrue($json['requireResidentKey']);
        $this->assertEquals('cross-platform', $json['authenticatorAttachment']);
        $this->assertEquals('preferred', $json['residentKey']);
        $this->assertEquals('preferred', $json['userVerification']);
    }

    public function testConstructNoCrossPlatform(): void
    {
        $o = new AuthenticatorSelection(UserVerificationType::PREFERRED, true, false);

        $this->assertEquals('platform', $o->getAuthenticatorAttachment());
        $this->assertEquals('preferred', $o->getResidentKey());
        $this->assertEquals('preferred', $o->getUserVerification());

        $json = $o->jsonSerialize();

        $this->assertCount(4, $json);
        $this->assertArrayHasKey('authenticatorAttachment', $json);
        $this->assertArrayHasKey('residentKey', $json);
        $this->assertArrayHasKey('requireResidentKey', $json);
        $this->assertArrayHasKey('userVerification', $json);

        $this->assertTrue($json['requireResidentKey']);
        $this->assertEquals('platform', $json['authenticatorAttachment']);
        $this->assertEquals('preferred', $json['residentKey']);
        $this->assertEquals('preferred', $json['userVerification']);
    }

    public function testConstructNoCrossPlatformNoResidentKey(): void
    {
        $o = new AuthenticatorSelection(UserVerificationType::PREFERRED, false, false);

        $this->assertEquals('platform', $o->getAuthenticatorAttachment());
        $this->assertEquals('discouraged', $o->getResidentKey());
        $this->assertEquals('preferred', $o->getUserVerification());
        $this->assertFalse($o->isRequireResidentKey());

        $json = $o->jsonSerialize();

        $this->assertCount(4, $json);
        $this->assertArrayHasKey('authenticatorAttachment', $json);
        $this->assertArrayHasKey('residentKey', $json);
        $this->assertArrayHasKey('requireResidentKey', $json);
        $this->assertArrayHasKey('userVerification', $json);


        $this->assertFalse($json['requireResidentKey']);
        $this->assertEquals('platform', $json['authenticatorAttachment']);
        $this->assertEquals('discouraged', $json['residentKey']);
        $this->assertEquals('preferred', $json['userVerification']);
    }
}
