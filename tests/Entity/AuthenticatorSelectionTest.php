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
        $this->assertEquals('preferred', $o->getResidentKeyType());
        $this->assertEquals('preferred', $o->getUserVerificationType());

        $json = $o->jsonSerialize();

        $this->assertCount(4, $json);
        $this->assertArrayHasKey('authenticatorAttachment', $json);
        $this->assertArrayHasKey('residentKeyType', $json);
        $this->assertArrayHasKey('requireResidentKey', $json);
        $this->assertArrayHasKey('userVerificationType', $json);

        $this->assertTrue($json['requireResidentKey']);
        $this->assertEquals('cross-platform', $json['authenticatorAttachment']);
        $this->assertEquals('preferred', $json['residentKeyType']);
        $this->assertEquals('preferred', $json['userVerificationType']);
    }

    public function testConstructNoCrossPlatform(): void
    {
        $o = new AuthenticatorSelection(UserVerificationType::PREFERRED, true, false);

        $this->assertEquals('platform', $o->getAuthenticatorAttachment());
        $this->assertEquals('preferred', $o->getResidentKeyType());
        $this->assertEquals('preferred', $o->getUserVerificationType());

        $json = $o->jsonSerialize();

        $this->assertCount(4, $json);
        $this->assertArrayHasKey('authenticatorAttachment', $json);
        $this->assertArrayHasKey('residentKeyType', $json);
        $this->assertArrayHasKey('requireResidentKey', $json);
        $this->assertArrayHasKey('userVerificationType', $json);

        $this->assertTrue($json['requireResidentKey']);
        $this->assertEquals('platform', $json['authenticatorAttachment']);
        $this->assertEquals('preferred', $json['residentKeyType']);
        $this->assertEquals('preferred', $json['userVerificationType']);
    }

    public function testConstructNoCrossPlatformNoResidentKey(): void
    {
        $o = new AuthenticatorSelection(UserVerificationType::PREFERRED, false, false);

        $this->assertEquals('platform', $o->getAuthenticatorAttachment());
        $this->assertEquals('discouraged', $o->getResidentKeyType());
        $this->assertEquals('preferred', $o->getUserVerificationType());
        $this->assertFalse($o->isRequireResidentKey());

        $json = $o->jsonSerialize();

        $this->assertCount(4, $json);
        $this->assertArrayHasKey('authenticatorAttachment', $json);
        $this->assertArrayHasKey('residentKeyType', $json);
        $this->assertArrayHasKey('requireResidentKey', $json);
        $this->assertArrayHasKey('userVerificationType', $json);


        $this->assertFalse($json['requireResidentKey']);
        $this->assertEquals('platform', $json['authenticatorAttachment']);
        $this->assertEquals('discouraged', $json['residentKeyType']);
        $this->assertEquals('preferred', $json['userVerificationType']);
    }
}
