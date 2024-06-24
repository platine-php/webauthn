<?php

declare(strict_types=1);

namespace Platine\Test\Webauthn\Entity;

use Platine\Dev\PlatineTestCase;
use Platine\Webauthn\Entity\AuthenticatorSelection;
use Platine\Webauthn\Entity\PublicKey;
use Platine\Webauthn\Entity\PublicKeyCredentialParam;
use Platine\Webauthn\Entity\RelyingParty;
use Platine\Webauthn\Entity\UserInfo;
use Platine\Webauthn\Enum\AttestationType;
use Platine\Webauthn\Enum\UserVerificationType;
use Platine\Webauthn\Helper\ByteBuffer;

/**
 * PublicKey class tests
 *
 * @group core
 * @group webauth
 */
class PublicKeyTest extends PlatineTestCase
{
    public function testAddPublicKeys(): void
    {
        $o = new PublicKey();
        $o->addPublicKeys();

        $res = $o->getPublicKeyCredentialParams();
        $this->assertCount(2, $res);
        $this->assertInstanceOf(PublicKeyCredentialParam::class, $res[0]);
        $this->assertInstanceOf(PublicKeyCredentialParam::class, $res[1]);
        $this->assertEquals(-7, $res[0]->getAlg());
        $this->assertEquals(-257, $res[1]->getAlg());
    }

    public function testGetterSetters(): void
    {
        $o = new PublicKey();

        $o->setTimeout(60); // second
        $this->assertEquals(60000, $o->getTimeout());

        $o->setAttestation(AttestationType::DIRECT);
        $this->assertEquals(AttestationType::DIRECT, $o->getAttestation());

        $o->setAllowCredentials([]);
        $this->assertEquals([], $o->getAllowCredentials());

        $authenticatorSelection = $this->getMockInstance(AuthenticatorSelection::class);
        $o->setAuthenticatorSelection($authenticatorSelection);
        $this->assertEquals($authenticatorSelection, $o->getAuthenticatorSelection());

        $o->setChallenge('1234567890');
        $this->assertInstanceOf(ByteBuffer::class, $o->getChallenge());
        $this->assertEquals('1234567890', $o->getChallenge()->getBinaryString());

        $o->setExcludeCredentials([]);
        $this->assertEquals([], $o->getExcludeCredentials());

        $o->setPublicKeyCredentialParams([]);
        $this->assertEquals([], $o->getPublicKeyCredentialParams());

        $o->setExtensions();
        $this->assertCount(1, $o->getExtensions());
        $this->assertArrayHasKey('exts', $o->getExtensions());
        $this->assertTrue($o->getExtensions()['exts']);

        $relyingParty = $this->getMockInstance(RelyingParty::class);
        $o->setRelyingParty($relyingParty);
        $this->assertEquals($relyingParty, $o->getRelyingParty());

        $o->setRelyingPartyId('1');
        $this->assertEquals('1', $o->getRelyingPartyId());

        $userInfo = $this->getMockInstance(UserInfo::class);
        $o->setUserInfo($userInfo);
        $this->assertEquals($userInfo, $o->getUserInfo());

        $o->setUserVerificationType(UserVerificationType::REQUIRED);
        $this->assertEquals(UserVerificationType::REQUIRED, $o->getUserVerificationType());
    }

    public function testJson(): void
    {
        $o = new PublicKey();

        $json = $o->jsonSerialize();

        $this->assertCount(8, $json);
    }
}
