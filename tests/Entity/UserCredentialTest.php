<?php

declare(strict_types=1);

namespace Platine\Test\Webauthn\Entity;

use Platine\Dev\PlatineTestCase;
use Platine\Webauthn\Entity\UserCredential;
use Platine\Webauthn\Helper\ByteBuffer;

/**
 * UserCredential class tests
 *
 * @group core
 * @group webauth
 */
class UserCredentialTest extends PlatineTestCase
{
    public function testAll(): void
    {
        $o = new UserCredential('1', ['internal']);

        $this->assertInstanceOf(ByteBuffer::class, $o->getId());
        $this->assertEquals('1', $o->getId()->getBinaryString());
        $this->assertEquals('public-key', $o->getType());
        $this->assertCount(1, $o->getTransports());
        $this->assertContains('internal', $o->getTransports());

        $json = $o->jsonSerialize();

        $this->assertCount(3, $json);
        $this->assertArrayHasKey('id', $json);
        $this->assertArrayHasKey('type', $json);
        $this->assertArrayHasKey('transports', $json);
        $this->assertIsArray($json['transports']);

        $this->assertInstanceOf(ByteBuffer::class, $json['id']);
        $this->assertEquals('1', $json['id']->getBinaryString());
        $this->assertEquals(1, $json['id']->getLength());
        $this->assertFalse($json['id']->isUseBase64UrlEncoding());
        $this->assertEquals('public-key', $json['type']);
        $this->assertContains('internal', $json['transports']);
    }
}
