<?php

declare(strict_types=1);

namespace Platine\Test\Webauthn\Entity;

use Platine\Dev\PlatineTestCase;
use Platine\Webauthn\Entity\UserInfo;
use Platine\Webauthn\Helper\ByteBuffer;

/**
 * UserInfo class tests
 *
 * @group core
 * @group webauth
 */
class UserInfoTest extends PlatineTestCase
{
    public function testAll(): void
    {
        $o = new UserInfo('1', 'tnh', 'Tony');

        $this->assertInstanceOf(ByteBuffer::class, $o->getId());
        $this->assertEquals('1', $o->getId()->getBinaryString());
        $this->assertEquals('tnh', $o->getName());
        $this->assertEquals('Tony', $o->getDisplayName());

        $json = $o->jsonSerialize();

        $this->assertCount(3, $json);
        $this->assertArrayHasKey('id', $json);
        $this->assertArrayHasKey('name', $json);
        $this->assertArrayHasKey('displayName', $json);

        $this->assertInstanceOf(ByteBuffer::class, $json['id']);
        $this->assertEquals('1', $json['id']->getBinaryString());
        $this->assertEquals(1, $json['id']->getLength());
        $this->assertFalse($json['id']->isUseBase64UrlEncoding());
        $this->assertEquals('tnh', $json['name']);
        $this->assertEquals('Tony', $json['displayName']);
    }
}
