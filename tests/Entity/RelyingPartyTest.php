<?php

declare(strict_types=1);

namespace Platine\Test\Webauthn\Entity;

use Platine\Dev\PlatineTestCase;
use Platine\Webauthn\Entity\RelyingParty;

/**
 * RelyingParty class tests
 *
 * @group core
 * @group webauth
 */
class RelyingPartyTest extends PlatineTestCase
{
    public function testAll(): void
    {
        global $mock_hash_to_string;
        $mock_hash_to_string = true;

        $o = new RelyingParty('localhost', 'Platine App', 'base64logo');

        $this->assertEquals('localhost', $o->getId());
        $this->assertEquals('Platine App', $o->getName());
        $this->assertEquals('base64logo', $o->getLogo());
        $this->assertEquals('hash_sha256', $o->getHashId());

        $json = $o->jsonSerialize();

        $this->assertCount(3, $json);
        $this->assertArrayHasKey('id', $json);
        $this->assertArrayHasKey('name', $json);
        $this->assertArrayHasKey('logo', $json);

        $this->assertEquals('localhost', $json['id']);
        $this->assertEquals('Platine App', $json['name']);
        $this->assertEquals('base64logo', $json['logo']);
    }
}
