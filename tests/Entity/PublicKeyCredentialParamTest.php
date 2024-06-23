<?php

declare(strict_types=1);

namespace Platine\Test\Webauthn\Entity;

use Platine\Dev\PlatineTestCase;
use Platine\Webauthn\Entity\PublicKeyCredentialParam;

/**
 * PublicKeyCredentialParam class tests
 *
 * @group core
 * @group webauth
 */
class PublicKeyCredentialParamTest extends PlatineTestCase
{
    public function testAll(): void
    {
        $o = new PublicKeyCredentialParam(-7);

        $this->assertEquals(-7, $o->getAlg());
        $this->assertEquals('public-key', $o->getType());

        $json = $o->jsonSerialize();

        $this->assertCount(2, $json);
        $this->assertArrayHasKey('alg', $json);
        $this->assertArrayHasKey('type', $json);

        $this->assertEquals('public-key', $json['type']);
        $this->assertEquals(-7, $json['alg']);
    }
}
