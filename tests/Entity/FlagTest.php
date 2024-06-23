<?php

declare(strict_types=1);

namespace Platine\Test\Webauthn\Entity;

use Platine\Dev\PlatineTestCase;
use Platine\Webauthn\Entity\Flag;

/**
 * Flag class tests
 *
 * @group core
 * @group webauth
 */
class FlagTest extends PlatineTestCase
{
    public function testAll(): void
    {
        $o = new Flag(190);

        $this->assertFalse($o->isBit0());
        $this->assertTrue($o->isBit1());
        $this->assertTrue($o->isBit2());
        $this->assertTrue($o->isBit3());
        $this->assertTrue($o->isBit4());
        $this->assertTrue($o->isBit5());
        $this->assertFalse($o->isBit6());
        $this->assertTrue($o->isBit7());
        $this->assertFalse($o->isAttestedDataIncluded());
        $this->assertTrue($o->isExtensionDataIncluded());
        $this->assertFalse($o->isUserPresent());
        $this->assertTrue($o->isUserVerified());

        $json = $o->jsonSerialize();

        $this->assertCount(12, $json);
    }
}
