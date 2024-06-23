<?php

declare(strict_types=1);

namespace Platine\Test\Webauthn\Enum;

use Platine\Dev\PlatineTestCase;
use Platine\Webauthn\Enum\AttestationType;

/**
 * All Enumeration class tests
 *
 * @group core
 * @group webauth
 */
class EnumTest extends PlatineTestCase
{
    public function testAll(): void
    {
        $aEnum = AttestationType::all();

        $this->assertCount(3, $aEnum);
        $this->assertContains(AttestationType::DIRECT, $aEnum);
        $this->assertContains(AttestationType::INDIRECT, $aEnum);
        $this->assertContains(AttestationType::NONE, $aEnum);
    }
}
