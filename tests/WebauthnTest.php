<?php

declare(strict_types=1);

namespace Platine\Test\Webauthn;

use Platine\Dev\PlatineTestCase;
use Platine\Webauthn\Webauthn;
use Platine\Webauthn\WebauthnConfiguration;

/**
 * Webauthn class tests
 *
 * @group core
 * @group webauth
 */
class WebauthnTest extends PlatineTestCase
{
    public function testConstructorDefault(): void
    {
        $cfg = new WebauthnConfiguration([]);
        $s = new Webauthn($cfg);
        
        $this->assertInstanceOf(
            WebauthnConfiguration::class,
            $this->getPropertyValue(Webauthn::class, $s, 'config')
        );
        $this->assertInstanceOf(Webauthn::class, $s);
    }

    
}
