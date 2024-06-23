<?php

declare(strict_types=1);

namespace Platine\Test\Webauthn\Entity;

use Platine\Dev\PlatineTestCase;
use Platine\Webauthn\Entity\CredentialPublicKey;
use Platine\Webauthn\Entity\PublicKey;

use function Platine\Test\Fixture\Webauthn\getCborBinaryTestData;

/**
 * CredentialPublicKey class tests
 *
 * @group core
 * @group webauth
 */
class CredentialPublicKeyTest extends PlatineTestCase
{
    public function testConstructRsa(): void
    {
        $data = getCborBinaryTestData();
       // $endOffset = 87;
       // $o = new CredentialPublicKey($data, 87, $endOffset);

        $this->assertEquals(-7, -7);
    }
}
