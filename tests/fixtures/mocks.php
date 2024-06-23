<?php

declare(strict_types=1);

namespace Platine\Webauthn\Entity;

$mock_hash_to_string = false;

function hash(string $algo, string $data, bool $binary = false, array $options = [])
{
    global $mock_hash_to_string;
    if ($mock_hash_to_string) {
        return 'hash_' . $algo;
    } else {
        return \hash($algo, $data, $binary, $options);
    }
}
