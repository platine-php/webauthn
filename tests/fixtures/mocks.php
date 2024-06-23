<?php

declare(strict_types=1);

namespace Platine\Webauthn\Attestation;

$mock_unpack_to_false = false;
$mock_unpack_to_value = false;
$mock_unpack_to_array = [];
$mock_substr_to_value = [];

function substr(string $string, int $offset, $length = -1)
{
    global $mock_substr_to_value;
    if ($mock_substr_to_value) {
        return $mock_substr_to_value;
    }

    return \substr($string, $offset, $length);
}

function unpack(string $format, string $string, int $offset = 0)
{
    global $mock_unpack_to_false, $mock_unpack_to_value, $mock_unpack_to_array;
    if ($mock_unpack_to_false) {
        return false;
    }

    if ($mock_unpack_to_value) {
        return $mock_unpack_to_value;
    }

    if ($mock_unpack_to_array) {
        if (isset($mock_unpack_to_array[$format])) {
            return $mock_unpack_to_array[$format];
        }
    }

    return \unpack($format, $string, $offset);
}


namespace Platine\Webauthn\Entity;

$mock_hash_to_string = false;
$mock_unpack_to_array = [];



function unpack(string $format, string $string, int $offset = 0)
{
    global $mock_unpack_to_array;


    if ($mock_unpack_to_array) {
        if (isset($mock_unpack_to_array[$format])) {
            return $mock_unpack_to_array[$format];
        }
    }

    return \unpack($format, $string, $offset);
}


function hash(string $algo, string $data, bool $binary = false, array $options = [])
{
    global $mock_hash_to_string;
    if ($mock_hash_to_string) {
        return 'hash_' . $algo;
    } else {
        return \hash($algo, $data, $binary, $options);
    }
}

namespace Platine\Webauthn\Helper;

$mock_unserialize_to_false = false;
$mock_hex2bin_to_false = false;
$mock_unpack_to_false = false;
$mock_function_exists_to_random_bytes = false;
$mock_function_exists_to_openssl_random_pseudo_bytes = false;
$mock_function_exists_to_false = false;
$mock_unpack_to_value = false;
$mock_random_bytes_to_value = false;
$mock_openssl_random_pseudo_bytes_to_value = false;
$mock_openssl_random_pseudo_bytes_to_false = false;
$mock_is_int_to_false = false;
$mock_is_string_to_false = false;
$mock_ord_to_value = false;


function ord(string $val)
{
    global $mock_ord_to_value;
    if ($mock_ord_to_value) {
        return $mock_ord_to_value;
    } else {
        return \ord($val);
    }
}

function is_string($val)
{
    global $mock_is_string_to_false;
    if ($mock_is_string_to_false) {
        return false;
    } else {
        return \is_string($val);
    }
}

function is_int($val)
{
    global $mock_is_int_to_false;
    if ($mock_is_int_to_false) {
        return false;
    } else {
        return \is_int($val);
    }
}

function random_bytes(int $val)
{
    global $mock_random_bytes_to_value;
    if ($mock_random_bytes_to_value) {
        return 'random_bytes_' . $val;
    } else {
        return \random_bytes($val);
    }
}

function openssl_random_pseudo_bytes(int $val)
{
    global $mock_openssl_random_pseudo_bytes_to_value, $mock_openssl_random_pseudo_bytes_to_false;

    if ($mock_openssl_random_pseudo_bytes_to_false) {
        return false;
    }

    if ($mock_openssl_random_pseudo_bytes_to_value) {
        return 'openssl_random_pseudo_bytes_' . $val;
    } else {
        return \openssl_random_pseudo_bytes($val);
    }
}

function function_exists(string $val)
{
    global $mock_function_exists_to_false,
            $mock_function_exists_to_random_bytes,
            $mock_function_exists_to_openssl_random_pseudo_bytes;

    if ($mock_function_exists_to_false) {
        return false;
    }

    if ($val === 'random_bytes') {
        if ($mock_function_exists_to_random_bytes) {
            return true;
        }
        return false;
    }

    if ($val === 'openssl_random_pseudo_bytes') {
        if ($mock_function_exists_to_openssl_random_pseudo_bytes) {
            return true;
        }
        return false;
    }

    return \function_exists($val);
}

function unserialize(string $val)
{
    global $mock_unserialize_to_false;
    if ($mock_unserialize_to_false) {
        return false;
    } else {
        return \unserialize($val);
    }
}

function hex2bin(string $val)
{
    global $mock_hex2bin_to_false;
    if ($mock_hex2bin_to_false) {
        return false;
    } else {
        return \hex2bin($val);
    }
}

function unpack(string $format, string $string, int $offset = 0)
{
    global $mock_unpack_to_false, $mock_unpack_to_value;
    if ($mock_unpack_to_false) {
        return false;
    }

    if ($mock_unpack_to_value) {
        return $mock_unpack_to_value;
    }

    return \unpack($format, $string, $offset);
}
