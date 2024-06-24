<?php

declare(strict_types=1);

namespace Platine\Stdlib\Helper;

$mock_realpath_to_foodir = false;

function realpath(string $key)
{
    global $mock_realpath_to_foodir;
    if ($mock_realpath_to_foodir) {
        return 'foodir';
    }

    return \realpath($key);
}

namespace Platine\Webauthn;
$mock_function_exists_to_false = false;
$mock_openssl_get_md_methods_to_empty = false;
$mock_hex2bin_to_false = false;

function openssl_get_md_methods()
{
    global $mock_openssl_get_md_methods_to_empty;

    if ($mock_openssl_get_md_methods_to_empty) {
        return [];
    }

    return \openssl_get_md_methods();
}

function hex2bin(string $val)
{
    global $mock_hex2bin_to_false;
    if ($mock_hex2bin_to_false) {
        return false;
    }

    return \hex2bin($val);
}

function function_exists(string $val)
{
    global $mock_function_exists_to_false;
    if ($mock_function_exists_to_false) {
        return false;
    }

    return \function_exists($val);
}


namespace Platine\Webauthn\Attestation\Format;

$mock_openssl_pkey_get_public_to_value = false;
$mock_openssl_verify_to_value = false;
$mock_openssl_x509_checkpurpose_to_value = false;
$mock_openssl_x509_parse_to_value = [];
$mock_hash_to_value = [];

function hash(string $algo, string $data, bool $binary = false)
{
    global $mock_hash_to_value;
    if ($mock_hash_to_value) {
        return $mock_hash_to_value;
    }

    return \hash($algo, $data, $binary);
}

function openssl_x509_parse($certificate, $name = true)
{
    global $mock_openssl_x509_parse_to_value;
    if ($mock_openssl_x509_parse_to_value) {
        return $mock_openssl_x509_parse_to_value;
    }

    return \openssl_x509_parse($certificate, $name);
}

function openssl_x509_checkpurpose($certificate, $purpose, $ca_info = [], $untrusted_certificates_file = null)
{
    global $mock_openssl_x509_checkpurpose_to_value;
    if ($mock_openssl_x509_checkpurpose_to_value) {
        return $mock_openssl_x509_checkpurpose_to_value;
    }

    return \openssl_x509_checkpurpose($certificate, $purpose, $ca_info, $untrusted_certificates_file);
}

function openssl_verify($data, $signature, $public_key, $algorithm)
{
    global $mock_openssl_verify_to_value;
    if ($mock_openssl_verify_to_value) {
        return $mock_openssl_verify_to_value;
    }

    return \openssl_verify($data, $signature, $public_key, $algorithm);
}

function openssl_pkey_get_public($public_key)
{
    global $mock_openssl_pkey_get_public_to_value;
    if ($mock_openssl_pkey_get_public_to_value) {
        return $mock_openssl_pkey_get_public_to_value;
    }

    return \openssl_pkey_get_public($public_key);
}

namespace Platine\Webauthn\Attestation;

$mock_unpack_to_false = false;
$mock_unpack_to_value = false;
$mock_unpack_to_array = [];
$mock_substr_to_value = [];
$mock_openssl_x509_parse_to_value = [];

function openssl_x509_parse($certificate, $name = true)
{
    global $mock_openssl_x509_parse_to_value;
    if ($mock_openssl_x509_parse_to_value) {
        return $mock_openssl_x509_parse_to_value;
    }

    return \openssl_x509_parse($certificate, $name);
}

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


function hash(string $algo, string $data, bool $binary = false)
{
    global $mock_hash_to_string;
    if ($mock_hash_to_string) {
        return 'hash_' . $algo;
    } else {
        return \hash($algo, $data, $binary);
    }
}

namespace Platine\Webauthn\Helper;

$mock_unserialize_to_false = false;
$mock_hex2bin_to_false = false;
$mock_unpack_to_false = false;
$mock_function_exists_to_random_bytes = false;
$mock_function_exists_to_openssl_random_pseudo_bytes = false;
$mock_function_exists_byte_buffer = false;
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
    }

    return \openssl_random_pseudo_bytes($val);
}

function function_exists(string $val)
{
    global $mock_function_exists_to_false,
            $mock_function_exists_to_random_bytes,
            $mock_function_exists_to_openssl_random_pseudo_bytes,
            $mock_function_exists_byte_buffer;

    if ($mock_function_exists_to_false) {
        return false;
    }

    if ($val === 'random_bytes') {
        if ($mock_function_exists_to_random_bytes) {
            return true;
        }

        if ($mock_function_exists_byte_buffer === false) {
            return false;
        }
    }

    if ($val === 'openssl_random_pseudo_bytes') {
        if ($mock_function_exists_to_openssl_random_pseudo_bytes) {
            return true;
        }

        if ($mock_function_exists_byte_buffer === false) {
            return false;
        }
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
