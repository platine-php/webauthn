<?php

declare(strict_types=1);

namespace Platine\Test\Fixture\Webauthn;

use Platine\Webauthn\Attestation\Format\BaseFormat;

class MyBaseFormat extends BaseFormat
{
}

function getCborAttestationDataTestData(): string
{
    return base64_decode(
        'o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVkBZ0mWDeWIDoxodDQXD2R2YFu'
            . 'P5K65ooYyx5lc87qDHZdjRQAAAAAAAAAAAAAAAAAAAAAAAAAAACCVsHq5O'
            . 'li0yu/FdfIvYq4gNKBPe6ESsgXlK+xPqSYEtKQBAwM5AQAgWQEAxEV0K'
            . 'c3gSJkvXGGLtvHNCzFqUnrdsPf8QjVF3Q2a+/2qx/YOckh2Nwxdqk'
            . '45dEGBny+qP8MgABJDF/c7wDE6pdtGZZ2UdjFkL2u5osXJrMQt02NM92'
            . 'e77Gei73xEJZISNfxZB8GYHHV5c9X95yawnTgc8VOI7qXvVe5AdSrvgpn'
            . '5UalKQqwWZNEljaY9Aks65NYCYA5Klya0W8rZtawZo92X2scy898C44qXx'
            . 'FkxzwjbBFc+3tKZr8wWIWT2rnIrrA5GvO6+v7zm3IHNKGhn/bSOk+JPdm'
            . 'O0R3+A9CM5M1baMnOkzcL/k/Rr5j/cUvcF5Mo36Jc+YFrnpxOBfJ+cjSFDAQAB'
    );
}

function getCborAuthenticatorDataTestData(): string
{
    return base64_decode(
        'SZYN5YgOjGh0NBcPZHZgW4/krrmihjLHmVzzuoMdl2NFAAAAAAiYcFjK3EuBtuEw3lDc'
            . 'vpYAIFufPmdt6rxpPYw9a+VZy4qRyRkxaos3XdIsOF1MEjGEpAEDAzkBACBZAQC'
            . 'rKn+bE/rh0t8zwdLlrT1DvmExNg0XzDh44bjcJo3rakt4gm18VrLjfsKYCe4s6I'
            . 'o6wJwNlhEkQE7aZkYYAjdgnFee6bipInTrCxdAzSxJ2NWZEsMAgNQYy7fmeZI/CG'
            . '6lUNZdF5p08/VWeq7jbi1HhjYfLQoJQtNdLt7yKXIIZoHwQ+g/EzIh60E6jVJpQk0'
            . 'tAOURJZ1CBRZlIaiAUHoPz9Q5qGvnu/Swj/0KN47fORVKm/X6Rb97h3VCL0uQyN6'
            . 'pS7OQsQRQn8xVTkWPBBYUF4dap5c9xPMFZVNk5zTPBqZr3lCUuuF6fr8e21zwO0DO'
            . 'bWI1+6p8Tfwe5mIAm1rZIUMBAAE='
    );
}

function getPublicKeyPemTestData(): string
{
    return '-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqyp/mxP64dLfM8HS5a09
Q75hMTYNF8w4eOG43CaN62pLeIJtfFay437CmAnuLOiKOsCcDZYRJEBO2mZGGAI3
YJxXnum4qSJ06wsXQM0sSdjVmRLDAIDUGMu35nmSPwhupVDWXReadPP1Vnqu424t
R4Y2Hy0KCULTXS7e8ilyCGaB8EPoPxMyIetBOo1SaUJNLQDlESWdQgUWZSGogFB6
D8/UOahr57v0sI/9CjeO3zkVSpv1+kW/e4d1Qi9LkMjeqUuzkLEEUJ/MVU5FjwQW
FBeHWqeXPcTzBWVTZOc0zwama95QlLrhen6/Httc8DtAzm1iNfuqfE38HuZiAJta
2QIDAQAB
-----END PUBLIC KEY-----
';
}
