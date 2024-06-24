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

function getCborRegistrationAttestationDataTestData(): string
{
    return base64_decode(
        'o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVkBZ0mWDeWIDoxodDQXD2R2YFuP5K65'
            . 'ooYyx5lc87qDHZdjRQAAAAAAAAAAAAAAAAAAAAAAAAAAACCV2NxVLaXLP0Uyig'
            . 'o8QTNg7GOdEsMcJSk9XN9x+Uqo+6QBAwM5AQAgWQEA5Ru9tN2Hdw/JnVt/NRM'
            . 't/bm/5XUDmACMScV5i5miQaBF5M7MYoNdz/wqkdbaPd1DHmDWcLBIaXCjDm4w'
            . 'AjEdHIr6f5M90J7PqbfYii/Z9uK2J0D3VQ9voiMPmg71g8UGw092+DYtAorc'
            . 'MSxcre3tKY03R0CIj5ydmhr9B+f3FJdjUYpW66plKfeI24Gb3BzKHB/NEN+E'
            . 'W02Y4W7bFayB2yxPWf1cCbWVZZSpmxaFpI4MSx5JG3IMTLFKesQFKgt0wWcy'
            . 'cPx2RyE+BktMRexF8ekGHPkOEh+uic4mq9pU9LUUSh6dTqeTDzJSw0TxrLO1'
            . 'KC6kcjjkE6kOrAUZu3KxNSFDAQAB'
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


function getAuthClientDataJson(): string
{
    return base64_decode(
        'eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiSFdFMmlVWGV6YT'
            . 'ZEUVNMMjMtU2dUcGdoNE5fejlPSmZvcFNVNnc2SjN1OCIsIm9yaWdpbiI6Imh0dHA6Ly'
            . '9sb2NhbGhvc3QiLCJjcm9zc09yaWdpbiI6ZmFsc2V9'
    );
}

function getRegistrationClientDataJson(): string
{
    return base64_decode(
        'eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoickI4LTItRml'
            . 'IZzlONFNDNmxHZ0x1NTNmaHN6ZEUxX05KWlp4X3dRcUJ6QSIsIm9yaWdpbiI6Imh0dHA'
            . '6Ly9sb2NhbGhvc3QiLCJjcm9zc09yaWdpbiI6ZmFsc2V9'
    );
}
