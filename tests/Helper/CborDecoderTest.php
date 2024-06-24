<?php

declare(strict_types=1);

namespace Platine\Test\Webauthn\Helper;

use Platine\Dev\PlatineTestCase;
use Platine\Webauthn\Exception\WebauthnException;
use Platine\Webauthn\Helper\ByteBuffer;
use Platine\Webauthn\Helper\CborDecoder;

use function Platine\Test\Fixture\Webauthn\getCborAttestationDataTestData;

/**
 * CborDecoder class tests
 *
 * @group core
 * @group webauth
 */
class CborDecoderTest extends PlatineTestCase
{
    public function testParseTag(): void
    {
        $t = new ByteBuffer('è13567865');

        $this->expectException(WebauthnException::class);
        CborDecoder::decode($t);
    }

    public function testParseMajorTypeNotFound(): void
    {
        global $mock_ord_to_value;

        $mock_ord_to_value = -6;

        $t = new ByteBuffer('1234567890');

        $this->expectException(WebauthnException::class);
        CborDecoder::decode($t);
    }

    public function testParseSimpleFloat24(): void
    {
        global $mock_ord_to_value;

        $mock_ord_to_value = 248;
        $t = new ByteBuffer('1234567890');

        $this->expectException(WebauthnException::class);
        CborDecoder::decode($t);
    }

    public function testParseSimpleFloat25(): void
    {
        global $mock_ord_to_value;

        $mock_ord_to_value = 249;
        $t = new ByteBuffer('1234567890');

        $this->expectException(WebauthnException::class);
        CborDecoder::decode($t);
    }

    public function testParseSimpleFloat26(): void
    {
        global $mock_ord_to_value;

        $mock_ord_to_value = 250;
        $t = new ByteBuffer('1234567890');

        $this->expectException(WebauthnException::class);
        CborDecoder::decode($t);
    }

    public function testParseExtractLength31(): void
    {
        $str = '_+_+}{|"?><MZAQ~`~9:{î13567865';
        $t = new ByteBuffer($str);
        $this->expectException(WebauthnException::class);
        CborDecoder::decode($t);
    }

    public function testDecode(): void
    {
        $data = getCborAttestationDataTestData();

        $res = CborDecoder::decode($data);

        $this->assertIsArray($res);
        $this->assertCount(3, $res);
        $this->assertArrayHasKey('attStmt', $res);
        $this->assertArrayHasKey('fmt', $res);
        $this->assertArrayHasKey('authData', $res);

        $this->assertEquals('none', $res['fmt']);
    }

    public function testDecodeSimpleFloat(): void
    {
        $true = CborDecoder::decode(base64_decode('9Q=='));// bool true
        $false = CborDecoder::decode(base64_decode('9A=='));// bool false
        $null = CborDecoder::decode(base64_decode('9w=='));// null
        $float = CborDecoder::decode(base64_decode('+0ASAAAAAAAA'));
        $int = CborDecoder::decode(base64_decode('GC0='));


        $this->assertTrue($true);
        $this->assertFalse($false);
        $this->assertNull($null);
        $this->assertEquals(4.5, $float);
        $this->assertEquals(45, $int);
        $this->assertEquals(4.5E-8, CborDecoder::decode(base64_decode('+z5oKMC+dp3B')));
        $this->assertEquals('tnh', CborDecoder::decode(base64_decode('Y3RuaA==')));
        $this->assertEquals(123456, CborDecoder::decode(base64_decode('GgAB4kA=')));
        $this->assertEquals(1234563434444, CborDecoder::decode(base64_decode('GwAAAR9xtwfM')));
        $this->assertEquals(1234563434444324678, CborDecoder::decode(base64_decode('GxEiDOcSvX9G')));


        // Unsupported simple value
        $this->expectException(WebauthnException::class);
        CborDecoder::decode(base64_decode('9g==')); // 22
    }

    public function testFloat24(): void
    {
        $t = $this->getMockInstance(ByteBuffer::class, ['getByteValue' => 220]);
        $this->setPropertyValue(ByteBuffer::class, $t, 'data', '123456');
        $this->setPropertyValue(ByteBuffer::class, $t, 'length', 6);

        $this->expectException(WebauthnException::class);
        CborDecoder::decode($t);
    }

    public function testFloatReservedValue(): void
    {
        $t = $this->getMockInstance(ByteBuffer::class, ['getByteValue' => 252]);
        $this->setPropertyValue(ByteBuffer::class, $t, 'data', '123456');
        $this->setPropertyValue(ByteBuffer::class, $t, 'length', 6);

        $this->expectException(WebauthnException::class);
        CborDecoder::decode($t);
    }

    public function testFloatInfiniteValue(): void
    {
        $t = $this->getMockInstance(ByteBuffer::class, ['getByteValue' => 255]);
        $this->setPropertyValue(ByteBuffer::class, $t, 'data', '123456');
        $this->setPropertyValue(ByteBuffer::class, $t, 'length', 6);

        $this->expectException(WebauthnException::class);
        CborDecoder::decode($t);
    }

    public function testDecodeArray(): void
    {
        $array = CborDecoder::decode(base64_decode('gRgt'));
        $this->assertEquals([45], $array);

        $this->assertEquals(['a' => 1, 'b' => 2], CborDecoder::decode(base64_decode('omFhAWFiAg==')));
    }

    public function testDecodeArrayInvalidArrayKey(): void
    {
        global $mock_is_int_to_false, $mock_is_string_to_false;

        $mock_is_int_to_false = true;
        $mock_is_string_to_false = true;


        $this->expectException(WebauthnException::class);
        CborDecoder::decode(new ByteBuffer(base64_decode('oWFhAw==')));
    }

    public function testDecodeInPlace(): void
    {
        $data = getCborAttestationDataTestData();

        $res = CborDecoder::decodeInPlace($data, 5, 45);

        $this->assertEquals('none', $res);
    }

    public function testDecodeRemainingByte(): void
    {
        $data = new ByteBuffer('1234567890');
        $this->expectException(WebauthnException::class);
        CborDecoder::decode($data);
    }
}
