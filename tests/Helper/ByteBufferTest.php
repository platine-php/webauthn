<?php

declare(strict_types=1);

namespace Platine\Test\Webauthn\Helper;

use Platine\Dev\PlatineTestCase;
use Platine\Webauthn\Exception\WebauthnException;
use Platine\Webauthn\Helper\ByteBuffer;

/**
 * ByteBuffer class tests
 *
 * @group core
 * @group webauth
 */
class ByteBufferTest extends PlatineTestCase
{
    public function testConstructorDefault(): void
    {
        $o = new ByteBuffer('1234567890');

        $this->assertEquals('1234567890', $o->getBinaryString());
        $this->assertEquals('31323334353637383930', (string) $o);
        $this->assertEquals(10, $o->getLength());
        $this->assertEquals(53, $o->getByteValue(4));
        $this->assertEquals(13622, $o->getUint16Value(4));
        $this->assertEquals(892745528, $o->getUint32Value(4));
        $this->assertEquals(3689632501694216496, $o->getUint64Value(2));
        $this->assertEquals(5678, $o->getBytes(4, 4));
        $this->assertEquals('31323334353637383930', $o->getHexValue());
        $this->assertEquals(0.1937255859375, $o->getHalfFloatValue(1));
        $this->assertEquals(1.0431041808089958E-8, $o->getFloatValue(1));
        $this->assertEquals(7.123136104244226E-67, $o->getDoubleValue(1));
        $this->assertFalse($o->isEqual(ByteBuffer::fromHex('11')));
        $this->assertFalse($o->isEmpty());

        $this->assertEquals('s:10:"1234567890";', $o->serialize());

        $o1 = new ByteBuffer('1');
        $this->assertEquals(1, $o1->getLength());

        $o1->unserialize('s:10:"1234567890";');
        $this->assertEquals('1234567890', $o1->getBinaryString());
        $this->assertEquals('31323334353637383930', (string) $o1);
        $this->assertEquals(10, $o1->getLength());
    }

    public function testUnserializeInvalidData(): void
    {
        global $mock_unserialize_to_false;
        $mock_unserialize_to_false = true;

        $o = ByteBuffer::fromBase64Url('MTIzNDU');
        $this->expectException(WebauthnException::class);
        $o->unserialize('s:10:"1234567890');
    }

    public function testSerializationMagicMethod(): void
    {
        global $mock_unserialize_to_false;
        $o = new ByteBuffer('1234567890');

        // Serialization
        $ser = $o->__serialize();
        $this->assertArrayHasKey('data', $ser);
        $this->assertEquals('s:10:"1234567890";', $ser['data']);

        // Unserialization
        $o1 = new ByteBuffer('1');

        $o1->__unserialize(['data' => 's:10:"1234567890";']);
        $this->assertEquals('1234567890', $o1->getBinaryString());

        $mock_unserialize_to_false = true;
        $this->expectException(WebauthnException::class);
        $o1->__unserialize(['data' => 's:10:"1234567890";']);
    }

    public function testConstructFromBase64(): void
    {
        $o = ByteBuffer::fromBase64Url('MTIzNDU');

        $this->assertEquals('12345', $o->getBinaryString());
        $this->assertEquals(5, $o->getLength());
    }

    public function testConstructFromHexFailed(): void
    {
        global $mock_hex2bin_to_false;
        $mock_hex2bin_to_false = true;

        $this->expectException(WebauthnException::class);
        $o = ByteBuffer::fromHex('11');
    }

    public function testJsonFeature(): void
    {
        $o = new ByteBuffer('1234567890');

        $this->assertEquals('1234567890', $o->getJson());

        $this->assertEquals('=?BINARY?B?MTIzNDU2Nzg5MA==?=', $o->jsonSerialize());

        $o->useBase64UrlEncoding(true);
        $this->assertEquals('1234567890', $o->jsonSerialize());

        // Error
        $o1 = new ByteBuffer('{1234567890');
        $this->expectException(WebauthnException::class);
        $o1->getJson();
    }

    /**
     * @dataProvider invalidOffsetLengthDataProvider
     * @param string $method
     * @param array<mixed> $params
     */
    public function testInvalidOffsetLength(string $method, array $params = [])
    {
        $o = new ByteBuffer('{1234567890');
        $this->expectException(WebauthnException::class);
        $o->{$method}(...$params);
    }

    /**
     * @dataProvider unpackFailedDataProvider
     * @param string $method
     * @param array<mixed> $params
     */
    public function testUnpackFailed(string $method, array $params = [])
    {
        global $mock_unpack_to_false;
        $mock_unpack_to_false = true;

        $o = new ByteBuffer('{1234567890');
        $this->expectException(WebauthnException::class);
        $o->{$method}(...$params);
    }

    public function testGetUint64ValueSignedIntegerOverflow()
    {
        global $mock_unpack_to_value;
        $mock_unpack_to_value = [0, -1];

        $o = new ByteBuffer('{1234567890');
        $this->expectException(WebauthnException::class);
        $o->getUint64Value(0);
    }

    public function testRandomBuffer()
    {
        global $mock_function_exists_to_false,
            $mock_function_exists_to_random_bytes,
            $mock_random_bytes_to_value;

        // random_bytes
        $mock_function_exists_to_random_bytes = true;
        $mock_random_bytes_to_value = true;
        $o1 = ByteBuffer::randomBuffer(10);
        $this->assertEquals('random_bytes_10', $o1->getBinaryString());

        // No Available Functions
        $mock_function_exists_to_false = true;

        $this->expectException(WebauthnException::class);
        ByteBuffer::randomBuffer(1);
    }

    public function testRandomBufferOpenSSL()
    {
        global $mock_openssl_random_pseudo_bytes_to_false,
            $mock_function_exists_to_openssl_random_pseudo_bytes,
            $mock_openssl_random_pseudo_bytes_to_value;

        $mock_function_exists_to_openssl_random_pseudo_bytes = true;
        $mock_openssl_random_pseudo_bytes_to_value = true;

        $o2 = ByteBuffer::randomBuffer(10);
        $this->assertEquals('openssl_random_pseudo_bytes_10', $o2->getBinaryString());

        $mock_openssl_random_pseudo_bytes_to_false = true;
        $this->expectException(WebauthnException::class);
        ByteBuffer::randomBuffer(1);
    }

    public function testGetHalfFloatValue()
    {
        // Exponent = 0
        $o = ByteBuffer::fromHex('0111');
        $this->assertEquals(1.627206802368164E-5, $o->getHalfFloatValue(0));

        // Exponent = 31
        $o1 = ByteBuffer::fromBase64Url('OKOKVWuVX8gnyu85DpmHzhWbt2g.TniDsqaFA3olAloC6');
        $this->assertEquals(14499, $o1->getUint16Value(0));
    }

    /**
     * Data provider for "testInvalidOffsetLength"
     * @return array<int, mixed>
     */
    public function invalidOffsetLengthDataProvider(): array
    {
        return [
          [
              'getBytes',
              [-1, 0],
          ],
          [
              'getByteValue',
              [-1],
          ],
          [
              'getUint16Value',
              [-1],
          ],
          [
              'getUint32Value',
              [-1],
          ],
          [
              'getUint64Value',
              [-1],
          ],
          [
              'getFloatValue',
              [-1],
          ],
          [
              'getDoubleValue',
              [-1],
          ],
        ];
    }

    /**
     * Data provider for "testUnpackFailed"
     * @return array<int, mixed>
     */
    public function unpackFailedDataProvider(): array
    {
        return [
          [
              'getUint16Value',
              [0],
          ],
          [
              'getUint32Value',
              [0],
          ],
          [
              'getUint64Value',
              [0],
          ],
          [
              'getFloatValue',
              [0],
          ],
          [
              'getDoubleValue',
              [0],
          ],
        ];
    }
}
