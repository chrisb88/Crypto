<?php

namespace cbm\Crypto;

/**
 * Class BasicConfigurationTest
 */
class CryptoTest extends \PHPUnit_Framework_TestCase
{
    private $urlParams = [
        'a' => 'Test1234',
        'b' => '1234Test'
    ];

    public function testEncryptDecrypt()
    {
        $params = new Crypto($this->urlParams);

        $encrypted = $params->encrypt();
        $this->assertNotEmpty($encrypted);
        $this->assertInternalType('string', $encrypted);

        $decrypted = $params::decrypt($encrypted);
        $this->assertNotEmpty($decrypted);
        $this->assertSame($this->urlParams, $decrypted);
    }

    public function testIvRandomness()
    {
        $params = new Crypto($this->urlParams);
        $encrypted1 = $params->encrypt();
        $encrypted2 = $params->encrypt();

        $this->assertNotSame($encrypted1, $encrypted2);

        $decrypted1 = $params::decrypt($encrypted1);
        $decrypted2 = $params::decrypt($encrypted2);

        $this->assertSame($this->urlParams, $decrypted1);
        $this->assertSame($this->urlParams, $decrypted2);
    }

    public function testDecryptInvalidIv()
    {
        $this->setExpectedException('RuntimeException');
        $params = new Crypto($this->urlParams);

        $encrypted = $params->encrypt();
        $tampered = 'abcd' . substr($encrypted, 4);
        $this->assertSame(strlen($encrypted), strlen($tampered));

        $decrypted = $params::decrypt($tampered);
        $this->assertNull($decrypted);
    }

    public function testDecryptInvalidBody()
    {
        $params = new Crypto($this->urlParams);

        $encrypted = $params->encrypt();
        $tampered  = substr($encrypted, 0, -10) . 'abcd';
        $tampered .= substr($encrypted, -6);
        $this->assertSame(strlen($encrypted), strlen($tampered));

        $decrypted = $params::decrypt($tampered);
        $this->assertNull($decrypted);
    }
}
