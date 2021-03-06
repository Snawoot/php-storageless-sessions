<?php

use VladislavYarmak\StoragelessSession\CryptoCookieSessionHandler;

/**
 * @covers CryptoCookieSessionHandler
 */
final class CryptoCookieSessionHandlerTest extends \PHPUnit_Framework_TestCase
{
    public function testCanBeCreated()
    {
        $this->assertInstanceOf(
            "VladislavYarmak\\StoragelessSession\\CryptoCookieSessionHandler",
            new CryptoCookieSessionHandler('somesecret')
        );
    }

    /**
     * @depends testCanBeCreated
     * @expectedException VladislavYarmak\StoragelessSession\BadSecretException
     */
    public function testCannotBeCreatedFromEmptyString()
    {
        new CryptoCookieSessionHandler('');
    }

    /**
     * @depends testCanBeCreated
     * @expectedException VladislavYarmak\StoragelessSession\BadAlgoException
     */
    public function testCannotBeCreatedWithWrongDigestAlgo()
    {
        $handler = new CryptoCookieSessionHandler(
            'somesecret',
            2592000,
            "non-existent-digest");
    }

    /**
     * @depends testCanBeCreated
     * @expectedException VladislavYarmak\StoragelessSession\BadAlgoException
     */
    public function testCannotBeCreatedWithWrongCipherAlgo()
    {
        $handler = new CryptoCookieSessionHandler(
            'somesecret',
            2592000,
            "sha256",
            "non-existent-cipher");
    }

    /**
     * @depends testCanBeCreated
     * @expectedException VladislavYarmak\StoragelessSession\BadNumericParamsException
     */
    public function testCannotBeCreatedWithZeroKeyLength()
    {
        $handler = new CryptoCookieSessionHandler(
            'somesecret',
            2592000,
            "sha256",
            "aes-256-ctr",
            0);
    }

    /**
     * @depends testCanBeCreated
     * @expectedException VladislavYarmak\StoragelessSession\BadNumericParamsException
     */
    public function testCannotBeCreatedWithZeroExpire()
    {
        $handler = new CryptoCookieSessionHandler('somesecret', 0);
    }

    /**
     * @depends testCanBeCreated
     */
    public function testOpenWorks()
    {
        $this->assertTrue(
            (new CryptoCookieSessionHandler('somesecret'))->open("/tmp", "session"));
    }

    /**
     * @depends testOpenWorks
     */
    public function testGarbageCollectorWorks()
    {
        $handler = new CryptoCookieSessionHandler('somesecret');
        $handler->open("/tmp", "session");
        $this->assertTrue($handler->gc("", ""));
    }

    /**
     * @depends testOpenWorks
     */
    public function testCloseWorks()
    {
        $handler = new CryptoCookieSessionHandler('somesecret');
        $handler->open("/tmp", "session");
        $this->assertTrue($handler->close());
    }

    /**
     * @depends testOpenWorks
     */
    public function testReadUndefined()
    {
        $sess_id = "session";
        $handler = new CryptoCookieSessionHandler('somesecret');
        $handler->open("/tmp", $sess_id);
        $this->assertEquals($handler->read($sess_id), "");
    }

    /**
     * @depends testOpenWorks
     */
    public function testReadRandomBase64Cookie()
    {
        $maxlength = 100;
        $sess_id = "session";
        $data = openssl_random_pseudo_bytes($maxlength);

        $handler = new CryptoCookieSessionHandler("somesecret");
        $handler->open("/tmp", $sess_id);

        for ($i=0; $i <= $maxlength; $i++) {
            $GLOBALS["_COOKIE"] = array(
                $sess_id => base64_encode(substr($data, 0, $i))
            );
            $this->assertEquals($handler->read($sess_id), "");
        }

        unset($GLOBALS["_COOKIE"]);
    }

    /**
     * @depends testOpenWorks
     */
    public function testReadRandomBinaryCookie()
    {
        $maxlength = 100;
        $sess_id = "session";
        $data = openssl_random_pseudo_bytes($maxlength);

        $handler = new CryptoCookieSessionHandler("somesecret");
        $handler->open("/tmp", $sess_id);

        for ($i=0; $i <= $maxlength; $i++) {
            $GLOBALS["_COOKIE"] = array(
                $sess_id => substr($data, 0, $i)
            );
            $this->assertEquals($handler->read($sess_id), "");
        }

        unset($GLOBALS["_COOKIE"]);
    }

    /**
     * @depends testOpenWorks
     */
    public function testRoundTrip()
    {
        $sess_id = "session";
        $secret = "somesecret";
        $data = openssl_random_pseudo_bytes(300);

        $handler = new CryptoCookieSessionHandler($secret);
        $handler->open("/tmp", $sess_id);
        $this->assertTrue($handler->write($sess_id, $data));
        $handler->close();

        $GLOBALS["_COOKIE"] = array();
        foreach ($GLOBALS["_SETCOOKIE"] as $key => $value)
            $GLOBALS["_COOKIE"][$key] = $value["value"];

        $handler = new CryptoCookieSessionHandler($secret);
        $handler->open("/tmp", $sess_id);
        $this->assertEquals($handler->read($sess_id), $data);
        $handler->close();

        unset($GLOBALS["_COOKIE"]);
        unset($GLOBALS["_SETCOOKIE"]);
    }

    /**
     * @depends testOpenWorks
     */
    public function testReadAfterWrite()
    {
        $sess_id = "session";
        $secret = "somesecret";
        $data = openssl_random_pseudo_bytes(300);

        $handler = new CryptoCookieSessionHandler($secret);
        $handler->open("/tmp", $sess_id);
        $this->assertTrue($handler->write($sess_id, $data));
        $this->assertEquals($handler->read($sess_id), $data);
        $handler->close();

        unset($GLOBALS["_SETCOOKIE"]);
    }

    /**
     * @depends testOpenWorks
     */
    public function testDataEncrypted()
    {
        $sess_id = "session";
        $secret = "somesecret";
        $data = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

        $handler = new CryptoCookieSessionHandler($secret);
        $handler->open("/tmp", $sess_id);
        $this->assertTrue($handler->write($sess_id, $data));
        $handler->close();

        $GLOBALS["_COOKIE"] = array();
        foreach ($GLOBALS["_SETCOOKIE"] as $key => $value) {
            $this->assertFalse(strpos($value["value"], "aaaaaaaa"));
            $this->assertFalse(strpos(base64_decode($value["value"]), "aaaaaaaa"));
        }
        
        unset($GLOBALS["_COOKIE"]);
        unset($GLOBALS["_SETCOOKIE"]);
    }

    /**
     * @depends testOpenWorks
     */
    public function testSessionDestroy()
    {
        $sess_id = "session";
        $secret = "somesecret";
        $data = "data";

        $handler = new CryptoCookieSessionHandler($secret);
        $handler->open("/tmp", $sess_id);
        $this->assertTrue($handler->write($sess_id, $data));

        $this->assertTrue($handler->destroy($sess_id));
        foreach ($GLOBALS["_SETCOOKIE"] as $ck) {
            $this->assertEquals($ck["value"], "");
            $this->assertLessThanOrEqual(time(), $ck["expire"]);
        }

        unset($GLOBALS["_SETCOOKIE"]);
    }

    /**
     * @depends testRoundTrip
     */
    public function testAutoopenWorks()
    {
        $sess_id = "session";
        $secret = "somesecret";
        $data = openssl_random_pseudo_bytes(300);

        $handler = new CryptoCookieSessionHandler($secret);
        $this->assertTrue($handler->write($sess_id, $data));
        $handler->close();

        $GLOBALS["_COOKIE"] = array();
        foreach ($GLOBALS["_SETCOOKIE"] as $key => $value)
            $GLOBALS["_COOKIE"][$key] = $value["value"];

        $handler = new CryptoCookieSessionHandler($secret);
        $this->assertEquals($handler->read($sess_id), $data);
        $handler->close();

        unset($GLOBALS["_COOKIE"]);
        unset($GLOBALS["_SETCOOKIE"]);
    }

    /**
     * @depends testRoundTrip
     */
    public function testDigestExpires()
    {
        $sess_id = "session";
        $secret = "somesecret";
        $data = openssl_random_pseudo_bytes(300);

        $handler = new CryptoCookieSessionHandler($secret, 5);
        $handler->open("/tmp", $sess_id);
        $this->assertTrue($handler->write($sess_id, $data));
        $handler->close();

        $GLOBALS["_COOKIE"] = array();
        foreach ($GLOBALS["_SETCOOKIE"] as $key => $value)
            $GLOBALS["_COOKIE"][$key] = $value["value"];

        $handler = new CryptoCookieSessionHandler($secret, 5);
        $handler->open("/tmp", $sess_id);
        $this->assertEquals($handler->read($sess_id), $data);

        sleep(10);

        $this->assertEquals($handler->read($sess_id), "");
        $handler->close();

        unset($GLOBALS["_COOKIE"]);
        unset($GLOBALS["_SETCOOKIE"]);
    }

    /**
     * @depends testReadAfterWrite
     */
    public function testDigestExpiresAfterWrite()
    {
        $sess_id = "session";
        $secret = "somesecret";
        $data = openssl_random_pseudo_bytes(300);

        $handler = new CryptoCookieSessionHandler($secret, 5);
        $handler->open("/tmp", $sess_id);
        $this->assertTrue($handler->write($sess_id, $data));

        $this->assertEquals($handler->read($sess_id), $data);

        sleep(10);

        $this->assertEquals($handler->read($sess_id), "");
        $handler->close();

        unset($GLOBALS["_SETCOOKIE"]);
    }

    /**
     * @depends testOpenWorks
     */
    public function testDigestBoundToSessionId()
    {
        $sess_id = "session";
        $sess_id2 = "another_session";
        $secret = "somesecret";
        $data = openssl_random_pseudo_bytes(300);

        $handler = new CryptoCookieSessionHandler($secret);
        $handler->open("/tmp", $sess_id);
        $handler->write($sess_id, $data);
        $handler->close();

        $GLOBALS["_COOKIE"] = array();
        foreach ($GLOBALS["_SETCOOKIE"] as $key => $value)
            $GLOBALS["_COOKIE"][$sess_id2] = $GLOBALS["_SETCOOKIE"][$sess_id]["value"];

        $handler = new CryptoCookieSessionHandler($secret);
        $handler->open("/tmp", $sess_id);
        $this->assertEquals($handler->read($sess_id2), "");
        $handler->close();

        unset($GLOBALS["_COOKIE"]);
        unset($GLOBALS["_SETCOOKIE"]);
    }

    /**
     * @depends testOpenWorks
     * @dataProvider cookieProvider
     */
    public function testInteroperability($secret, $cookies, $expected)
    {
        $GLOBALS["_COOKIE"] = $cookies;
        $sess_id = $cookies["PHPSESSID"];

        $handler = new CryptoCookieSessionHandler($secret);
        $handler->open("/tmp", $sess_id);
        $this->assertEquals($handler->read($sess_id), $expected);
        $handler->close();
    }

    public function cookieProvider()
    {
        return [
            [
                "somesecret",
                [
                    "PHPSESSID" => "sh8teeplnis2017ncuv2ur1le4",
                    "sh8teeplnis2017ncuv2ur1le4" => 'X6eKM1bWNywsbOwvIWdPk4a-a_bRcyFXzZi_26I854CsafR9PrLZDDNcY-q-dMpfGFBzFy7DFc5fcMMx07ajNXIqMkxgu_TC'
                ],
                'a|s:1:"1";b|s:1:"2";'
            ]
        ];
    }

    /**
     * @depends testOpenWorks
     * @expectedException VladislavYarmak\StoragelessSession\CookieTooBigException
     */
    public function testLengthException()
    {
        $secret = "somesecret";
        $sess_id = "session";
        $maxlength = 4096;
        $data = openssl_random_pseudo_bytes($maxlength);

        $handler = new CryptoCookieSessionHandler($secret);
        $handler->open("/tmp", $sess_id);
        $this->assertEquals($handler->write($sess_id, $data), $expected);
        $handler->close();
    }

	/**
	 * Call protected/private method of a class.
	 *
	 * @param object &$object    Instantiated object that we will run method on.
	 * @param string $methodName Method name to call
	 * @param array  $parameters Array of parameters to pass into method.
	 *
	 * @return mixed Method return.
	 */
	public function invokeMethod(&$object, $methodName, array $parameters = array())
	{
	    $reflection = new \ReflectionClass(get_class($object));
	    $method = $reflection->getMethod($methodName);
	    $method->setAccessible(true);
	
	    return $method->invokeArgs($object, $parameters);
	}

    /**
     * @depends testCanBeCreated
     */
    public function testBase64UrlsafeEncoding()
    {
        $maxlength = 100;
        $data = openssl_random_pseudo_bytes($maxlength);

        $handler = new CryptoCookieSessionHandler("somesecret");

        for ($i=0; $i <= $maxlength; $i++) {
            unset($GLOBALS['_BASE64_DECODE_CALLS']);

			$data = substr($data, 0, $i);
            $encoded = $this->invokeMethod($handler, "base64_urlsafe_encode", array($data));
            $decoded = $this->invokeMethod($handler, "base64_urlsafe_decode", array($encoded));

            $this->assertEquals($decoded, $data);

            list($sent_to_base64_dec) = $GLOBALS['_BASE64_DECODE_CALLS'];
            $this->assertEquals($sent_to_base64_dec, \base64_encode($data));
        }

        unset($GLOBALS['_BASE64_DECODE_CALLS']);
    }
}
