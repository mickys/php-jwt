<?php

namespace MiladRahimi\Jwt\Tests\Cryptography\Algorithms\Hmac;

use MiladRahimi\Jwt\Cryptography\Algorithms\Hmac\HS384;
use MiladRahimi\Jwt\Exceptions\InvalidSignatureException;
use MiladRahimi\Jwt\Tests\TestCase;

class HS384Test extends TestCase
{
    public function test_sign_and_verify_it_should_sign_with_given_key()
    {
        $plain = 'Header Payload';

        $signer = new HS384($this->key);
        $signature = $signer->sign($plain);
        $signer->verify($plain, $signature);

        $this->assertTrue(true);
    }

    public function test_sign_and_verify_it_should_fail_with_wrong_plain()
    {
        $signer = new HS384($this->key);
        $signature = $signer->sign('Header Payload');

        $this->expectException(InvalidSignatureException::class);
        $signer->verify('WRONG!', $signature);
    }
}
