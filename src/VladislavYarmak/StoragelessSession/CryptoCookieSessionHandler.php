<?php

namespace VladislavYarmak\StoragelessSession;

const UINT32_LE_PACK_CODE       =   "V";
const UINT32_SIZE               =   4;
const RFC2965_COOKIE_SIZE       =   4096;
const MIN_OVERHEAD_PER_COOKIE   =   3;
const METADATA_SIZE             =   UINT32_SIZE;

if(!function_exists('hash_equals')) {
    function hash_equals($a, $b) {
        $ret = strlen($a) ^ strlen($b);
        $ret |= array_sum(unpack("C*", $a^$b));
        return !$ret;
    }
}

final class CryptoCookieSessionHandler implements \SessionHandlerInterface {
    private $secret;
    private $digest_algo;
    private $digest_len;
    private $cipher_algo;
    private $cipher_ivlen;
    private $session_name_len;
    private $session_cookie_params;
    private $overwritten = array();
    private $opened = false;

    public function __construct(
        $secret,
        $expire         = 2592000,
        $digest_algo    = "sha256",
        $cipher_algo    = "aes-256-ctr",
        $cipher_keylen  = 32
    ) {

        if (empty($secret)) {
            throw new BadSecretException();
        }
        $this->secret           = $secret;

        if (!in_array($digest_algo, hash_algos())) {
            throw new BadAlgoException();
        }
        $this->digest_algo      = $digest_algo;

        if (!in_array($cipher_algo, openssl_get_cipher_methods(true))) {
            throw new BadAlgoException();
        }
        $this->cipher_algo      = $cipher_algo;

        if ( !( is_int($cipher_keylen) && is_int($expire) && $expire > 0 && $cipher_keylen > 0)) {
            throw new BadNumericParamsException();
        }
        $this->cipher_keylen    = $cipher_keylen;
        $this->expire           = $expire;
    }

    public function open($savePath, $sessionName) {
        $this->digest_len = strlen(hash($this->digest_algo, "", true));
        $this->cipher_ivlen = openssl_cipher_iv_length($this->cipher_algo);
        if ($this->digest_len === false or $this->cipher_ivlen === false) throw new BadAlgoException();

        $this->session_name_len = strlen(session_name());
        $this->session_cookie_params = session_get_cookie_params();

        $this->opened = true;
        return true;
    }

    public function close() {
        return true;
    }

    public function read($id) {
        if (!$this->opened) $this->open("", "");

        if (isset($this->overwritten[$id])) {
            list($ovr_data, $ovr_expires) = $this->overwritten[$id];
            return (time() < $ovr_expires) ? $ovr_data : "";
        }

        if (!isset($_COOKIE[$id])) {
            return "";
        }

        $input = $this->base64_urlsafe_decode($_COOKIE[$id]);
        if ($input === false) {
            return "";
        }

        $digest = substr($input, 0, $this->digest_len);
        if ($digest === false) return "";

        $message = substr($input, $this->digest_len);
        if ($message === false) return "";

        if (!hash_equals(
            hash_hmac($this->digest_algo, $id . $message, $this->secret, true),
            $digest)) {
            return "";
        }

        $valid_till_bin = substr($message, 0, METADATA_SIZE);
        $valid_till = unpack(UINT32_LE_PACK_CODE, $valid_till_bin)[1];

        if (time() > $valid_till) {
            return "";
        }

        $iv = substr($message, METADATA_SIZE, $this->cipher_ivlen);
        $ciphertext = substr($message, METADATA_SIZE + $this->cipher_ivlen);

        $key = $this->pbkdf2($this->digest_algo, $this->secret, $id . $valid_till_bin, 1, $this->cipher_keylen, true);
        $data = openssl_decrypt($ciphertext, $this->cipher_algo, $key, OPENSSL_RAW_DATA, $iv);
        if ($data === false) {
            throw new OpenSSLError();
        }

        return $data;
    }

    public function write($id, $data) {
        if (!$this->opened) $this->open("", "");

        $expires = time() + $this->expire;
        $valid_till_bin = pack(UINT32_LE_PACK_CODE, $expires);

        $iv = openssl_random_pseudo_bytes($this->cipher_ivlen);
        $key = $this->pbkdf2($this->digest_algo, $this->secret, $id . $valid_till_bin, 1, $this->cipher_keylen, true);

        $ciphertext = openssl_encrypt($data, $this->cipher_algo, $key, OPENSSL_RAW_DATA, $iv);
        if ($ciphertext === false) {
            throw new OpenSSLError();
        }

        $meta = $valid_till_bin;
        $message = $meta . $iv . $ciphertext;

        $digest = hash_hmac($this->digest_algo, $id . $message, $this->secret, true);
        $output = $this->base64_urlsafe_encode($digest . $message);
        
        if ( (strlen($output) +
            $this->session_name_len +
            strlen($id) +
            2 * MIN_OVERHEAD_PER_COOKIE) > RFC2965_COOKIE_SIZE
        )
            throw new CookieTooBigException();

        $this->overwritten[$id] = array($data, $expires);
        return setcookie($id,
            $output,
            ($this->session_cookie_params["lifetime"] > 0) ? time() + $this->session_cookie_params["lifetime"] : 0,
            $this->session_cookie_params["path"],
            $this->session_cookie_params["domain"],
            $this->session_cookie_params["secure"],
            $this->session_cookie_params["httponly"]
        );

    }

    public function destroy($id) {
        setcookie( $id, '', time() - 1000 );
        setcookie( $id, '', time() - 1000, '/' );
        unset($this->overwritten[$id]);
        return true;
    }

    public function gc($maxlifetime) {
        return true;
    }

    /*
     * PBKDF2 key derivation function as defined by RSA's PKCS #5: https://www.ietf.org/rfc/rfc2898.txt
     * $algorithm - The hash algorithm to use. Recommended: SHA256
     * $password - The password.
     * $salt - A salt that is unique to the password.
     * $count - Iteration count. Higher is better, but slower. Recommended: At least 1000.
     * $key_length - The length of the derived key in bytes.
     * $raw_output - If true, the key is returned in raw binary format. Hex encoded otherwise.
     * Returns: A $key_length-byte key derived from the password and salt.
     *
     * Test vectors can be found here: https://www.ietf.org/rfc/rfc6070.txt
     *
     * This implementation of PBKDF2 was originally created by https://defuse.ca
     * With improvements by http://www.variations-of-shadow.com
     */
    private function pbkdf2($algorithm, $password, $salt, $count, $key_length, $raw_output = false)
    {
        $algorithm = strtolower($algorithm);
        if(!in_array($algorithm, hash_algos(), true))
            trigger_error('PBKDF2 ERROR: Invalid hash algorithm.', E_USER_ERROR);
        if($count <= 0 || $key_length <= 0)
            trigger_error('PBKDF2 ERROR: Invalid parameters.', E_USER_ERROR);

        if (function_exists("hash_pbkdf2")) {
            // The output length is in NIBBLES (4-bits) if $raw_output is false!
            if (!$raw_output) {
                $key_length = $key_length * 2;
            }
            return hash_pbkdf2($algorithm, $password, $salt, $count, $key_length, $raw_output);
        }

        $hash_length = strlen(hash($algorithm, "", true));
        $block_count = ceil($key_length / $hash_length);

        $output = "";
        for($i = 1; $i <= $block_count; $i++) {
            // $i encoded as 4 bytes, big endian.
            $last = $salt . pack("N", $i);
            // first iteration
            $last = $xorsum = hash_hmac($algorithm, $last, $password, true);
            // perform the other $count - 1 iterations
            for ($j = 1; $j < $count; $j++) {
                $xorsum ^= ($last = hash_hmac($algorithm, $last, $password, true));
            }
            $output .= $xorsum;
        }

        if($raw_output)
            return substr($output, 0, $key_length);
        else
            return bin2hex(substr($output, 0, $key_length));
    }

    private function base64_urlsafe_encode($input) {
        return strtr(base64_encode($input), array("+" => "-", "/" => "_", "=" => ""));
    }

    private function base64_urlsafe_decode($input) {
        $translated = strtr($input, array("-" => "+", "_" => "/"));
        $padded = str_pad($translated, ( (int)((strlen($input) + 3) / 4) ) * 4, "=", STR_PAD_RIGHT);
        return base64_decode($padded);
    }
}

class BadSecretException extends \Exception {

}
class BadAlgoException extends \Exception {

}
class BadNumericParamsException extends \Exception {

}
class CookieTooBigException extends \Exception {

}
class OpenSSLError extends \Exception {

}
