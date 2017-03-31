<?php

namespace VladislavYarmak\StoragelessSession;

const UINT32_LE_PACK_CODE       =   "V";
const UINT32_SIZE               =   4;
const RFC2965_COOKIE_SIZE       =   4096;
const MIN_OVERHEAD_PER_COOKIE   =   3;
const METADATA_SIZE             =   UINT32_SIZE;

final class CryptoCookieSessionHandler implements \SessionHandlerInterface {
    private $secret;
    private $digest_algo;
    private $digest_len;
    private $cipher_algo;
    private $cipher_ivlen;
    private $session_name_len;
    private $session_cookie_params;
    private $overwritten = array();

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

        return true;
    }

    public function close() {
        return true;
    }

    public function read($id) {
        if (isset($this->overwritten[$id])) return $this->overwritten[$id];

        if (!isset($_COOKIE[$id])) {
            return "";
        }

        $input = base64_decode($_COOKIE[$id]);
        if ($input === false) {
            return "";
        }

        $digest = substr($input, 0, $this->digest_len);
        $message = substr($input, $this->digest_len);

        if (!hash_equals(
            hash_hmac($this->digest_algo, $message, $this->secret, true),
            $digest)) {
            return "";
        }

        $valid_till = unpack(UINT32_LE_PACK_CODE, substr($message, 0, METADATA_SIZE))[1];

        if (time() > $valid_till) {
            return "";
        }

        $iv = substr($message, METADATA_SIZE, $this->cipher_ivlen);
        $ciphertext = substr($message, METADATA_SIZE + $this->cipher_ivlen);

        $key = hash_pbkdf2($this->digest_algo, $this->secret, $iv, 1, $this->cipher_keylen, true);
        $data = openssl_decrypt($ciphertext, $this->cipher_algo, $key, OPENSSL_RAW_DATA, $iv);
        if ($data === false) {
            throw new OpenSSLError();
        }

        return $data;
    }

    public function write($id, $data) {
        $iv = openssl_random_pseudo_bytes($this->cipher_ivlen);
        $key = hash_pbkdf2($this->digest_algo, $this->secret, $iv, 1, $this->cipher_keylen, true);

        $ciphertext = openssl_encrypt($data, $this->cipher_algo, $key, OPENSSL_RAW_DATA, $iv);
        if ($ciphertext === false) {
            throw new OpenSSLError();
        }

        $meta = pack(UINT32_LE_PACK_CODE, time() + $this->expire);
        $message = $meta . $iv . $ciphertext;

        $digest = hash_hmac($this->digest_algo, $message, $this->secret, true);
        $output = rtrim(base64_encode($digest . $message), '=');
        
        if ( (strlen($output) +
            $this->session_name_len +
            strlen($id) +
            2 * MIN_OVERHEAD_PER_COOKIE) > RFC2965_COOKIE_SIZE
        )
            throw new CookieTooBigException();

        $this->overwritten[$id] = $data;
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
