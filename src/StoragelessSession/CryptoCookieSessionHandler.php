<?php

namespace StoragelessSession;

const UINT16_LE_PACK_CODE       =   "v";
const UINT16_SIZE               =   2;
const UINT32_LE_PACK_CODE       =   "V";
const UINT32_SIZE               =   4;
const RFC2965_COOKIE_SIZE       =   4096;
const MIN_OVERHEAD_PER_COOKIE   =   3;
const METADATA_SIZE             =   UINT32_SIZE + UINT16_SIZE;

function addBlockPadding($str, $bsize) {
    $len = strlen($str);
    $remainder = $len % $bsize;
    $targetlen = (int)(($len + $bsize - 1) / $bsize) * $bsize;
    $padded = str_pad($str, $targetlen, "\0", STR_PAD_RIGHT);
    return array($padded, $bsize - $remainder);
}

function removeBlockPadding($str, $padding_bytes) {
    return substr($str, 0, -$padding_bytes);
}

class CryptoCookieSessionHandler implements \SessionHandlerInterface {
    private $secret;
    private $digest_algo;
    private $digest_len;
    private $cipher_algo;
    private $cipher_ivlen;
    private $session_name_len;
    private $session_cookie_params;

    public function __construct(
        $secret,
        $expire         = 2592000,
        $digest_algo    = "sha256",
        $cipher_algo    = "aes-256-cbc",
        $cipher_keylen  = 32
    ) {
        $this->secret           = $secret;
        $this->digest_algo      = $digest_algo;
        $this->cipher_algo      = $cipher_algo;
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

        extract(unpack(UINT32_LE_PACK_CODE . 'valid_till/' . UINT16_LE_PACK_CODE . 'pad_leftover',
            substr($message, 0, METADATA_SIZE)));

        if (time() > $valid_till) {
            return "";
        }

        $iv = substr($message, METADATA_SIZE, $this->cipher_ivlen);
        $ciphertext = substr($message, METADATA_SIZE + $this->cipher_ivlen);

        $key = hash_pbkdf2($this->digest_algo, $this->secret, $iv, 1, $this->cipher_keylen, true);
        $data = openssl_decrypt($ciphertext, $this->cipher_algo, $key, OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING, $iv);
        if ($data === false) {
            throw new OpenSSLError();
        }

        return removeBlockPadding($data, $pad_leftover);
    }

    public function write($id, $data) {
        $iv = openssl_random_pseudo_bytes($this->cipher_ivlen);
        $key = hash_pbkdf2($this->digest_algo, $this->secret, $iv, 1, $this->cipher_keylen, true);

        list($padded_data, $leftover) = addBlockPadding($data, $this->cipher_ivlen);

        $ciphertext = openssl_encrypt($padded_data, $this->cipher_algo, $key, OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING, $iv);
        if ($ciphertext === false) {
            throw new OpenSSLError();
        }

        $meta = pack(UINT32_LE_PACK_CODE . UINT16_LE_PACK_CODE, time() + $this->expire, $leftover);
        $message = $meta . $iv . $ciphertext;

        $digest = hash_hmac($this->digest_algo, $message, $this->secret, true);
        $output = rtrim(base64_encode($digest . $message), '=');
        
        if ( (strlen($output) +
            $this->session_name_len +
            strlen($id) +
            2 * MIN_OVERHEAD_PER_COOKIE) > RFC2965_COOKIE_SIZE
        )
            throw new CookieTooBigException();

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
class CookieTooBigException extends \Exception {

}
class OpenSSLError extends \Exception {

}
