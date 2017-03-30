# php-storageless-sessions
Sessions handler which stores session data in HMAC-signed and encrypted cookies.

## Requirements
* PHP 5.6.0 or newer
* OpenSSL extension (built-in by default)
* Hash extension (built-in by default)

## Usage
### Plain PHP
```php
<?php

$secret = "reallylongsecretplease";
$handler = new StoragelessSession\CryptoCookieSessionHandler($secret);

session_set_save_handler($handler, true);
session_start();

$_SESSION["key"] = "value";
```
### Symfony
```yaml
framework:
    session:
        handler_id:  session.handler.cookie

services:
    session.handler.cookie:
        class:     SessionHandler\Cookie
        public:    true
        arguments:    ['reallylongsecretplease']
```
## Handler constructor parameters
```
CryptoCookieSessionHandler($secret, $expire = 2592000, $digest_algo = "sha256", $cipher_algo = "aes-256-cbc", $cipher_keylen = 32)
```
* `$secret` - secret passphrase used for HMAC signature and encryption
* `$expire` - expiration time of HMAC signature
* `$digest_algo` - hash algorithm used for key derivation and cookie signature. See `hash_algos()` for all available message digest algorithms.
* `$cipher_algo` - cipher algorithm used for session contents encryption. See `openssl_get_cipher_methods()` for all available ciphers.
* `$cipher_keylen` - proper key length for specified cipher algorithm, used for encryption key derivation
