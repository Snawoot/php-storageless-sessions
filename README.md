# php-storageless-sessions [![Build Status](https://travis-ci.org/Snawoot/php-storageless-sessions.svg?branch=master)](https://travis-ci.org/Snawoot/php-storageless-sessions)
Sessions handler which stores session data in HMAC-signed and encrypted cookies.

---

:heart: :heart: :heart:

You can say thanks to the author by donations to these wallets:

- ETH: `0xB71250010e8beC90C5f9ddF408251eBA9dD7320e`
- BTC:
  - Legacy: `1N89PRvG1CSsUk9sxKwBwudN6TjTPQ1N8a`
  - Segwit: `bc1qc0hcyxc000qf0ketv4r44ld7dlgmmu73rtlntw`

---

## Requirements
* PHP 5.4.0 or newer
* OpenSSL extension (built-in by default)
* Hash extension (built-in by default)
* Enabled output buffering (`output_buffering=1` or `output_buffering=On` in php.ini)

## Usage
### Plain PHP
```php
<?php

$secret = "reallylongsecretplease";
$handler = new VladislavYarmak\StoragelessSession\CryptoCookieSessionHandler($secret);

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
        class:     VladislavYarmak\StoragelessSession\CryptoCookieSessionHandler
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
