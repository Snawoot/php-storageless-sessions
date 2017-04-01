<?php

namespace VladislavYarmak\StoragelessSession;

function setcookie(
    $name,
    $value = "",
    $expire = 0,
    $path = "",
    $domain = "",
    $secure = false,
    $httponly = false) {

    if (!array_key_exists('_SETCOOKIE', $GLOBALS)) $GLOBALS["_SETCOOKIE"] = array();
    $GLOBALS["_SETCOOKIE"][$name] = compact("value", "expire", "path", "domain", "secure", "httponly");
    return true;
}

require_once(__DIR__ . "/../src/VladislavYarmak/StoragelessSession/CryptoCookieSessionHandler.php");