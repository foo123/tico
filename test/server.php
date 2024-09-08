<?php
// This file allows us to emulate Apache's "mod_rewrite" functionality from the
// built-in PHP web server. This provides a convenient way to test an
// application without having installed a "real" web server software here.
// run as: "php -S localhost:8000 server.php"

$__DIR__ = dirname(__FILE__);

$uri = /*urldecode(*/parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH)/*)*/;
if (!strlen($uri)) $uri = '/';

//if ('/index.php' == substr($uri, -10)) $uri = substr($uri, 0, -9); // remove '/index.php' from uri

if ($uri !== '/' && $uri !== '/subfolder/' && file_exists($__DIR__ . '/' . $uri)) return false; // existing file, serve as-is

if (0 === strpos($uri, '/subfolder/')) include($__DIR__ . '/subfolder/index.php'); // dispatch to subfolder app
else include($__DIR__ . '/index.php'); // dispatch to main app
