<?php

define('ROOT', dirname(__FILE__));
include(ROOT . '/../tico/Tico.php');

tico(/*'https://my.git/tico/test'*/ 'http://localhost:8000', ROOT)
->option('webroot', ROOT)
->option('case_insensitive_uris', true)
->option('views', [tico()->path('/views')])
->on('*', '/', function() {

    tico()->output(
        array(
            'title' => 'Index',
            'msg' => 'index',
        ),
        'hello.tpl.php'
    );

})
->on('*', '/foo', function() {

    tico()->output(
        array(
            'title' => 'foo',
            'msg' => 'foo',
        ),
        'hello.tpl.php'
    );

})
->on(false, function() {

    tico()->output(
        array(),
        '404.tpl.php',
        array('StatusCode' => 404)
    );

})
->serve()
;
