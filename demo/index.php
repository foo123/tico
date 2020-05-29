<?php
define('ROOT', dirname(__FILE__));
define('VIEWS', ROOT . '/views');

include(ROOT.'/../tico/Tico.php');

tico('http://localhost:8000', ROOT)
    ->on('*', '{/:?}', function(){

        tico()->output(array('title'=>'Demo Index'), VIEWS.'/index.tpl.php');

    })
    ->on(array('get', 'post'), '/hello/{:msg}', function($params){

        tico()->output(array('title'=>'Hello!', 'msg'=>$params['msg']), VIEWS.'/hello.tpl.php');

    })
    ->on('*', '/json/api', function(){

        tico()->output(array(
            'param1' => '123',
            'param2' => '456',
            'param3' => '789'
        ), 'json');

    })
    ->on('*', '/redirect', function(){

        tico()->redirect(tico()->uri('/'), 302);

    })
    ->on(false, function(){

        tico()->output(array(), VIEWS.'/404.tpl.php', array('StatusCode'=>404));

    })
    ->serve()
;

exit;