<?php

define('ROOT', dirname(__FILE__));
include(ROOT.'/../tico/Tico.php');

class MyModel
{
    public function getMsg()
    {
        return "Hello";
    }
}

tico('http://localhost:8000', ROOT)
    ->set('model', new MyModel()) // simple dependency injection container
    ->middleware(function( $next ) {

        // eg check if user is authenticated,
        // for example check user cookie and set user var appropriately
        tico()->set('user', isset($_COOKIE['user']) ? $_COOKIE['user'] : 'guest');
        $next();

    })
    ->middleware(function( $next ) {

        // if this condition is met, abort current request, eg user is not authenticated
        if ( ('guest'==tico()->get('user')) && ('/hello/foo'==tico()->requestPath()) )
            //tico()->redirect(tico()->uri('/hello/bar'), 302);
            tico()->output(
                array('title' => 'Hello!', 'msg' => 'guest'),
                tico()->path('/views/hello.tpl.php')
            );
        // else pass along
        else
            $next();

    })
    ->on('*', '/', function( ) {

        tico()->output(
            array('title' => 'Demo Index'),
            tico()->path('/views/index.tpl.php')
        );

    })
    ->on(array('get', 'post'), '/hello/{:msg}', function( $params ) {

        tico()->output(
            array('title' => 'Hello!', 'msg' => $params['msg']),
            tico()->path('/views/hello.tpl.php')
        );

    })
    ->on('*', '/json/api', function( ) {

        tico()->output(array(
            'param1' => '123',
            'param2' => '456',
            'param3' => '789'
        ), 'json');

    })
    ->on('*', '/redirect', function( ) {

        tico()->redirect(tico()->uri('/'), 302);

    })
    ->on(false, function( ) {

        tico()->output(
            array(),
            tico()->path('/views/404.tpl.php'),
            array('StatusCode' => 404)
        );

    })
    ->middleware(function( $next ) {

        // post process, eg create cache files from response
        if ( (200 == tico()->response()->getStatusCode()) && !tico()->response()->getFile() && !tico()->response()->getCallback() )
        {
            tico()->response()->setContent(tico()->response()->getContent().'<!-- post processed -->');
        }

    }, 'after')
    ->serve()
;

exit;