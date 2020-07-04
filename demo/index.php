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
        tico()->set('user', tico()->request()->cookies->get('user', 'guest'));
        // start session example (eg native php session)
        $session = new HttpSession(/*array(..)*/);
        tico()->request()->setSession($session);
        $session->start();
        if ( !$session->has('count') ) $session->set('count', 0);
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

        $session = tico()->request()->getSession();
        $session->set('count', $session->get('count')+1);
        tico()->output(
            array(
                'title' => 'Hello!',
                'msg' => $params['msg'],
                'count'=> $session->get('count')
            ),
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
    ->on('*', '/download', function( ) {

        tico()->output(
            tico()->path('/file.txt'),
            'file'
        );

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
        if ( (200 == tico()->response()->getStatusCode()) && 'text/html'==tico()->response()->headers->get('Content-Type') && !tico()->response()->getFile() && !tico()->response()->getCallback() )
        {
            tico()->response()->setContent(tico()->response()->getContent().'<!-- post processed -->');
        }

    }, 'after')
    ->serve()
;

exit;