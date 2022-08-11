<?php

define('ROOT', dirname(__FILE__));
include(ROOT . '/../tico/Tico.php');

class MyModel
{
    public function getMsg()
    {
        return "Hello";
    }
}

tico('http://localhost:8000', ROOT)
    ->option('webroot', ROOT)
    ->option('case_insensitive_uris', true)
    ->option('original_params_key', 'ORIG')
    ->option('views', [tico()->path('/views')])
    //->set('model', new MyModel()) // simple dependency injection container
    ->set('model', function() {
        return new MyModel();
    }) // container supports lazy factory-like functions
    ->middleware(function($next) {

        // eg check if user is authenticated,
        // for example check user cookie and set user var appropriately
        tico()->set('user', tico()->request()->cookies->get('user', 'guest'));
        // start session example (eg native php session)
        $session = new HttpSession(/*array(..)*/);
        tico()->request()->setSession($session);
        $session->start();
        if (!$session->has('count')) $session->set('count', 0);
        $next();

    })
    ->middleware(function($next) {

        // if this condition is met, abort current request, eg user is not authenticated
        if (('guest' == tico()->get('user')) && ('/hello/foo' == tico()->requestPath()))
            //tico()->redirect(tico()->uri('/hello/bar'), 302);
            tico()->output(
                array('title' => 'Hello!', 'msg' => 'guest'),
                'hello.tpl.php'
            );
        // else pass along
        else
            $next();

    })
    ->on('*', '/', function() {

        tico()->output(
            // streamed output
            function() {
                echo tico()->tpl('index.tpl.php', array('title' => 'Demo Index'));
            },
            'html'
        );

    })
    ->on(array('get', 'post'), '/hello/{:msg}', function($params) {

        $session = tico()->request()->getSession();
        $session->set('count', $session->get('count')+1);
        tico()->output(
            array(
                'title' => 'Hello!',
                'msg' => $params['ORIG']['msg'] /*in original case*/,
                'count'=> $session->get('count')
            ),
            'hello.tpl.php'
        );

    })
    ->onGroup('/foo', function() {

        // group routes under common prefix
        tico()
            // /foo/moo
            ->on('*', '/moo', function() {
                tico()->output(
                    array(
                        'title' => 'Group Route',
                        'msg' => 'Group Route /foo/moo',
                        'count'=> 0
                    ),
                    'hello.tpl.php'
                );
            })
            // /foo/koo
            ->onGroup('/koo', function() {
                tico()
                    // /foo/koo
                    ->on('*', '/', function() {
                        tico()->output(
                            array(
                                'title' => 'Group Route',
                                'msg' => 'Group Route /foo/koo',
                                'count'=> 0
                            ),
                            'hello.tpl.php'
                        );
                    })
                    // /foo/koo/soo
                    ->on('*', '/soo', function() {
                        tico()->output(
                            array(
                                'title' => 'Group Route',
                                'msg' => 'Group Route /foo/koo/soo',
                                'count'=> 0
                            ),
                            'hello.tpl.php'
                        );
                    })
                ;
            })
        ;

    })
    ->on('*', '/json/api', function() {

        tico()->output(array(
            'param1' => '123',
            'param2' => '456',
            'param3' => '789'
        ), 'json');

    })
    ->on('*', '/download', function() {

        tico()->output(
            tico()->path('/file.txt'),
            'file'
        );

    })
    ->on('*', '/redirect', function() {

        tico()->redirect(tico()->uri('/'), 302);

    })
    ->on(false, function() {

        tico()->output(
            array(),
            '404.tpl.php',
            array('StatusCode' => 404)
        );

    })
    ->middleware(function($next) {

        // post process, eg create cache files from response
        if ((200 == tico()->response()->getStatusCode()) && 'text/html'==tico()->response()->headers->get('Content-Type') && !tico()->response()->getFile() && !tico()->response()->getCallback())
        {
            tico()->response()->setContent(tico()->response()->getContent() . '<!-- post processed -->');
        }

    }, 'after')
    ->serve()
;

exit;