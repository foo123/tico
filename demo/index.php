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
    ->option('views', [tico()->path('/views')])
    ->option('normalized_uris', true)
    ->option('normalize_uri', function($part) {
        $part = str_replace(array('ά', 'έ', 'ή', 'ί', 'ϊ', 'ΐ', 'ό', 'ύ', 'ϋ', 'ΰ', 'ώ', 'ς'), array('α', 'ε', 'η', 'ι', 'ι', 'ι', 'ο', 'υ', 'υ', 'υ', 'ω', 'σ'), mb_strtolower($part, 'UTF-8'));
        return $part;
    })
    ->option('route_params_object', true)
    //->set('model', new MyModel()) // simple dependency injection container
    ->set('model', function() {
        return new MyModel();
    }) // container supports lazy factory-like functions
    ->set('cache', function() {
        include tico()->path('/cache/CacheManager.php');
        return (new CacheManager())
            ->option('cache_dur_sec', 2 * 60/*2 minutes*/)
            ->option('cache_dir', tico()->path('/cache/data'))
        ;
    }) // container supports lazy factory-like functions
    ->hook('tico_before_serve_cached', function() {
        // a custom hook
        tico()->variable('tico_before_serve_cached__content', tico()->variable('tico_before_serve_cached__content')."\n\n<!--cached version-->");
    })
;


// if cache enabled and served, exit fast and early
(tico()->serveCache())

or

// else serve request normally, using full framework
(tico()
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
            array('title' => 'Hello!', 'msg' => 'guest', 'count'=> 0),
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
->on(['get', 'post'], '/hello/{:msg}', function($params) {

    $session = tico()->request()->getSession();
    $session->set('count', $session->get('count')+1);
    tico()->output(
        array(
            'title' => 'Hello!',
            'msg' => ('msg:'.$params->get('msg', '&lt;empty&gt;', true)).(',param:'.tico()->requestParam('param', '&lt;empty&gt;')) /*in original case*/,
            'count'=> $session->get('count')
        ),
        'hello.tpl.php'
    );

})
// non-ascii/utf8 normalized uris
->on(['get', 'post'], '/γεια/{:msg}', function($params) {

    $session = tico()->request()->getSession();
    $session->set('count', $session->get('count')+1);
    tico()->output(
        array(
            'title' => 'Γειά!',
            'msg' => ('msg:'.$params->get('msg', '&lt;empty&gt;', true)).(',param:'.tico()->requestParam('param', '&lt;empty&gt;')) /*in original case*/,
            'count'=> $session->get('count')
        ),
        'hello.tpl.php'
    );

})
->onGroup('/foo', function() {

    // group routes under common prefix
    tico()
        // /foo
        ->on('*', '/', function() {
            tico()->output(
                array(
                    'title' => 'Group Route',
                    'msg' => 'Group Route /foo',
                    'count'=> 0
                ),
                'hello.tpl.php'
            );
        })
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
->on('*', '/fetch', function() {

    $uri = tico()->request()->query->get('uri', 'https://github.com/foo123/tico');
    tico()
    ->variable('cache', false) // don't cache this page
    ->http('get', 'server', $uri, null, null, $output, $status) // do http request
    ->output(
    !$status ? '<span style="color:red;font-size:16px;">-- An error occured</span>' : (200 <= $status && $status < 300 ? $output : "<span style=\"color:".(400 <= $status && $status < 500 ? 'orange' : (500 <= $status ? 'red' : 'green')).";font-size:16px;\">-- Response Status for &quot;{$uri}&quot;: <b>{$status}</b> --</span>"),
    'html'
    );
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
->serve())
;

exit;