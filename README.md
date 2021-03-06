# tico

Tiny, super-simple but versatile quasi-MVC web framework for PHP (v.1.8.0)


**Uses:**

1. [`Importer`](https://github.com/foo123/Importer) class &amp; asset dependency loader
2. [`Dromeo`](https://github.com/foo123/Dromeo) versatile pattern router
3. [`InTpl`](https://github.com/foo123/InTpl) simple php templates w/ inheritance
4. `HttpFoundation` adapted from **Symfony's HttpFoundation component**


**demo** (see `/demo/index.php`)

```php
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
    // some options
    ->option('webroot', ROOT)
    ->option('views', array(tico()->path('/views')))
    ->option('case_insensitive_uris', true)

    //->set('model', new MyModel()) // simple dependency injection container
    ->set('model', function( ) {
        return new MyModel();
    }) // container supports lazy factory-like functions

    // middleware functionality
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
                'hello.tpl.php'
            );
        // else pass along
        else
            $next();

    })


    // can handle other ports from same script, as long as handling is directed to this file
    /*
    ->onPort(4040) // on :4040 port
    //->onPort('*') // on any port
        ->on('*', '/', function( ) {

            tico()->output(
                array('title' => 'Demo Port Index'),
                'foo/index.tpl.php'
            );

        })
        ->on(false, function( ) {

            tico()->output(
                array(),
                'foo/404.tpl.php',
                array('StatusCode' => 404)
            );

        })
    */
    
    // can handle subdomains from same script, as long as subdomain handling is directed to this file
    /*
    ->onSubdomain('foo') // on "foo." subdomain
    //->onSubdomain('*') // on any subdomain
        ->on('*', '/', function( ) {

            tico()->output(
                array('title' => 'Demo Subdomain Index'),
                'foo/index.tpl.php'
            );

        })
        ->on(false, function( ) {

            tico()->output(
                array(),
                'foo/404.tpl.php',
                array('StatusCode' => 404)
            );

        })
    */

    //->onSubdomain(false) // on main domain / port
        ->on('*', '/', function( ) {

            tico()->output(
                array('title' => 'Demo Index'),
                'index.tpl.php'
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
                'hello.tpl.php'
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
                '404.tpl.php',
                array('StatusCode' => 404)
            );

        })

    // middlewares are same for main domain and all subdomains and all ports
    ->middleware(function( $next ) {

        // post process, eg create cache files from response
        if ( (200 == tico()->response()->getStatusCode()) && 'text/html'==tico()->response()->headers->get('Content-Type') && !tico()->response()->getFile() && !tico()->response()->getCallback() )
        {
            tico()->response()->setContent(tico()->response()->getContent().'<!-- post processed -->');
        }

    }, 'after')
    
    ->serve()
;
```
