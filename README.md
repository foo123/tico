# tico

Tiny, super-simple but versatile quasi-MVC web framework for PHP (**v.1.22.0** in progress)


**Uses:**

1. [`Importer`](https://github.com/foo123/Importer) class &amp; asset dependency loader
2. [`Dromeo`](https://github.com/foo123/Dromeo) versatile pattern router
3. [`InTpl`](https://github.com/foo123/InTpl) simple php templates w/ inheritance
4. `HttpFoundation` adapted from [Symfony's HttpFoundation component (v.7.3.1 / 2025)](https://github.com/symfony/http-foundation)


**demo** (see `/demo/index.php`)

```php
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
    // some options
    ->option('webroot', ROOT) // default
    ->option('views', [tico()->path('/views')])
    ->option('normalized_uris', true) // default
    ->option('normalize_uri', function($part) {
        return str_replace(array('ά','έ','ή','ί','ϊ','ΐ','ό','ύ','ϋ','ΰ','ώ','ς'), array('α','ε','η','ι','ι','ι','ο','υ','υ','υ','ω','σ'), mb_strtolower($part, 'UTF-8'));
    })
    /*->option('tpl_render', function($tpl, $data, $viewsFolders) {
        // custom template renderer
        return MyFancyTpl::render($tpl, $data);
    })*/
    //->set('model', new MyModel()) // simple dependency injection container
    ->set('model', function() {
        return new MyModel();
    }) // container supports lazy factory-like functions
    ->set('cache', function() {
        // any custom caching solution can be used that has get/set methods, here a simple CacheManager
        include tico()->path('/cache/CacheManager.php');
        return (new CacheManager())
            ->option('cache_dur_sec', 10 * 60/*10 minutes*/)
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
// middleware functionality
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
    if (('guest'==tico()->get('user')) && ('/hello/foo'==tico()->requestPath()))
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
// on :4040 port, '*' means on any port
->onPort(4040, function() {

    tico()
        ->on('*', '/', function() {

            tico()->output(
                array('title' => 'Demo Port Index'),
                '4040/index.tpl.php'
            );

        })
        ->on(false, function() {

            tico()->output(
                array(),
                '4040/404.tpl.php',
                array('StatusCode' => 404)
            );

        })
    ;

})

// can handle subdomains from same script, as long as subdomain handling is directed to this file
// on "foo." subdomain, '*' means on any subdomain
->onSubdomain('foo', function() {

    tico()
        ->on('*', '/', function() {

            tico()->output(
                array('title' => 'Demo Subdomain Index'),
                'foo/index.tpl.php'
            );

        })
        ->on(false, function() {

            tico()->output(
                array(),
                'foo/404.tpl.php',
                array('StatusCode' => 404)
            );

        })
    ;

})

// on main domain / port
->on('*', '/', function() {

    tico()->output(
        array('title' => 'Demo Index'),
        'index.tpl.php'
    );

})
->on(['get', 'post'], '/hello/{:msg}', function($params) {

    $session = tico()->request()->getSession();
    $session->set('count', $session->get('count')+1);
    tico()->output(
        array(
            'title' => 'Hello!',
            'msg' => $params[':']['msg'], // original msg
            'count'=> $session->get('count')
        ),
        'hello.tpl.php'
    );

})
// non-ascii/unicode normalized uris
->on(['get', 'post'], '/γεια/{:msg}', function($params) {

    $session = tico()->request()->getSession();
    $session->set('count', $session->get('count')+1);
    tico()->output(
        array(
            'title' => 'Γειά!',
            'msg' => $params[':']['msg'], // original msg
            'count'=> $session->get('count')
        ),
        'hello.tpl.php'
    );

})
// group routes under common prefix
->onGroup('/foo', function() {

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
->on(false, function() {

    tico()->output(
        array(),
        '404.tpl.php',
        array('StatusCode' => 404)
    );

})

// middlewares are same for main domain and all subdomains and all ports
->middleware(function($next) {

    // post process, eg create cache files from response
    if ((200 == tico()->response()->getStatusCode()) && 'text/html'==tico()->response()->headers->get('Content-Type') && !tico()->response()->getFile() && !tico()->response()->getCallback())
    {
        tico()->response()->setContent(tico()->response()->getContent().'<!-- post processed -->');
    }

}, 'after')

->serve())
;
```

**see also:**

* [ModelView](https://github.com/foo123/modelview.js) a simple, fast, powerful and flexible MVVM framework for JavaScript
* [tico](https://github.com/foo123/tico) a tiny, super-simple MVC framework for PHP
* [LoginManager](https://github.com/foo123/LoginManager) a simple, barebones agnostic login manager for PHP, JavaScript, Python
* [SimpleCaptcha](https://github.com/foo123/simple-captcha) a simple, image-based, mathematical captcha with increasing levels of difficulty for PHP, JavaScript, Python
* [Dromeo](https://github.com/foo123/Dromeo) a flexible, and powerful agnostic router for PHP, JavaScript, Python
* [PublishSubscribe](https://github.com/foo123/PublishSubscribe) a simple and flexible publish-subscribe pattern implementation for PHP, JavaScript, Python
* [Localizer](https://github.com/foo123/Localizer) a simple and versatile localization class (l10n) for PHP, JavaScript, Python
* [Importer](https://github.com/foo123/Importer) simple class &amp; dependency manager and loader for PHP, JavaScript, Python
* [Contemplate](https://github.com/foo123/Contemplate) a fast and versatile isomorphic template engine for PHP, JavaScript, Python
* [HtmlWidget](https://github.com/foo123/HtmlWidget) html widgets, made as simple as possible, both client and server, both desktop and mobile, can be used as (template) plugins and/or standalone for PHP, JavaScript, Python (can be used as [plugins for Contemplate](https://github.com/foo123/Contemplate/blob/master/src/js/plugins/plugins.txt))
* [Paginator](https://github.com/foo123/Paginator)  simple and flexible pagination controls generator for PHP, JavaScript, Python
* [Formal](https://github.com/foo123/Formal) a simple and versatile (Form) Data validation framework based on Rules for PHP, JavaScript, Python
* [Dialect](https://github.com/foo123/Dialect) a cross-vendor &amp; cross-platform SQL Query Builder, based on [GrammarTemplate](https://github.com/foo123/GrammarTemplate), for PHP, JavaScript, Python
* [DialectORM](https://github.com/foo123/DialectORM) an Object-Relational-Mapper (ORM) and Object-Document-Mapper (ODM), based on [Dialect](https://github.com/foo123/Dialect), for PHP, JavaScript, Python
* [Unicache](https://github.com/foo123/Unicache) a simple and flexible agnostic caching framework, supporting various platforms, for PHP, JavaScript, Python
* [Xpresion](https://github.com/foo123/Xpresion) a simple and flexible eXpression parser engine (with custom functions and variables support), based on [GrammarTemplate](https://github.com/foo123/GrammarTemplate), for PHP, JavaScript, Python
* [Regex Analyzer/Composer](https://github.com/foo123/RegexAnalyzer) Regular Expression Analyzer and Composer for PHP, JavaScript, Python
