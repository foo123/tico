# tico

Tiny, super-simple but versatile quasi-MVC web framework for PHP (v.1.0.0)


**Uses:**

1. [`Importer`](https://github.com/foo123/Importer) class &amp; asset dependency loader
2. [`Dromeo`](https://github.com/foo123/Dromeo) versatile pattern router
3. [`InTpl`](https://github.com/foo123/InTpl) simple php templates w/ inheritance
4. `HttpFoundation` adapted from **Symfony's HttpFoundation component**


**demo** (see `/demo/index.php`)

```php
include(dirname(__FILE__).'/../tico/Tico.php');

tico('http://localhost:8000', dirname(__FILE__))
    ->locale([

        'Hello!' => 'Γεια σας!'
        //.. more localised strings ..

    ], 'el')
    ->on('*', '/', function( ) {

        tico()->output(
            ['title' => 'Demo Index'],
            tico()->path('/views/index.tpl.php')
        );

    })
    ->on(['get', 'post'], '/hello/{:msg}', function( $params ) {

        tico()->output(
            ['title' => tico()->l('Hello!'), 'msg' => $params['msg']],
            tico()->path('/views/hello.tpl.php')
        );

    })
    ->on('*', '/json/api', function( ) {

        tico()->output([
            'param1' => '123',
            'param2' => '456',
            'param3' => '789'
        ], 'json');

    })
    ->on('*', '/redirect', function( ) {

        tico()->redirect(tico()->uri('/'), 302);

    })
    ->on(false, function( ) {

        tico()->output(
            [],
            tico()->path('/views/404.tpl.php'),
            array('StatusCode' => 404)
        );

    })
    ->serve()
;
```
