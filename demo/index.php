<?php
define('ROOT', dirname(__FILE__));

include(ROOT.'/../tico/Tico.php');

tico('http://localhost:8000', ROOT)
->on('{/:?}', function(){
    tico()->output('Tico v.1.0.0 Index', 'text');
})
->on('/hello/{:msg}', function($params){
    tico()->output(array('msg'=>$params['msg']), ROOT.'/views/hello_world.tpl.php');
})
->on('/redirect', function($params){
    tico()->redirect(tico()->uri('/'));
})
->on(false, function(){
    tico()->output('404', 'text');
})
->serve()
;

exit;