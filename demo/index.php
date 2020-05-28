<?php
define('ROOT', dirname(__FILE__));

include(ROOT.'/../tico/Tico.php');

tico('http://localhost:8000', ROOT)
    ->on('{/:?}', function(){
        
        tico()->output('Tico Index', 'text');
    
    })
    ->on('/hello/{:msg}', function($params){
        
        tico()->output(array('msg'=>$params['msg']), ROOT.'/views/hello_world.tpl.php');
    
    })
    ->on('/json/api', function(){
        
        tico()->output(array(
            'param1' => '123',
            'param2' => '456',
            'param3' => '789'
        ), 'json');
    
    })
    ->on('/redirect', function(){
        
        tico()->redirect(tico()->uri('/'));
    
    })
    ->on(false, function(){
        
        tico()->output('404', 'text');
    
    })
    ->serve()
;

exit;