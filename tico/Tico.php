<?php
/**
*
* Tiny, super-simple but versatile quasi-MVC web framework for PHP
* @version 1.0.0
* https://github.com/foo123/tico
*
*/

if ( !defined('TICO') ) define('TICO', dirname(__FILE__));
class Tico
{
    const VERSION = '1.0.0';

    public $Loader = null;
    public $Router = null;
    public $Response = null;

    public $BaseUrl = '';
    public $BasePath = '';

    protected $tplCallStack = array();
    public $LanguagePluralForm = array();
    public $Language = array();
    public $Locale = null;

    public function __construct( $baseUrl='', $basePath='' )
    {
        $this->BaseUrl = rtrim($baseUrl, '/');
        $this->BasePath = rtrim($basePath, '/\\');
    }

    protected function _fixServerVars( )
    {
        $default_server_values = array(
            'SERVER_SOFTWARE' => '',
            'REQUEST_URI' => '',
        );

        $_SERVER = array_merge( $default_server_values, $_SERVER );

        // Fix for IIS when running with PHP ISAPI
        if ( empty( $_SERVER['REQUEST_URI'] ) || ( PHP_SAPI != 'cgi-fcgi' && preg_match( '/^Microsoft-IIS\//', $_SERVER['SERVER_SOFTWARE'] ) ) ) {

            // IIS Mod-Rewrite
            if ( isset( $_SERVER['HTTP_X_ORIGINAL_URL'] ) ) {
                $_SERVER['REQUEST_URI'] = $_SERVER['HTTP_X_ORIGINAL_URL'];
            }
            // IIS Isapi_Rewrite
            elseif ( isset( $_SERVER['HTTP_X_REWRITE_URL'] ) ) {
                $_SERVER['REQUEST_URI'] = $_SERVER['HTTP_X_REWRITE_URL'];
            } else {
                // Use ORIG_PATH_INFO if there is no PATH_INFO
                if ( !isset( $_SERVER['PATH_INFO'] ) && isset( $_SERVER['ORIG_PATH_INFO'] ) )
                    $_SERVER['PATH_INFO'] = $_SERVER['ORIG_PATH_INFO'];

                // Some IIS + PHP configurations puts the script-name in the path-info (No need to append it twice)
                if ( isset( $_SERVER['PATH_INFO'] ) ) {
                    if ( $_SERVER['PATH_INFO'] == $_SERVER['SCRIPT_NAME'] )
                        $_SERVER['REQUEST_URI'] = $_SERVER['PATH_INFO'];
                    else
                        $_SERVER['REQUEST_URI'] = $_SERVER['SCRIPT_NAME'] . $_SERVER['PATH_INFO'];
                }

                // Append the query string if it exists and isn't null
                if ( ! empty( $_SERVER['QUERY_STRING'] ) ) {
                    $_SERVER['REQUEST_URI'] .= '?' . $_SERVER['QUERY_STRING'];
                }
            }
        }

        // Fix for PHP as CGI hosts that set SCRIPT_FILENAME to something ending in php.cgi for all requests
        if ( isset( $_SERVER['SCRIPT_FILENAME'] ) && ( strpos( $_SERVER['SCRIPT_FILENAME'], 'php.cgi' ) == strlen( $_SERVER['SCRIPT_FILENAME'] ) - 7 ) )
            $_SERVER['SCRIPT_FILENAME'] = $_SERVER['PATH_TRANSLATED'];

        // Fix for Dreamhost and other PHP as CGI hosts
        if ( strpos( $_SERVER['SCRIPT_NAME'], 'php.cgi' ) !== false )
            unset( $_SERVER['PATH_INFO'] );

        // Fix empty PHP_SELF
        if ( empty( $_SERVER['PHP_SELF'] ) )
            $_SERVER['PHP_SELF'] = preg_replace( '/(\?.*)?$/', '', $_SERVER["REQUEST_URI"] );
    }

    public function loader( )
    {
        if ( $this->Loader ) return $this->Loader;
        if ( !class_exists('Importer', false) ) include( TICO.'/Importer.php' );
        $this->Loader = new Importer( $this->BasePath, $this->BaseUrl );
        return $this->Loader;
    }

    public function router( )
    {
        if ( $this->Router ) return $this->Router;
        if ( !class_exists('Dromeo', false) ) include( TICO.'/Dromeo.php' );
        $this->Router = new Dromeo( /*$this->BaseUrl*/ );
        return $this->Router;
    }

    public function response( )
    {
        if ( $this->Response ) return $this->Response;
        if ( !class_exists('HttpResponse', false) ) include( TICO.'/HttpResponse.php' );
        $this->Response = new HttpResponse( );
        return $this->Response;
    }

    public function tpl( $tpl, $data=array() )
    {
        if ( !class_exists('InTpl', false) ) include(TICO.'/InTpl.php');
        return InTpl::Tpl($tpl)->render($data);
    }

    public function output( $data, $type='html', $headers=array() )
    {
        $type = empty($type) ? 'html' : $type;
        switch( $type )
        {
            case 'pre':
                if ( is_array($data) || is_object($data) ) $data = print_r($data, true);
                $data = '<pre>' . str_replace(array('&','<','>'), array('&amp;','&lt;','&gt;'), (string)$data) . '</pre>';
                // no break

            case 'html':
                if ( !$this->response()->headers->has('Content-Type') )
                {
                    $this->response()->headers->set('Content-Type', 'text/html');
                }
                // no break

            case 'text':
                if ( !$this->response()->headers->has('Content-Type') )
                {
                    $this->response()->headers->set('Content-Type', 'text/plain');
                }
                $this->response()->setContent((string)$data);
                break;

            case 'json':
                if ( !$this->response()->headers->has('Content-Type') )
                {
                    $this->response()->headers->set('Content-Type', 'application/json');
                }
                $this->response()->setContent(false === $data ? 'false' : json_encode( $data ));
                break;

            case 'file':
                $file = $data;
                if ( !$this->response()->headers->has('Content-Type') )
                {
                    $file_type = mime_content_type( $file );
                    if ( empty($file_type) ) $file_type = 'application/octet-stream';
                    $this->response()->headers->set('Content-Type', $file_type);
                }
                //$this->response->headers->set('Content-Length', filesize( $file ));
                $this->response()->setFile($file);
                if ( $headers && isset($headers['deleteFileAfterSend']) )
                {
                    $this->response()->deleteFileAfterSend($headers['deleteFileAfterSend']);
                    unset($headers['deleteFileAfterSend']);
                }
                break;

            default:
                if ( !$this->response()->headers->has('Content-Type') )
                {
                    $this->response()->headers->set('Content-Type', 'text/html');
                }
                $this->response()->setContent($this->tpl($type, $data));
                break;
        }
        if ( !empty($headers) )
        {
            foreach ((array)$headers as $key=>$value)
            {
                if ( 'charset' === strtolower($key) )
                {
                    $this->response()->setCharset($value);
                }
                elseif ( 'statuscode' === strtolower($key) )
                {
                    $this->response()->setStatusCode((int)$value);
                }
                elseif ( 'cache-control' === strtolower($key) )
                {
                    foreach((array)$value as $v)
                    {
                        $v = strtolower($v);
                        if ( 'public' === $v )
                            $this->response()->setPublic();
                        elseif ( 'private' === $v )
                            $this->response()->setPrivate();
                        else
                            $this->response()->headers->addCacheControlDirective($v);
                    }
                }
                else
                {
                    $this->response()->headers->set($key, $value);
                }
            }
        }
        return $this;
    }

    public function redirect( $uri, $code=302 )
    {
        $this->response()->setTargetUrl($uri, $code);
        return $this;
    }

    public function enqueue( $type, $id, $asset_def=array() )
    {
        $this->loader()->enqueue( $type, $id, (array)$asset_def );
        return $this;
    }

    public function assets( $type="scripts" )
    {
        return $this->loader()->assets( $type );
    }

    public function path( )
    {
        return $this->BasePath . DIRECTORY_SEPARATOR . ltrim(implode('', func_get_args( )), '/\\');
    }

    public function uri( )
    {
        return $this->BaseUrl . '/' . ltrim(implode('', func_get_args( )), '/');
    }

    public function route( $route, $params=array(), $strict=false )
    {
        return $this->uri($this->router()->make($route, $params, $strict));
    }

    public function locale( $l, $lang )
    {
        if ( !empty($lang) )
        {
            $lang = (string)$lang;
            if ( is_callable($l) )
            {
                $this->LanguagePluralForm[$lang] = $l;
            }
            else if ( !empty($l) )
            {
                if ( !isset($this->Language[$lang]) ) $this->Language[$lang] = array();
                $this->Language[$lang] = array_merge($this->Language[$lang], (array)$l);
            }
            $this->Locale = $lang;
        }
        return $this;
    }

    public function l( $s, $args=null )
    {
        // localisation
        $locale = $this->Locale;
        $ls = $locale && isset($this->Language[$locale]) && isset($this->Language[$locale][$s]) ? $this->Language[$locale][$s] : $s;
        if ( !empty($args) ) $ls = vsprintf($ls, (array)$args);
        return $ls;
    }

    public function pl( $n )
    {
        // custom plural form per locale
        $locale = $this->Locale;
        $isSingular = $locale && isset($this->LanguagePluralForm[$locale]) && is_callable($this->LanguagePluralForm[$locale]) ? (bool)call_user_func($this->LanguagePluralForm[$locale], $n) : (1 == $n);
        return $isSingular;
    }

    public function nl( $n, $singular, $plural, $args=null )
    {
        // singular/plural localisation
        return $this->l($this->pl($n) ? $singular : $plural, $args);
    }

    public function isSsl()
    {
        return (!empty($_SERVER['HTTPS']) && 'off' !== strtolower($_SERVER['HTTPS'])) || (isset($_SERVER['SERVER_PORT']) && ('443' == $_SERVER['SERVER_PORT'])) ? true : false;
    }

    public function currentUrl( $withquery=false )
    {
        static $current_url = null;
        static $current_url_qs = null;
        if ( null === $current_url )
        {
            $query = !empty($_SERVER['QUERY_STRING']) ? '?'.$_SERVER['QUERY_STRING'] : '';
            $pageURL = ($this->isSsl() ? 'https' : 'http') . '://';
            if ( '80' != $_SERVER["SERVER_PORT"] )
            {
                $pageURL .= $_SERVER["SERVER_NAME"].":".$_SERVER["SERVER_PORT"].$_SERVER["REQUEST_URI"];
            }
            else
            {
                $pageURL .= $_SERVER["SERVER_NAME"].$_SERVER["REQUEST_URI"];
            }
            if ( false !== ($p=strpos($pageURL,'?')) )
            {
                $current_url_qs = $pageURL;
                $current_url = substr($pageURL, 0, $p);
            }
            elseif ( !empty($query) )
            {
                $current_url_qs = $pageURL.$query;
                $current_url = $pageURL;
            }
            else
            {
                $current_url_qs = $pageURL;
                $current_url = $pageURL;
            }
        }
        return $withquery ? $current_url_qs : $current_url;
    }

    public function requestPath( $strip=false )
    {
        $request_uri = isset($_SERVER['REQUEST_URI']) ? strtok(strtok($_SERVER["REQUEST_URI"],'?'), '#') : '';

        if ( $strip && false !== ($p=strpos($this->BaseUrl, '/')) )
        {
            $base_uri = substr($this->BaseUrl, $p);
            if ( 0 === strpos($request_uri, $base_uri) )
            {
                $request_uri = substr($request_uri, strlen($base_uri));
            }
        }
        // remove trailing slash
        if ( '/' === substr($request_uri, -1) )
            $request_uri = substr($request_uri, 0, -1);

        return $request_uri;
    }

    public function requestMethod( $allow_overide=false, $default='GET' )
    {
        $method = strtoupper(isset($_SERVER['REQUEST_METHOD']) ? $_SERVER['REQUEST_METHOD'] : $default);
        if ( !empty($allow_overide) )
        {
            $key = true === $allow_overide ? 'request_method' : (string)$allow_overide;
            if ( 'POST'===$method && !empty($_POST[$key]) )
                $method = strtoupper($_POST[$key]);
            elseif ( 'GET'===$method && !empty($_GET[$key]) )
                $method = strtoupper($_GET[$key]);
        }
        return $method;
    }

    public function on( $route, $handler )
    {
        if ( false === $route )
        {
            $this->router( )->fallback(function($route) use($handler) {
                return call_user_func($handler, false);
            });
        }
        else
        {
            if ( is_string($route) )
            {
                $route = array(
                    'route'     => $route,
                    'name'      => $route,
                    'method'    => '*', // optional, * = any
                    'defaults'  => array()
                );
            }
            $route = (array)$route;
            if ( empty($route['name']) )
                $route['name'] = $route['route'];
            if ( !is_callable($handler) && isset($route['handler']) && is_callable($route['handler']) )
                $handler = $route['handler'];
            $route['handler'] = function($route) use($handler) {
                return call_user_func($handler, $route['data']);
            };
            $this->router( )->on( $route );
        }
        return $this;
    }

    public function get( $route, $handler )
    {
        return $this->on(array(
            'route' => $route,
            'method' => 'get'
        ), $handler);
    }

    public function post( $route, $handler )
    {
        return $this->on(array(
            'route' => $route,
            'method' => 'post'
        ), $handler);
    }

    public function serve( )
    {
        $this->_fixServerVars( );
        $this->router( )->route( $this->requestPath( true ), $this->requestMethod( ) );
        $this->response( )->send( );
    }
}
function tico( $baseUrl='', $basePath='' )
{
    static $app = null;
    if ( !$app )
    {
        $app = new Tico($baseUrl, $basePath);
    }
    return $app;
}