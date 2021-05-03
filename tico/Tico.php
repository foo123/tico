<?php
/**
*
* Tiny, super-simple but versatile quasi-MVC web framework for PHP
* @version 1.8.0
* https://github.com/foo123/tico
*
*/

if (! defined('TICO')) define('TICO', dirname(__FILE__));
class Tico
{
    const VERSION = '1.8.0';

    public $Loader = null;
    public $Router = null;
    public $Request = null;
    public $Response = null;

    public $BaseUrl = '';
    public $BasePath = '';

    public $LanguagePluralForm = array();
    public $Language = array();
    public $Locale = null;

    public $Option = array();
    public $Data = array();
    public $Middleware = null;
    public $SubdomainsPorts = array();
    private $_onSubdomainPort = null;

    public function __construct($baseUrl = '', $basePath = '')
    {
        $this->BaseUrl = rtrim($baseUrl, '/');
        $this->BasePath = rtrim($basePath, '/\\');
        $this->Middleware = (object)array('before'=>array(), 'after'=>array());

        // set some default options
        $this->option('webroot', $this->BasePath);
        $this->option('views', array(''));
        $this->option('case_insensitive_uris', true);
    }

    protected function _fixServerVars()
    {
        $default_server_values = array(
            'SERVER_SOFTWARE' => '',
            'REQUEST_URI' => '',
        );

        $_SERVER = array_merge($default_server_values, $_SERVER);

        // Fix for IIS when running with PHP ISAPI
        if (empty($_SERVER['REQUEST_URI']) || (PHP_SAPI != 'cgi-fcgi' && preg_match('/^Microsoft-IIS\//', $_SERVER['SERVER_SOFTWARE'])))
        {
            // IIS Mod-Rewrite
            if (isset($_SERVER['HTTP_X_ORIGINAL_URL']))
            {
                $_SERVER['REQUEST_URI'] = $_SERVER['HTTP_X_ORIGINAL_URL'];
            }
            // IIS Isapi_Rewrite
            elseif (isset($_SERVER['HTTP_X_REWRITE_URL']))
            {
                $_SERVER['REQUEST_URI'] = $_SERVER['HTTP_X_REWRITE_URL'];
            }
            else
            {
                // Use ORIG_PATH_INFO if there is no PATH_INFO
                if (! isset($_SERVER['PATH_INFO']) && isset($_SERVER['ORIG_PATH_INFO']))
                    $_SERVER['PATH_INFO'] = $_SERVER['ORIG_PATH_INFO'];

                // Some IIS + PHP configurations puts the script-name in the path-info (No need to append it twice)
                if (isset($_SERVER['PATH_INFO']))
                {
                    if ($_SERVER['PATH_INFO'] == $_SERVER['SCRIPT_NAME'])
                        $_SERVER['REQUEST_URI'] = $_SERVER['PATH_INFO'];
                    else
                        $_SERVER['REQUEST_URI'] = $_SERVER['SCRIPT_NAME'] . $_SERVER['PATH_INFO'];
                }

                // Append the query string if it exists and isn't null
                if (! empty($_SERVER['QUERY_STRING']))
                {
                    $_SERVER['REQUEST_URI'] .= '?' . $_SERVER['QUERY_STRING'];
                }
            }
        }

        // Fix for PHP as CGI hosts that set SCRIPT_FILENAME to something ending in php.cgi for all requests
        if (isset($_SERVER['SCRIPT_FILENAME']) && (strpos($_SERVER['SCRIPT_FILENAME'], 'php.cgi') == strlen($_SERVER['SCRIPT_FILENAME']) - 7))
            $_SERVER['SCRIPT_FILENAME'] = $_SERVER['PATH_TRANSLATED'];

        // Fix for Dreamhost and other PHP as CGI hosts
        if (strpos($_SERVER['SCRIPT_NAME'], 'php.cgi') !== false)
            unset($_SERVER['PATH_INFO']);

        // Fix empty PHP_SELF
        if (empty($_SERVER['PHP_SELF']))
            $_SERVER['PHP_SELF'] = preg_replace('/(\?.*)?$/', '', $_SERVER["REQUEST_URI"]);
    }

    public function env($key, $default = null, $registry = 'ANY')
    {
        $registry = explode('|', strtoupper($registry));
        $search_all = in_array('ANY', $registry);

        $val = $default;

        if (($search_all || in_array('CONSTANTS', $registry)) && defined($key))
        {
            $val = constant($key);
        }
        elseif (($search_all || in_array('SERVER', $registry)) && isset($_SERVER[$key]))
        {
            $val = $_SERVER[$key];
        }
        elseif (($search_all || in_array('ENV', $registry)) && isset($_ENV[$key]))
        {
            $val = $_ENV[$key];
        }
        elseif (($search_all || in_array('ENV', $registry)) && false !== getenv($key))
        {
            $val = getenv($key);
        }
        elseif (($search_all || in_array('INI', $registry)) && false !== ini_get($key))
        {
            $val = ini_get($key);
        }

        return $val;
    }

    public function option($key)
    {
        $args = func_get_args();
        if (1 < count($args))
        {
            $this->Option[$key] = $args[1];
            return $this;
        }
        return isset($this->Option[$key]) ? $this->Option[$key] : null;
    }

    public function get($key)
    {
        $key = (string)$key;
        if (! isset($this->Data[$key]))
            throw new InvalidArgumentException('"'.$key.'" is not set!');


        $val = $this->Data[$key];
        // lazy factory getter, execute only once and return whatever it returns
        if (is_callable($val) && (!is_object($val) || ($val instanceof Closure))) $this->Data[$key] = $val = call_user_func($val);

        return $val;
    }

    public function set($key, $val)
    {
        $this->Data[(string)$key] = $val;
        return $this;
    }

    public function loader()
    {
        if ($this->Loader) return $this->Loader;
        if (! class_exists('Importer', false)) include(TICO . '/Importer.php');
        $this->Loader = new Importer($this->BasePath, $this->BaseUrl);
        return $this->Loader;
    }

    public function router($new = false)
    {
        if (true === $new)
        {
            if (! class_exists('Dromeo', false)) include(TICO . '/Dromeo.php');
            return new Dromeo();
        }
        else
        {
            if ($this->Router) return $this->Router;
            if (! class_exists('Dromeo', false)) include(TICO . '/Dromeo.php');
            $this->Router = new Dromeo();
            return $this->Router;
        }
    }

    public function request(/*$req*/)
    {
        $args = func_get_args();
        if (0 < count($args))
        {
            $req = $args[0];
            if (! class_exists('HttpRequest', false)) include(TICO . '/HttpFoundation.php');
            if ($req instanceof HttpRequest) $this->Request = $req;
            return $this;
        }
        else
        {
            if ($this->Request) return $this->Request;
            if (! class_exists('HttpRequest', false)) include(TICO . '/HttpFoundation.php');
            $this->Request = HttpRequest::createFromGlobals();
            return $this->Request;
        }
    }

    public function response(/*$res*/)
    {
        $args = func_get_args();
        if (0 < count($args))
        {
            $res = $args[0];
            if (! class_exists('HttpResponse', false)) include(TICO . '/HttpFoundation.php');
            if ($res instanceof HttpResponse) $this->Response = $res;
            return $this;
        }
        else
        {
            if ($this->Response) return $this->Response;
            if (! class_exists('HttpResponse', false)) include(TICO . '/HttpFoundation.php');
            $this->Response = new HttpResponse();
            return $this->Response;
        }
    }

    public function tpl($tpl, $data = array())
    {
        if (! class_exists('InTpl', false)) include(TICO . '/InTpl.php');
        return InTpl::Tpl($tpl, (array)$this->option('views'))->render($data);
    }

    public function output($data, $type = 'html', $headers = array())
    {
        $type = empty($type) ? 'html' : $type;
        switch($type)
        {
            case 'pre':
                if (is_array($data) || is_object($data)) $data = print_r($data, true);
                $data = '<pre>' . str_replace(array('&','<','>'), array('&amp;','&lt;','&gt;'), (string)$data) . '</pre>';
                // no break

            case 'html':
                if (! $this->response()->headers->has('Content-Type'))
                {
                    $this->response()->headers->set('Content-Type', 'text/html');
                }
                // no break

            case 'text':
                if (! $this->response()->headers->has('Content-Type'))
                {
                    $this->response()->headers->set('Content-Type', 'text/plain');
                }
                if (is_callable($data))
                    $this->response()->setCallback($data);
                else
                    $this->response()->setContent((string)$data);
                break;

            case 'json':
                if (! $this->response()->headers->has('Content-Type'))
                {
                    $this->response()->headers->set('Content-Type', 'application/json');
                }
                if (is_callable($data))
                    $this->response()->setCallback($data);
                else
                    $this->response()->setContent(json_encode($data));
                break;

            case 'file':
                $file = $data;
                if (! $this->response()->headers->has('Content-Type'))
                {
                    $file_type = mime_content_type($file);
                    if (empty($file_type)) $file_type = 'application/octet-stream';
                    $this->response()->headers->set('Content-Type', $file_type);
                }
                //$this->response->headers->set('Content-Length', filesize($file));
                $this->response()->setFile($file);
                if ($headers && isset($headers['deleteFileAfterSend']))
                {
                    $this->response()->deleteFileAfterSend($headers['deleteFileAfterSend']);
                    unset($headers['deleteFileAfterSend']);
                }
                break;

            default:
                if (! $this->response()->headers->has('Content-Type'))
                {
                    $this->response()->headers->set('Content-Type', 'text/html');
                }
                if (is_callable($data))
                    $this->response()->setCallback($data);
                else
                    $this->response()->setContent($this->tpl($type, $data));
                break;
        }
        if (! empty($headers))
        {
            foreach ((array)$headers as $key => $value)
            {
                $keyl = strtolower($key);
                if ('charset' === $keyl)
                {
                    $this->response()->setCharset($value);
                }
                elseif ('statuscode' === $keyl)
                {
                    $this->response()->setStatusCode((int)$value);
                }
                elseif ('cache-control' === $keyl)
                {
                    foreach ((array)$value as $v)
                    {
                        $v = strtolower($v);
                        if ('public' === $v)
                            $this->response()->setPublic();
                        elseif ('private' === $v)
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

    public function redirect($uri, $code = 302)
    {
        $this->response()->setTargetUrl($uri, $code);
        return $this;
    }

    public function enqueue($type, $id, $asset_def = array())
    {
        $this->loader()->enqueue($type, $id, (array)$asset_def);
        return $this;
    }

    public function assets($type = "scripts")
    {
        return $this->loader()->assets($type);
    }

    public function autoload($what)
    {
        foreach($what as $type => $items)
            $this->loader()->register($type, $items);
        $this->loader()->register_autoload();
        return $this;
    }

    public function path()
    {
        $path = ltrim(implode('', func_get_args( )), '/\\');
        return $this->BasePath . (strlen($path) ? (DIRECTORY_SEPARATOR . $path) : '');
    }

    public function webroot()
    {
        $webroot = $this->option('webroot');
        if (! $webroot) $webroot = $this->BasePath;
        $path = ltrim(implode('', func_get_args( )), '/\\');
        return rtrim($webroot, '/\\') . (strlen($path) ? (DIRECTORY_SEPARATOR . $path) : '');
    }

    public function uri2()
    {
        $args = func_get_args();
        $params = array_shift($args);
        $subdomain = '';
        $port = '';
        if (is_string($params))
        {
            if (':' === substr($params, 0, 1))
                $port = substr($params, 1);
            else
                $subdomain = $params;
        }
        elseif (is_numeric($params))
        {
            $port = (string)$params;
        }
        elseif (is_array($params))
        {
            $subdomain = isset($params['subdomain']) ? (string)$params['subdomain'] : '';
            $port = isset($params['port']) ? (string)$params['port'] : '';
        }
        if ('' === $subdomain && '' === $port) return call_user_func_array(array($this, 'uri'), $args);
        list($scheme, $host, $port0, $path) = $this->_parseUrl($this->BaseUrl, '');
        if (strlen($subdomain)) $host = $subdomain . '.' . $host;
        if ('' === $port) $port = $port0;
        $uri = ltrim(implode('', $args), '/');
        return (false === strpos($uri, '://', 0) ? ($scheme . '://' . $host . (strlen($port) ? (':' . $port) : '') . $path . (strlen($uri) ? '/' : '')) : '') . $uri;
    }

    public function uri()
    {
        $uri = ltrim(implode('', func_get_args( )), '/');
        return (false === strpos($uri, '://', 0) ? ($this->BaseUrl . (strlen($uri) ? '/' : '')) : '') . $uri;
    }

    public function route($route, $params = array(), $strict = false, $subdomainPort = false)
    {
        if (false !== $subdomainPort && isset($this->SubdomainsPorts[$subdomainPort]))
        {
            return $this->uri2($subdomainPort, $this->Subdomains[$subdomainPort]->make($route, $params, $strict));
        }
        else
        {
            return $this->uri($this->router()->make($route, $params, $strict));
        }
    }

    public function locale($l, $lang)
    {
        if (! empty($lang))
        {
            $lang = (string)$lang;
            if (is_callable($l))
            {
                $this->LanguagePluralForm[$lang] = $l;
            }
            else if (! empty($l))
            {
                if (! isset($this->Language[$lang])) $this->Language[$lang] = array();
                $this->Language[$lang] = array_merge($this->Language[$lang], (array)$l);
            }
            $this->Locale = $lang;
        }
        return $this;
    }

    public function l($s, $args = null)
    {
        // localisation
        $locale = $this->Locale;
        $ls = $locale && isset($this->Language[$locale]) && isset($this->Language[$locale][$s]) ? $this->Language[$locale][$s] : $s;
        if (! empty($args)) $ls = vsprintf($ls, (array)$args);
        return $ls;
    }

    public function pl($n)
    {
        // custom plural form per locale
        $locale = $this->Locale;
        $isSingular = $locale && isset($this->LanguagePluralForm[$locale]) && is_callable($this->LanguagePluralForm[$locale]) ? (bool)call_user_func($this->LanguagePluralForm[$locale], $n) : (1 == $n);
        return $isSingular;
    }

    public function nl($n, $singular, $plural, $args = null)
    {
        // singular/plural localisation
        return $this->l($this->pl($n) ? $singular : $plural, $args);
    }

    public function isSsl()
    {
        return $this->request()->isSecure()/*(! empty($_SERVER['HTTPS']) && 'off' !== strtolower($_SERVER['HTTPS'])) || (isset($_SERVER['SERVER_PORT']) && ('443' == $_SERVER['SERVER_PORT'])) ? true : false*/;
    }

    public function currentUrl($withquery = false)
    {
        static $current_url = null;
        static $current_url_qs = null;
        if (null === $current_url)
        {
            $current_url = rtrim($this->request()->getUri(false), '/');
            $current_url_qs = rtrim(str_replace('/?', '?', $this->request()->getUri(true)), '/');
            /*$query = !empty($_SERVER['QUERY_STRING']) ? '?'.$_SERVER['QUERY_STRING'] : '';
            $pageURL = ($this->isSsl() ? 'https' : 'http') . '://';
            if (('80' != $_SERVER["SERVER_PORT"]) && ! ($this->isSsl() && '443' == $_SERVER["SERVER_PORT"]))
            {
                $pageURL .= $_SERVER["SERVER_NAME"] . ":" . $_SERVER["SERVER_PORT"] . $_SERVER["REQUEST_URI"];
            }
            else
            {
                $pageURL .= $_SERVER["SERVER_NAME"] . $_SERVER["REQUEST_URI"];
            }
            if (false !== ($p=strpos($pageURL,'?')))
            {
                $current_url_qs = $pageURL;
                $current_url = substr($pageURL, 0, $p);
            }
            elseif (! empty($query))
            {
                $current_url_qs = $pageURL . $query;
                $current_url = $pageURL;
            }
            else
            {
                $current_url_qs = $pageURL;
                $current_url = $pageURL;
            }*/
        }
        return $withquery ? $current_url_qs : $current_url;
    }

    private function _parseUrl($baseUrl, $defaultPath = '', $caseInsensitive = false)
    {
        /*if (false !== ($p=strpos(str_replace('://', ':%%', $baseUrl), '/')))
        {
            $domain = substr($baseUrl, 0, $p);
            $path = trim(substr($baseUrl, $p));
        }
        else
        {
            $domain = $baseUrl;
            $path = '';
        }
        if (false !== ($p=strpos($domain, '://')))
        {
            $scheme = substr($domain, 0, $p+3);
            $domain = substr($domain, $p+3);
        }
        else
        {
            $scheme = 'http://';
        }*/
        $parts = parse_url($baseUrl);
        $scheme = isset($parts['scheme']) ? $parts['scheme'] : 'http';
        $host = isset($parts['host']) ? $parts['host'] : '';
        $port = (string)(isset($parts['port']) ? $parts['port'] : '');
        $path = isset($parts['path']) ? $parts['path'] : '';
        if (! strlen($path)) $path = $defaultPath;
        if ($caseInsensitive)
        {
            $scheme = strtolower($scheme);
            $host = strtolower($host);
            $path = strtolower($path);
        }
        return array($scheme, $host, $port, $path);
    }

    public function requestPort()
    {
        return (string)$this->request()->getPort(); // $_SERVER['SERVER_PORT'];
    }

    public function requestSubdomain($caseInsensitive = true)
    {
        $currentHost = $this->request()->headers->get('HOST'); // $_SERVER['HTTP_HOST'];
        list($scheme, $host, $port, $path) = $this->_parseUrl($this->BaseUrl, '', $caseInsensitive);
        $subdomain = trim(preg_replace('#\.' . preg_quote($host, '#') . '$#i', '', $currentHost));
        if ($subdomain === $currentHost) $subdomain = '';
        if ($caseInsensitive) $subdomain = strtolower($subdomain);
        return $subdomain;
    }

    public function requestPath($strip = true, $caseInsensitive = true)
    {
        $request_uri = /*isset($_SERVER['REQUEST_URI']) ? */strtok(strtok($this->request()->getRequestUri(), '?'), '#')/* : ''*/;

        if ($strip)
        {
            list($scheme, $host, $port, $base_uri) = $this->_parseUrl($this->BaseUrl, '');
            if (strlen($base_uri) && (0 === strpos(strtolower($request_uri), strtolower($base_uri))))
                $request_uri = substr($request_uri, strlen($base_uri));
        }
        // remove trailing slash
        if ('/' === substr($request_uri, -1))
            $request_uri = substr($request_uri, 0, -1);
        // make sure root is / (and not empty string)
        if ('' === $request_uri)
            $request_uri = '/';

        if ($caseInsensitive) $request_uri = strtolower($request_uri);
        return $request_uri;
    }

    public function requestMethod($allow_overide = false, $default = 'GET')
    {
        $this->request();
        if (! empty($allow_overide))
            HttpRequest::enableHttpMethodParameterOverride();
        $method = $this->request()->getMethod($default);
        /*$method = strtoupper(isset($_SERVER['REQUEST_METHOD']) ? $_SERVER['REQUEST_METHOD'] : $default);
        if (! empty($allow_overide))
        {
            $key = true === $allow_overide ? '_method' : (string)$allow_overide;
            if ('POST' === $method && ! empty($_POST[$key]))
                $method = strtoupper($_POST[$key]);
            elseif ('GET' === $method && ! empty($_GET[$key]))
                $method = strtoupper($_GET[$key]);
        }*/
        return $method;
    }

    public function middleware($middleware, $type = 'before')
    {
        if (is_callable($middleware))
        {
            $type = 'after' === strtolower((string)$type) ? 'after' : 'before';
            $this->Middleware->{$type}[] = $middleware;
        }
        return $this;
    }

    public function on($method, $route, $handler = null)
    {
        $router = $this->_onSubdomainPort ? $this->SubdomainsPorts[$this->_onSubdomainPort] : $this->router();
        if (false === $method)
        {
            $handler = $route;
            $router->fallback(function($route) use ($handler) {
                return call_user_func($handler, false);
            });
        }
        else
        {
            if (is_string($route)) $route = array('route' => $route);
            $route = (array)$route;
            $route['method'] = $method;
            if (! isset($route['name']))
                $route['name'] = $route['route'];
            if (! is_callable($handler) && isset($route['handler']) && is_callable($route['handler']))
                $handler = $route['handler'];
            $route['handler'] = function($route) use ($handler) {
                return call_user_func($handler, $route['data']);
            };
            $router->on($route);
        }
        return $this;
    }

    public function onPort($port)
    {
        if (false === $port)
        {
            $this->_onSubdomainPort = null;
        }
        else
        {
            $this->_onSubdomainPort = ':' . (string)$port;
            if (! isset($this->SubdomainsPorts[$this->_onSubdomainPort]))
                $this->SubdomainsPorts[$this->_onSubdomainPort] = $this->router(true);
        }
        return $this;
    }

    public function onSubdomain($subdomain)
    {
        if (false === $subdomain)
        {
            $this->_onSubdomainPort = null;
        }
        else
        {
            $this->_onSubdomainPort = (string)$subdomain;
            if (! isset($this->SubdomainsPorts[$this->_onSubdomainPort]))
                $this->SubdomainsPorts[$this->_onSubdomainPort] = $this->router(true);
        }
        return $this;
    }

    public function serve()
    {
        $this->_fixServerVars();

        $this->request();

        $passed = true;

        if (! empty($this->Middleware->before))
        {
            $passed = false;
            $next1 = function( ) use (&$next1, &$passed) {
                static $i = -1;
                $i++;
                if ($i >= count($this->Middleware->before)) $passed = true;
                else call_user_func($this->Middleware->before[$i], $next1);
            };
            call_user_func($next1);
        }

        if ($passed)
        {
            $requestPort = ':' . $this->requestPort();
            $requestSubdomain = $this->requestSubdomain($this->option('case_insensitive_uris'));
            $requestPath = $this->requestPath(true, $this->option('case_insensitive_uris'));
            $requestMethod = $this->requestMethod();

            if (1 < strlen($requestPort) && isset($this->SubdomainsPorts[$requestPort]))
            {
                $this->SubdomainsPorts[$requestPort]->route($requestPath, $requestMethod);
            }
            elseif (strlen($requestSubdomain) && isset($this->SubdomainsPorts[$requestSubdomain]))
            {
                $this->SubdomainsPorts[$requestSubdomain]->route($requestPath, $requestMethod);
            }
            elseif (isset($this->SubdomainsPorts[':*'])) // any port
            {
                $this->SubdomainsPorts[':*']->route($requestPath, $requestMethod);
            }
            elseif (isset($this->SubdomainsPorts['*'])) // any subdomain
            {
                $this->SubdomainsPorts['*']->route($requestPath, $requestMethod);
            }
            else // main domain/port
            {
                $this->router()->route($requestPath, $requestMethod);
            }
        }

        if (! empty($this->Middleware->after))
        {
            $next2 = function( ) use (&$next2) {
                static $i = -1;
                $i++;
                if ($i < count($this->Middleware->after)) call_user_func($this->Middleware->after[$i], $next2);
            };
            call_user_func($next2);
        }

        $this->response()->prepare($this->request())->send();
    }
}
function tico($baseUrl = '', $basePath = '')
{
    static $app = null;
    if (! $app) $app = $baseUrl instanceof Tico ? $baseUrl : new Tico($baseUrl, $basePath);
    return $app;
}