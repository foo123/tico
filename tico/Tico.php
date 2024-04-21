<?php
/**
*
* Tiny, super-simple but versatile quasi-MVC web framework for PHP
* @version 1.15.0
* https://github.com/foo123/tico
*
*/

if (!class_exists('Tico', false))
{
define('TICO', dirname(__FILE__));

class TicoValue
{
    private $v = null;
    private $isLoaded = false;

    public function __construct($value, $asIs = false)
    {
        $this->v = $value;
        $this->isLoaded = (bool)$asIs;
    }

    public function value()
    {
        if (!$this->isLoaded)
        {
            $this->isLoaded = true;
            // lazy factory getter, execute only once and return whatever it returns
            if (is_callable($this->v) && (!is_object($this->v) || ($this->v instanceof Closure)))
            {
                $this->v = @call_user_func($this->v);
            }
        }
        return $this->v;
    }
}

class Tico
{
    const VERSION = '1.15.0';

    public $Loader = null;
    public $Router = null;
    public $Request = null;
    public $Response = null;

    public $BaseUrl = '';
    public $BasePath = '';

    public $Option = array();
    public $Data = array();
    public $Variable = array();
    public $Middleware = null;
    public $SubdomainsPorts = array();

    private $_onSubdomainPort = null;
    private $_fixed = false;

    public function __construct($baseUrl = '', $basePath = '')
    {
        $this->BaseUrl = rtrim($baseUrl, '/');
        $this->BasePath = rtrim($basePath, '/\\');
        $this->Middleware = (object)array(
            'before' => array(),
            'after' => array()
        );

        // set some default options
        $this->option('webroot', $this->BasePath);
        $this->option('case_insensitive_uris', true);
        $this->option('views', array(''));

        $this->variable('cache', empty($_GET) && empty($_POST)); // page w/ request params not cached
    }

    protected function _fixServerVars()
    {
        if (!$this->_fixed)
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
                    if (!isset($_SERVER['PATH_INFO']) && isset($_SERVER['ORIG_PATH_INFO']))
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
                    if (!empty($_SERVER['QUERY_STRING']))
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

            $this->_fixed = true;
        }
    }

    public function args($argv = null)
    {
        $argv = $argv ? $argv : $_SERVER['argv'];
        array_shift($argv); $o = array();

        for ($i=0,$j=count($argv); $i<$j; ++$i)
        {
            $a = $argv[$i];

            if (substr($a, 0, 2) === '--')
            {
                $eq = strpos($a, '=');
                if ($eq !== false)
                {
                    $o[substr($a, 2, $eq - 2)] = substr($a, $eq + 1);

                }
                else
                {
                    $k = substr($a, 2);
                    if ($i + 1 < $j && $argv[$i + 1][0] !== '-')
                    {
                        $o[$k] = $argv[$i + 1]; $i++;
                    }
                    elseif (!isset($o[$k]))
                    {
                        $o[$k] = true;
                    }
                }
            }
            elseif (substr($a, 0, 1) === '-')
            {
                if (substr($a, 2, 1) === '=')
                {
                    $o[substr($a, 1, 1)] = substr($a, 3);
                }
                else
                {
                    foreach (str_split(substr($a, 1)) as $k)
                    {
                        if (!isset($o[$k]))
                        {
                            $o[$k] = true;
                        }
                    }
                    if ($i + 1 < $j && $argv[$i + 1][0] !== '-')
                    {
                        $o[$k] = $argv[$i + 1]; $i++;
                    }
                }
            }
            else
            {
                $o[] = $a;
            }
        }
        return $o;
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

    public function variable($key)
    {
        $args = func_get_args();
        if (1 < count($args))
        {
            $this->Variable[$key] = $args[1];
            return $this;
        }
        return isset($this->Variable[$key]) ? $this->Variable[$key] : null;
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
        if (!isset($this->Data[$key]))
        {
            throw new InvalidArgumentException('Tico:"'.$key.'" is not set!');
        }
        return $this->Data[$key]->value();
    }

    public function set($key, $val, $as_is = false)
    {
        $this->Data[(string)$key] = new TicoValue($val, $as_is);
        return $this;
    }

    public function loader()
    {
        if ($this->Loader) return $this->Loader;
        if (!class_exists('Importer', false)) include(TICO . '/Importer.php');
        $this->Loader = new Importer($this->BasePath, $this->BaseUrl);
        return $this->Loader;
    }

    public function router($router = false)
    {
        if (true === $router)
        {
            if (!class_exists('Dromeo', false)) include(TICO . '/Dromeo.php');
            return new Dromeo();
        }
        elseif (is_string($router) && strlen($router))
        {
            return isset($this->SubdomainsPorts[$router]) ? $this->SubdomainsPorts[$router] : null;
        }
        else
        {
            if ($this->Router) return $this->Router;
            if (!class_exists('Dromeo', false)) include(TICO . '/Dromeo.php');
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
            if (!class_exists('HttpRequest', false)) include(TICO . '/HttpFoundation.php');
            if ($req instanceof HttpRequest) $this->Request = $req;
            return $this;
        }
        else
        {
            if ($this->Request) return $this->Request;
            if (!class_exists('HttpRequest', false)) include(TICO . '/HttpFoundation.php');
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
            if (!class_exists('HttpResponse', false)) include(TICO . '/HttpFoundation.php');
            if ($res instanceof HttpResponse) $this->Response = $res;
            return $this;
        }
        else
        {
            if ($this->Response) return $this->Response;
            if (!class_exists('HttpResponse', false)) include(TICO . '/HttpFoundation.php');
            $this->Response = new HttpResponse();
            return $this->Response;
        }
    }

    public function tpl($tpl, $data = array())
    {
        $tpl_render = $this->option('tpl_render');
        if (is_callable($tpl_render))
        {
            return @call_user_func($tpl_render, $tpl, $data, (array)$this->option('views'));
        }
        else
        {
            if (!class_exists('InTpl', false)) include(TICO . '/InTpl.php');
            return InTpl::Tpl($tpl, (array)$this->option('views'))->render($data);
        }
    }

    public function output($data, $type = 'html', $headers = array())
    {
        $type = empty($type) ? 'html' : $type;
        switch($type)
        {
            case 'html':
                if (!$this->response()->headers->has('Content-Type'))
                {
                    $this->response()->headers->set('Content-Type', 'text/html');
                }
                // no break

            case 'text':
                if (!$this->response()->headers->has('Content-Type'))
                {
                    $this->response()->headers->set('Content-Type', 'text/plain');
                }
                if (is_callable($data))
                    $this->response()->setCallback($data);
                else
                    $this->response()->setContent((string)$data);
                break;

            case 'json':
                if (!$this->response()->headers->has('Content-Type'))
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
                if (!$this->response()->headers->has('Content-Type'))
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
                $this->variable('cache', false); // files not cached
                break;

            default:
                if (!$this->response()->headers->has('Content-Type'))
                {
                    $this->response()->headers->set('Content-Type', 'text/html');
                }
                if (is_callable($data))
                    $this->response()->setCallback($data);
                else
                    $this->response()->setContent($this->tpl($type, $data));
                break;
        }
        if (!empty($headers))
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

    public function cached()
    {
        $response = $this->response();
        $content = (string)$response->getContent();
        return strlen($content) ? serialize(array(
            'protocol' => 'HTTP/'.$response->getProtocolVersion(),
            'time' => time(),
            'status' => $response->getStatusCode(),
            'status-text' => HttpResponse::$statusTexts[$response->getStatusCode()],
            'content-type' => $response->headers->get('Content-Type'),
            'content' => $content,
        )) : null;
    }

    public function _serveCached($cached)
    {
        if (is_string($cached))
        {
            try {
                $content = @unserialize($cached, array('allowed_classes'=>false));
            } catch(Exception $e) {
                $content = null;
            }
            if (!empty($content) && !empty($content['status']) && isset($content['content']))
            {
                header('Content-Type: '.$content['content-type'], false, $content['status']);
                header('Last-Modified: '.date('D, d M Y H:i:s', $content['time']).' GMT', false, $content['status']);
                header($content['protocol'].' '.$content['status'].' '.$content['status-text'], true, $content['status']);
                echo $content['content'];
                return true;
            }
        }
        return false;
    }

    public function redirect($uri, $code = 302)
    {
        $this->response()->setTargetUrl($uri, $code);
        $this->variable('cache', false); // redirects not cached
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
        {
            $this->loader()->register($type, $items);
        }
        $this->loader()->register_autoload();
        return $this;
    }

    public function path()
    {
        $path = ltrim(implode('', func_get_args()), '/\\');
        return $this->BasePath . (strlen($path) ? (DIRECTORY_SEPARATOR . $path) : '');
    }

    public function webroot()
    {
        $webroot = $this->option('webroot');
        if (!$webroot) $webroot = $this->BasePath;
        $path = ltrim(implode('', func_get_args()), '/\\');
        return rtrim($webroot, '/\\') . (strlen($path) ? (DIRECTORY_SEPARATOR . $path) : '');
    }

    public function uri2()
    {
        $args = func_get_args();
        $params = array_shift($args);
        $subdomain = '';
        $port = '';
        $locale = '';
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
            $locale = isset($params['locale']) ? (string)$params['locale'] : '';
        }
        if ('' === $subdomain && '' === $port && '' === $locale) return call_user_func_array(array($this, 'uri'), $args);
        list($scheme, $host, $port0, $path) = $this->parseUrl($this->BaseUrl, '');
        if (strlen($subdomain)) $host = $subdomain . '.' . $host;
        if ('' === $port) $port = $port0;
        $uri = ltrim(implode('', $args), '/');
        return (false === strpos($uri, '://', 0) ? ($scheme . '://' . $host . (strlen($port) ? (':' . $port) : '') . $path . (strlen($uri) ? '/' : '')) : '') . $uri;
    }

    public function uri()
    {
        $uri = ltrim(implode('', func_get_args()), '/');
        return (false === strpos($uri, '://', 0) ? ($this->BaseUrl . (strlen($uri) ? '/' : '')) : '') . $uri;
    }

    public function route($route, $params = array(), $strict = false, $subdomainPort = false)
    {
        if (is_string($subdomainPort) && isset($this->SubdomainsPorts[$subdomainPort]))
        {
            return $this->uri2($subdomainPort, $this->Subdomains[$subdomainPort]->make($route, $params, $strict));
        }
        else
        {
            return $this->uri($this->router()->make($route, $params, $strict));
        }
    }

    public function isSsl()
    {
        return $this->request()->isSecure();
    }

    public function isCli()
    {
        $sapi = php_sapi_name();
        return ('cli' === $sapi || 'phpdbg' === $sapi /*&& empty($_SERVER['REMOTE_ADDR'])*/);
    }

    public function currentUrl($withquery = false)
    {
        static $current_url = null;
        static $current_url_qs = null;
        if (null === $current_url)
        {
            $current_url = rtrim($this->request()->getUri(false), '/');
            $current_url_qs = rtrim(str_replace('/?', '?', $this->request()->getUri(true)), '/');
        }
        return $withquery ? $current_url_qs : $current_url;
    }

    private function parseUrl($baseUrl, $defaultPath = '', $caseInsensitive = false)
    {
        $parts = parse_url($baseUrl);
        $scheme = isset($parts['scheme']) ? $parts['scheme'] : 'http';
        $host = isset($parts['host']) ? $parts['host'] : '';
        $port = (string)(isset($parts['port']) ? $parts['port'] : '');
        $path = isset($parts['path']) ? $parts['path'] : '';
        if (!strlen($path)) $path = $defaultPath;
        if ($caseInsensitive)
        {
            $scheme = strtolower($scheme);
            $host = strtolower($host);
            $path = strtolower($path);
        }
        return array($scheme, $host, $port, $path);
    }

    public function requestPort($onlyIfSet = false)
    {
        return (string)$this->request()->getPort($onlyIfSet);
    }

    public function requestSubdomain($caseInsensitive = true)
    {
        $currentHost = $this->request()->headers->get('HOST');
        list($scheme, $host, $port, $path) = $this->parseUrl($this->BaseUrl, '', $caseInsensitive);
        $subdomain = trim(preg_replace('#\.' . preg_quote($host, '#') . '$#i', '', $currentHost));
        if ($subdomain === $currentHost) $subdomain = '';
        if ($caseInsensitive) $subdomain = strtolower($subdomain);
        return $subdomain;
    }

    public function requestPath($strip = true, $caseInsensitive = true)
    {
        $request_uri = strtok(strtok($this->request()->getRequestUri(), '?'), '#');

        if ($strip)
        {
            list($scheme, $host, $port, $base_uri) = $this->parseUrl($this->BaseUrl, '');
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
        if (!empty($allow_overide))
        {
            HttpRequest::enableHttpMethodParameterOverride();
        }
        $method = $this->request()->getMethod($default);
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
        $router = $this->router($this->_onSubdomainPort);
        if (false === $method)
        {
            $handler = $route;
            if (is_callable($handler) && $router->isTop())
            {
                $tico = $this;
                $router->fallback(function($route) use ($handler,$tico) {
                    $tico->variable('cache', false); // 404 not cached
                    return call_user_func($handler, false);
                });
            }
        }
        else
        {
            if (is_string($route))
            {
                $route = array('route' => $route);
            }
            $route = (array)$route;
            if (!is_callable($handler) && isset($route['handler']) && is_callable($route['handler']))
            {
                $handler = $route['handler'];
            }
            if (isset($route['route']) && is_callable($handler))
            {
                $route['method'] = $method;
                if (('/' === $route['route']) && !$router->isTop())
                {
                    $route['route'] = '';
                }
                if (!isset($route['name']))
                {
                    $route['name'] = $router->key . $route['route'];
                }
                $route['handler'] = function($route) use ($handler) {
                    return call_user_func($handler, $route['data']);
                };
                $router->on($route);
            }
        }
        return $this;
    }

    public function onGroup($groupRoute, $groupAssignment = null)
    {
        if (is_callable($groupAssignment))
        {
            $this->router($this->_onSubdomainPort)->onGroup((string)$groupRoute, function($subRouter) use ($groupAssignment) {
                $subdomainPort = $this->_onSubdomainPort;
                if ($subdomainPort)
                {
                    $currRouter = $this->SubdomainsPorts[$subdomainPort];
                    $this->SubdomainsPorts[$subdomainPort] = $subRouter;
                }
                else
                {
                    $currRouter = $this->Router;
                    $this->Router = $subRouter;
                }
                call_user_func($groupAssignment);
                if ($subdomainPort)
                {
                    $this->SubdomainsPorts[$subdomainPort] = $currRouter;
                }
                else
                {
                    $this->Router = $currRouter;
                }
            });
        }
        elseif (false === $groupRoute)
        {
            if ($this->_onSubdomainPort)
            {
                $this->SubdomainsPorts[$this->_onSubdomainPort] = $this->SubdomainsPorts[$this->_onSubdomainPort]->top();
            }
            elseif ($this->Router)
            {
                $this->Router = $this->Router->top();
            }
        }
        else
        {
            if ($this->_onSubdomainPort)
            {
                $this->SubdomainsPorts[$this->_onSubdomainPort] = $this->SubdomainsPorts[$this->_onSubdomainPort]->top();
            }
            elseif ($this->Router)
            {
                $this->Router = $this->Router->top();
            }
            $this->router($this->_onSubdomainPort)->onGroup((string)$groupRoute, function($subRouter) {
                if ($this->_onSubdomainPort)
                {
                    $this->SubdomainsPorts[$this->_onSubdomainPort] = $subRouter;
                }
                else
                {
                    $this->Router = $subRouter;
                }
            });
        }
        return $this;
    }

    public function onPort($port, $portAssignment = null)
    {
        if (is_callable($portAssignment))
        {
            $onSubdomainPort = $this->_onSubdomainPort;
            $this->_onSubdomainPort = ':' . (string)$port;
            if (!isset($this->SubdomainsPorts[$this->_onSubdomainPort]))
                $this->SubdomainsPorts[$this->_onSubdomainPort] = $this->router(true);
            call_user_func($portAssignment);
            $this->_onSubdomainPort = $onSubdomainPort;
        }
        elseif (false === $port)
        {
            if ($this->_onSubdomainPort)
            {
                $this->SubdomainsPorts[$this->_onSubdomainPort] = $this->SubdomainsPorts[$this->_onSubdomainPort]->top();
            }
            $this->_onSubdomainPort = null;
        }
        else
        {
            $this->_onSubdomainPort = ':' . (string)$port;
            if (!isset($this->SubdomainsPorts[$this->_onSubdomainPort]))
                $this->SubdomainsPorts[$this->_onSubdomainPort] = $this->router(true);
        }
        return $this;
    }

    public function onSubdomain($subdomain, $subdomainAssignment = null)
    {
        if (is_callable($subdomainAssignment))
        {
            $onSubdomainPort = $this->_onSubdomainPort;
            $this->_onSubdomainPort = (string)$subdomain;
            if (!isset($this->SubdomainsPorts[$this->_onSubdomainPort]))
                $this->SubdomainsPorts[$this->_onSubdomainPort] = $this->router(true);
            call_user_func($subdomainAssignment);
            $this->_onSubdomainPort = $onSubdomainPort;
        }
        elseif (false === $subdomain)
        {
            if ($this->_onSubdomainPort)
            {
                $this->SubdomainsPorts[$this->_onSubdomainPort] = $this->SubdomainsPorts[$this->_onSubdomainPort]->top();
            }
            $this->_onSubdomainPort = null;
        }
        else
        {
            $this->_onSubdomainPort = (string)$subdomain;
            if (!isset($this->SubdomainsPorts[$this->_onSubdomainPort]))
                $this->SubdomainsPorts[$this->_onSubdomainPort] = $this->router(true);
        }
        return $this;
    }

    public function serveCache()
    {
        if ($this->isCli()) return false;

        $this->_fixServerVars();

        // if cache enabled serve fast and early
        $cache = $this->get('cache');
        $cached = $cache && method_exists($cache, 'get') ? $cache->get($_SERVER['REQUEST_URI']) : null;
        if ($cached && $this->_serveCached($cached)) return true;
        return false;
    }

    public function serve()
    {
        if ($this->isCli()) return;

        $this->_fixServerVars();

        $this->request();

        $passed = true;

        if (!empty($this->Middleware->before))
        {
            $passed = false;
            $next1 = function() use (&$next1, &$passed) {
                static $i = -1;
                ++$i;
                if ($i >= count($this->Middleware->before)) $passed = true;
                else call_user_func($this->Middleware->before[$i], $next1);
            };
            call_user_func($next1);
        }

        if ($passed)
        {
            $caseInsensitiveUris = $this->option('case_insensitive_uris');
            $requestPortOrig = $this->requestPort(true);
            $requestPort = ':' . (null == $requestPortOrig ? '' : (string)$requestPortOrig);
            $requestSubdomain = $this->requestSubdomain($caseInsensitiveUris);
            $requestMethod = $this->requestMethod();
            $requestPathOrig = $this->requestPath(true, false);
            $requestPath = $caseInsensitiveUris ? strtolower($requestPathOrig) : $requestPathOrig;
            $originalParamsKey = $this->option('original_params_key'); // default null

            if ((1 < strlen($requestPort)) && isset($this->SubdomainsPorts[$requestPort]))
            {
                $this->SubdomainsPorts[$requestPort]->route($requestPath, $requestMethod, true, $requestPathOrig, $originalParamsKey);
            }
            elseif (strlen($requestSubdomain) && isset($this->SubdomainsPorts[$requestSubdomain]))
            {
                $this->SubdomainsPorts[$requestSubdomain]->route($requestPath, $requestMethod, true, $requestPathOrig, $originalParamsKey);
            }
            elseif ((1 < strlen($requestPort)) && isset($this->SubdomainsPorts[':*'])) // any port
            {
                $this->SubdomainsPorts[':*']->route($requestPath, $requestMethod, true, $requestPathOrig, $originalParamsKey);
            }
            elseif (strlen($requestSubdomain) && isset($this->SubdomainsPorts['*'])) // any subdomain
            {
                $this->SubdomainsPorts['*']->route($requestPath, $requestMethod, true, $requestPathOrig, $originalParamsKey);
            }
            else // main domain/port
            {
                $this->router()->route($requestPath, $requestMethod, true, $requestPathOrig, $originalParamsKey);
            }
        }

        if (!empty($this->Middleware->after))
        {
            $next2 = function() use (&$next2) {
                static $i = -1;
                ++$i;
                if ($i < count($this->Middleware->after)) call_user_func($this->Middleware->after[$i], $next2);
            };
            call_user_func($next2);
        }

        $this->response()->prepare($this->request());
        // if cache enabled for this page, cache it
        if ($this->variable('cache') && (($cache = $this->get('cache')) && method_exists($cache, 'set') ) && ($cached = $this->cached())) $cache->set($_SERVER['REQUEST_URI'], $cached);
        $this->response()->send();
    }
}
function tico($baseUrl = '', $basePath = '')
{
    static $tico = null;
    if (!$tico) $tico = $baseUrl instanceof Tico ? $baseUrl : new Tico($baseUrl, $basePath);
    return $tico;
}
}