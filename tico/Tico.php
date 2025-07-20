<?php
/**
*
* Tiny, super-simple but versatile quasi-MVC web framework for PHP
* @version 1.22.0
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
class TicoParams
{
    private $datao = null;
    private $datai = null;

    public function __construct($data = array(), $orig_key = null)
    {
        $this->datao = array();
        $this->datai = array();
        foreach ($data as $key => $val)
        {
            if ($key === $orig_key) continue;
            $this->datao[$key] = $val;
        }
        if (!empty($orig_key) && isset($data[$orig_key]))
        {
            foreach ((array)$data[$orig_key] as $key => $val)
            {
                if (!isset($this->datao[$key])) continue;
                $this->datai[$key] = $val;
            }
        }
    }

    public function get($key, $default = null, $original = false)
    {
        return $original ? (isset($this->datai[$key]) ? $this->datai[$key] : $default) : (isset($this->datao[$key]) ? $this->datao[$key] : $default);
    }
}
class Tico
{
    const VERSION = '1.22.0';

    public $Loader = null;
    public $Router = null;
    public $Request = null;
    public $Response = null;

    public $BaseUrl = '';
    public $BasePath = '';

    public $Option = array();
    public $Data = array();
    public $Variable = array();
    public $Hooks = array();
    public $Middleware = null;
    public $SubdomainsPorts = array();

    private $_onSubdomainPort = null;
    private $_k = null;

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
        $this->option('route_params_object', false);
        $this->option('views', array(''));

        $this->variable('cache', empty($_GET) && empty($_POST)); // page w/ request params not cached
    }

    protected function _fixServerVars()
    {
        if (is_null($this->_k))
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

            //$parts = explode('?', $_SERVER['REQUEST_URI']);
            $uri = '/' . trim(/*$parts[0]*/$_SERVER['REQUEST_URI'], '/');
            $port = isset($_SERVER['SERVER_PORT']) ? (':' . $_SERVER['SERVER_PORT']) : '';
            $host = isset($_SERVER['HTTP_HOST']) ? $_SERVER['HTTP_HOST'] : (isset($_SERVER['SERVER_NAME']) ? $_SERVER['SERVER_NAME'] : '');
            if (strlen($port) && ($port == substr($host, -strlen($port)))) $port = '';
            $this->_k = $host . $port . $uri;
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

    public function variable($key)
    {
        $args = func_get_args();
        if (1 < count($args))
        {
            $val = $args[1];
            /*if (is_null($val))
            {
                // unset
                if (isset($this->Variable[$key]))
                    unset($this->Variable[$key]);
            }
            else
            {*/
                $this->Variable[$key] = $val;
            /*}*/
            return $this;
        }
        return isset($this->Variable[$key]) ? $this->Variable[$key] : null;
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

    public function hook($hook/*, $handler = null, $priority = 0*/)
    {
        $args = func_get_args();
        $hook = (string)$hook;
        if (1 < count($args))
        {
            $handler = $args[1];
            $priority = isset($args[2]) ? $args[2] : 0;
            if (is_callable($handler))
            {
                if (false === $priority)
                {
                    // remove hook
                    if (!empty($this->Hooks[$hook]))
                    {
                        $hooks =& $this->Hooks[$hook];
                        for ($i=count($hooks)-1; $i>=0; --$i)
                        {
                            if ($handler === $hooks[$i][0]) array_splice($hooks, $i, 1);
                        }
                    }
                }
                else
                {
                    // insert hook
                    if (!isset($this->Hooks[$hook])) $this->Hooks[$hook] = array();
                    $this->Hooks[$hook][] = array($handler, ((int)$priority) || 0, count($this->Hooks[$hook]));
                }
            }
        }
        else
        {
            // run hook
            if (!empty($this->Hooks[$hook]))
            {
                $hooks = $this->Hooks[$hook]; // array copy
                // sort according to increasing priority
                usort($hooks, function($a, $b) {return $a[1] == $b[1] ? ($a[2]-$b[2]) : ($a[1]-$b[1]);});
                // handlers can use tico()->variable() to pass values between hooks (eg like filters)
                foreach ($hooks as $handler) @call_user_func($handler[0]);
            }
        }
        return $this;
    }

    public function httpfoundation()
    {
        static $_included = false;
        if (!$_included && (!class_exists('HttpRequest', false) || !class_exists('HttpResponse', false)))
        {
            $_included = true;
            include(TICO . '/HttpFoundation.php');
        }
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
        $this->httpfoundation();
        if (0 < count($args))
        {
            $req = $args[0];
            if ($req instanceof HttpRequest) $this->Request = $req;
            return $this;
        }
        else
        {
            if ($this->Request) return $this->Request;
            $this->variable('tico_request', null);
            $this->hook('tico_request');
            if (($req = $this->variable('tico_request')) && ($req instanceof HttpRequest))
            {
                $this->Request = $req;
                $this->variable('tico_request', null);
            }
            else
            {
                $this->Request = HttpRequest::createFromGlobals();
            }
            return $this->Request;
        }
    }

    public function response(/*$res*/)
    {
        $args = func_get_args();
        $this->httpfoundation();
        if (0 < count($args))
        {
            $res = $args[0];
            if ($res instanceof HttpResponse) $this->Response = $res;
            return $this;
        }
        else
        {
            if ($this->Response) return $this->Response;
            $this->variable('tico_response', null);
            $this->hook('tico_response');
            if (($res = $this->variable('tico_response')) && ($res instanceof HttpResponse))
            {
                $this->Response = $res;
                $this->variable('tico_response', null);
            }
            else
            {
                $this->Response = new HttpResponse();
            }
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
        $handler = $this->option('tico_output');
        if (is_callable($handler))
        {
            @call_user_func($handler, $data, $type, $headers);
            return $this;
        }
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
                {
                    $this->variable('tico_set_callback__type', $type);
                    $this->variable('tico_set_callback__callback', $data);
                    $this->hook('tico_set_callback');
                    $this->response()->setCallback($this->variable('tico_set_callback__callback'));
                    $this->variable('tico_set_callback__callback', null);
                    $this->variable('tico_set_callback__type', null);
                }
                else
                {
                    $this->variable('tico_set_content__type', $type);
                    $this->variable('tico_set_content__content', (string)$data);
                    $this->hook('tico_set_content');
                    $this->response()->setContent($this->variable('tico_set_content__content'));
                    $this->variable('tico_set_content__content', null);
                    $this->variable('tico_set_content__type', null);
                }
                break;

            case 'json':
                if (!$this->response()->headers->has('Content-Type'))
                {
                    $this->response()->headers->set('Content-Type', 'application/json');
                }
                if (is_callable($data))
                {
                    $this->variable('tico_set_callback__type', $type);
                    $this->variable('tico_set_callback__callback', $data);
                    $this->hook('tico_set_callback');
                    $this->response()->setCallback($this->variable('tico_set_callback__callback'));
                    $this->variable('tico_set_callback__callback', null);
                    $this->variable('tico_set_callback__type', null);
                }
                else
                {
                    $this->variable('tico_set_content__type', $type);
                    $this->variable('tico_set_content__content', json_encode($data));
                    $this->hook('tico_set_content');
                    $this->response()->setContent($this->variable('tico_set_content__content'));
                    $this->variable('tico_set_content__content', null);
                    $this->variable('tico_set_content__type', null);
                }
                break;

            case 'file':
                $file = $data;
                $this->variable('tico_set_file__file', $file);
                if ($headers && isset($headers['deleteFileAfterSend']))
                {
                    $this->variable('tico_set_file__deleteFileAfterSend', $headers['deleteFileAfterSend']);
                    unset($headers['deleteFileAfterSend']);
                }
                else
                {
                    $this->variable('tico_set_file__deleteFileAfterSend', false);
                }
                $this->hook('tico_set_file');
                $file = $this->variable('tico_set_file__file');
                $deleteFileAfterSend = $this->variable('tico_set_file__deleteFileAfterSend');
                $this->variable('tico_set_file__file', null);
                $this->variable('tico_set_file__deleteFileAfterSend', null);
                if ($file)
                {
                    if (!$this->response()->headers->has('Content-Type'))
                    {
                        $file_type = mime_content_type($file);
                        if (empty($file_type)) $file_type = 'application/octet-stream';
                        $this->response()->headers->set('Content-Type', $file_type);
                    }
                    //$this->response->headers->set('Content-Length', filesize($file));
                    $this->response()->setFile($file);
                    if ($deleteFileAfterSend) $this->response()->deleteFileAfterSend(true);
                    $this->variable('cache', false); // files not cached
                }
                break;

            default:
                if (!$this->response()->headers->has('Content-Type'))
                {
                    $this->response()->headers->set('Content-Type', 'text/html');
                }
                if (is_callable($data))
                {
                    $this->variable('tico_set_callback__type', $type);
                    $this->variable('tico_set_callback__callback', $data);
                    $this->hook('tico_set_callback');
                    $this->response()->setCallback($this->variable('tico_set_callback__callback'));
                    $this->variable('tico_set_callback__callback', null);
                    $this->variable('tico_set_callback__type', null);
                }
                else
                {
                    $this->variable('tico_set_content__type', $type);
                    $this->variable('tico_set_content__content', $this->tpl($type, $data));
                    $this->hook('tico_set_content');
                    $this->response()->setContent($this->variable('tico_set_content__content'));
                    $this->variable('tico_set_content__content', null);
                    $this->variable('tico_set_content__type', null);
                }
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

    public function datetime($time = null)
    {
        if (is_null($time)) $time = time();
        $dt = \DateTime::createFromFormat('U', $time);
        $dt->setTimezone(new \DateTimeZone('UTC'));
        return $dt->format('D, d M Y H:i:s').' GMT';
    }

    public function cached()
    {
        if (!$this->request()->isMethodCacheable() || !$this->response()->isCacheable()) return null;
        $response = $this->response();
        $content = (string)$response->getContent();
        return strlen($content) ? serialize(array(
            'key' => $this->_k,
            'protocol' => 'HTTP/'.$response->getProtocolVersion(),
            'time' => time(),
            'status' => $response->getStatusCode(),
            'status-text' => HttpResponse::$statusTexts[$response->getStatusCode()],
            'content-type' => $response->headers->get('Content-Type'),
            'content' => $content,
        )) : null;
    }

    private function _serveCached($cached)
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
                $this->variable('tico_before_serve_cached__content_type', $content['content-type']);
                $this->variable('tico_before_serve_cached__content', $content['content']);
                $this->hook('tico_before_serve_cached');
                $content['content-type'] = $this->variable('tico_before_serve_cached__content_type');
                $content['content'] = $this->variable('tico_before_serve_cached__content');
                $this->variable('tico_before_serve_cached__content_type', null);
                $this->variable('tico_before_serve_cached__content', null);
                header('Content-Type: '.$content['content-type'], true, $content['status']);
                header('Last-Modified: '.$this->datetime($content['time']), true, $content['status']);
                header('Date: '.$this->datetime(time()), true, $content['status']);
                header($content['protocol'].' '.$content['status'].' '.$content['status-text'], true, $content['status']);
                echo $content['content'];
                $this->hook('tico_after_serve_cached');
                return true;
            }
        }
        return false;
    }

    public function redirect($uri, $code = 302)
    {
        $this->variable('tico_redirect__code', $code);
        $this->variable('tico_redirect__uri', $uri);
        $this->hook('tico_redirect');
        $this->response()->setTargetUrl($this->variable('tico_redirect__uri'), $this->variable('tico_redirect__code'));
        $this->variable('tico_redirect__code', null);
        $this->variable('tico_redirect__uri', null);
        $this->variable('cache', false); // redirects not cached
        return $this;
    }

    public function enqueue($type, $id, $asset_def = array())
    {
        $this->variable('tico_enqueue__type', $type);
        $this->variable('tico_enqueue__id', $id);
        $this->variable('tico_enqueue__asset', (array)$asset_def);
        $this->hook('tico_enqueue');
        $this->loader()->enqueue($this->variable('tico_enqueue__type'), $this->variable('tico_enqueue__id'), $this->variable('tico_enqueue__asset'));
        $this->variable('tico_enqueue__type', null);
        $this->variable('tico_enqueue__id', null);
        $this->variable('tico_enqueue__asset', null);
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

    public function flatten($input, $output = array(), $prefix = null)
    {
        if (!empty($input))
        {
            foreach ($input as $key => $val)
            {
                $name = empty($prefix) ? $key : ($prefix."[$key]");

                if (is_array($val)) $output = $this->flatten($val, $output, $name);
                else $output[$name] = $val;
            }
        }
        return $output;
    }

    public function kv($input, $output = array(), $glue = '')
    {
        if (!empty($input))
        {
            foreach ($input as $key => $val)
            {
                $output[] = ((string)$key) . $glue . ((string)$val);
            }
        }
        return $output;
    }

    public function httpCLIENT($method, $uri, $requestBody = '', $requestHeaders = array(), &$responseStatus = 0, &$responseHeaders = null)
    {
        switch (strtoupper($method))
        {
            case 'POST':
            if (!empty($requestBody))
            {
                if (is_array($requestBody))
                {
                    $requestData = $requestBody;
                }
                else
                {
                    $requestData = array();
                    @parse_str((string)$requestBody, $requestData);
                }
                $requestData = $this->flatten($requestData);
                $formData = implode('', array_map(function($name, $value) {return '<input type="hidden" name="'.$name.'" value="'.$value.'" />';}, array_keys($requestData), $requestData));
            }
            else
            {
                $formData = '';
            }
            try {
                @header('Content-Type: text/html; charset=UTF-8', true, 200);
                @header('Date: '.$this->datetime(time()), true, 200);
                echo ('<!DOCTYPE html><html><head><meta http-equiv="content-type" content="text/html; charset=UTF-8"/><title>POST '.$uri.'</title></head><body onload="do_post();"><form name="post_form" id="post_form" method="post" enctype="application/x-www-form-urlencoded" action="'.$uri.'">'.$formData.'</form><script type="text/javascript">function do_post() {document.post_form.submit();}</script></body></html>');
            } catch (Exception $e) {
            }
            break;

            case 'GET':
            default:
            try {
                @header("Location: $uri", true, 303);
                @header('Content-Type: text/html; charset=UTF-8', true, 303);
                @header('Date: '.$this->datetime(time()), true, 303);
                echo ('<!DOCTYPE html><html><head><meta http-equiv="content-type" content="text/html; charset=UTF-8"/><meta http-equiv="refresh" content="0; URL='.$uri.'"/><title>GET '.$uri.'</title></head><body onload="do_get();"><script type="text/javascript">function do_get() {window.location.href = "'.$uri.'";}</script></body></html>');
            } catch (Exception $e) {
            }
            break;
        }
        return null;
    }

    public function httpCURL($method, $uri, $requestBody = '', $requestHeaders = array(), &$responseStatus = 0, &$responseHeaders = null)
    {
        if (!function_exists('curl_init')) return false;
        $curl = curl_init($uri);
        curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($curl, CURLOPT_HEADERFUNCTION, function($curl, $header) use (&$responseHeaders) {
            if (is_null($responseHeaders)) $responseHeaders = array();
            $len = strlen($header);
            $header = explode(':', $header, 2);
            if (count($header) >= 2)
            {
                $k = strtolower(trim($header[0])); $v = trim($header[1]);
                if (!isset($responseHeaders[$k])) $responseHeaders[$k] = array($v);
                else $responseHeaders[$k][] = $v;
            }
            return $len;
        });
        curl_setopt($curl, CURLOPT_HTTPHEADER, $requestHeaders);
        if ('POST' === strtoupper($method))
        {
            curl_setopt($curl, CURLOPT_POST, true);
            curl_setopt($curl, CURLOPT_POSTFIELDS, $requestBody);
        }
        else
        {
            curl_setopt($curl, CURLOPT_HTTPGET, true);
        }
        try {
            $responseBody = @curl_exec($curl);
            $responseStatus = @curl_getinfo($curl, CURLINFO_HTTP_CODE);
        } catch (Exception $e) {
            $responseBody = false;
        }
        curl_close($curl);
        return $responseBody;
    }

    public function httpFILE($method, $uri, $requestBody = '', $requestHeaders = array(), &$responseStatus = 0, &$responseHeaders = null)
    {
        $context = stream_context_create(array(
            "http" => array(
                "method"        => strtoupper($method),
                "header"        => implode("\r\n", (array)$requestHeaders),
                "content"       => (string)$requestBody,
                "ignore_errors" => true,
            ),
        ));
        try {
            $responseBody = @file_get_contents($uri, false, $context);
        } catch (Exception $e) {
            $responseBody = false;
        }
        if (!empty($http_response_header)) $responseHeaders = array_merge(array(), $http_response_header);
        if (!empty($responseHeaders) && preg_match('#HTTP/\\S*\\s+(\\d{3})#', $responseHeaders[0], $m)) $responseStatus = (int)$m[1];
        return $responseBody;
    }

    public function http($method = 'get', $transport = 'server', $uri = '', $data = null, $headers = null, &$responseBody = '', &$responseStatus = 0, &$responseHeaders = null)
    {
        // TODO: support POST files ??
        // TODO: support server socket transport ??
        if (!empty($uri))
        {
            $method = strtolower((string)$method);
            $transport = strtolower((string)$transport);
            if ('client' === $transport || 'browser' === $transport)
            {
                switch ($method)
                {
                    case 'post':
                    $responseBody = $this->httpCLIENT('POST', $uri, $data);
                    break;

                    case 'get':
                    default:
                    $responseBody = $this->httpCLIENT('GET', $uri.(!empty($data) ? ((false === strpos($uri, '?') ? '?' : '&').http_build_query($data, '', '&')) : ''));
                    break;
                }
            }
            elseif ('curl' === $transport || 'server_curl' === $transport)
            {
                switch ($method)
                {
                    case 'post':
                    $responseBody = $this->httpCURL('POST', $uri, !empty($data) ? http_build_query($data, '', '&') : '', $this->kv($headers, array('Content-type: application/x-www-form-urlencoded'), ': '), $responseStatus, $responseHeaders);
                    break;

                    case 'get':
                    default:
                    $responseBody = $this->httpCURL('GET', $uri.(!empty($data) ? ((false === strpos($uri, '?') ? '?' : '&').http_build_query($data, '', '&')) : ''), '', $this->kv($headers, array(), ': '), $responseStatus, $responseHeaders);
                    break;
                }
            }
            else//if ('server' === $transport || 'server_file' === $transport)
            {
                switch ($method)
                {
                    case 'post':
                    $responseBody = $this->httpFILE('POST', $uri, !empty($data) ? http_build_query($data, '', '&') : '', $this->kv($headers, array('Content-type: application/x-www-form-urlencoded'), ': '), $responseStatus, $responseHeaders);
                    break;

                    case 'get':
                    default:
                    $responseBody = $this->httpFILE('GET', $uri.(!empty($data) ? ((false === strpos($uri, '?') ? '?' : '&').http_build_query($data, '', '&')) : ''), '', $this->kv($headers, array(), ': '), $responseStatus, $responseHeaders);
                    break;
                }
            }
        }
        return $this;
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

    public function requestParam($key, $default = null, $caseInsensitive = null)
    {
        if (null === $caseInsensitive) $caseInsensitive = $this->option('case_insensitive_uris');
        $this->request();
        return $caseInsensitive ? $this->request()->queryci->get(strtolower($key), $default) : $this->request()->query->get($key, $default);
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
                    $params = $this->option('route_params_object') ? new TicoParams($route['data'], $this->option('original_params_key')) : $route['data'];
                    return call_user_func($handler, $params);
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
        try
        {
            $cache = $this->get('cache');
        }
        catch (Exception $e)
        {
            $cache = null;
        }
        if (is_object($cache) && method_exists($cache, 'get'))
        {
            $this->variable('tico_serve_cache__key', $this->_k);
            $this->hook('tico_serve_cache');
            $cached = $cache->get($this->variable('tico_serve_cache__key'));
            $this->variable('tico_serve_cache__key', null);
            if ($cached && $this->_serveCached($cached)) return true;
        }
        return false;
    }

    public function serve()
    {
        if ($this->isCli()) return false;

        $this->_fixServerVars();

        $this->hook('tico_before_serve');
        $this->request();

        $passed = true;

        if (!empty($this->Middleware->before))
        {
            $this->hook('tico_before_middleware_before');
            $passed = false;
            $next1 = function() use (&$next1, &$passed) {
                static $i = -1;
                ++$i;
                if ($i >= count($this->Middleware->before)) $passed = true;
                else call_user_func($this->Middleware->before[$i], $next1);
            };
            call_user_func($next1);
            $this->hook('tico_after_middleware_before');
        }

        if ($passed)
        {
            $this->hook('tico_before_route');
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
            $this->hook('tico_after_route');
        }

        if (!empty($this->Middleware->after))
        {
            $this->hook('tico_before_middleware_after');
            $next2 = function() use (&$next2) {
                static $i = -1;
                ++$i;
                if ($i < count($this->Middleware->after)) call_user_func($this->Middleware->after[$i], $next2);
            };
            call_user_func($next2);
            $this->hook('tico_after_middleware_after');
        }

        $this->response()->prepare($this->request());
        $this->hook('tico_prepared_response');

        // if cache enabled for this page, cache it
        if ($this->variable('cache'))
        {
            try
            {
                $cache = $this->get('cache');
            }
            catch (Exception $e)
            {
                $cache = null;
            }
        }
        else
        {
            $cache = null;
        }
        if (is_object($cache) && method_exists($cache, 'set') && ($cached = $this->cached()))
        {
            $this->variable('tico_cache_response__key', $this->_k);
            $this->variable('tico_cache_response__content', $cached);
            $this->hook('tico_cache_response');
            $cache->set($this->variable('tico_cache_response__key'), $this->variable('tico_cache_response__content'));
            $this->variable('tico_cache_response__key', null);
            $this->variable('tico_cache_response__content', null);
        }

        $this->hook('tico_send_response');
        $this->response()->send();
        $this->hook('tico_after_serve');
        return true;
    }
}
function tico($baseUrl = '', $basePath = '')
{
    static $tico = null;
    if (!$tico) $tico = $baseUrl instanceof Tico ? $baseUrl : new Tico($baseUrl, $basePath);
    return $tico;
}
}