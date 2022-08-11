<?php
/**
*
*   Dromeo
*   Simple and Flexible Pattern Routing Framework for PHP, JavaScript, Python
*   @version: 1.1.2
*
*   https://github.com/foo123/Dromeo
*
**/
if (!class_exists('Dromeo', false))
{
class DromeoRoute
{
    private $__args__ = null;
    public $isParsed = false;
    public $route = null;
    public $prefix = null;
    public $pattern = null;
    public $captures = null;
    public $tpl = null;
    public $handlers = null;
    public $method = null;
    public $literal = null;
    public $namespace = null;
    public $name = null;
    public $key = null;

    public static function to_key($route, $method)
    {
        return implode(',', $method) . '->' . $route;
    }

    public function __construct($delims, $patterns, $route, $method, $name = null, $prefix = '')
    {
        $this->__args__ = array($delims, $patterns);
        $this->isParsed = false; // lazy init
        $this->handlers = array();
        $this->route = (string)$route;
        $this->prefix = (string)$prefix;
        $this->method = $method;
        $this->pattern = null;
        $this->captures = null;
        $this->literal = false;
        $this->namespace = null;
        $this->tpl = null;
        $this->name = isset($name) ? (string)$name : null;
        $this->key = self::to_key($this->route, $this->method);
    }

    public function __destruct()
    {
        $this->dispose();
    }

    public function dispose()
    {
        $this->__args__ = null;
        $this->isParsed = null;
        $this->handlers = null;
        $this->route = null;
        $this->prefix = null;
        $this->pattern = null;
        $this->captures = null;
        $this->tpl = null;
        $this->method = null;
        $this->literal = null;
        $this->namespace = null;
        $this->name = null;
        $this->key = null;
        return $this;
    }

    public function parse()
    {
        if ($this->isParsed) return $this;
        $r = Dromeo::makeRoute($this->__args__[0], $this->__args__[1], $this->route, $this->method, $this->prefix);
        $this->pattern = $r[1];
        $this->captures = $r[2];
        $this->tpl = $r[5];
        $this->literal = true === $r[4];
        $this->__args__ = null;
        $this->isParsed = true;
        return $this;
    }

    public function match($route, $method = '*')
    {
        if (!in_array($method, $this->method) && ('*' !== $this->method[0])) return null;
        if (!$this->isParsed) $this->parse(); // lazy init
        $route = (string)$route;
        $matched = $this->literal ? ($this->pattern === $route) : preg_match($this->pattern, $route, $match, PREG_OFFSET_CAPTURE, 0);
        return $matched ? ($this->literal ? true : $match) : null;
    }

    public function make($params = array(), $strict = false)
    {
        $out = '';
        $params = (array)$params;
        $strict = true === $strict;
        if (!$this->isParsed) $this->parse(); // lazy init
        $tpl = $this->tpl;
        for($i=0,$l=count($tpl); $i<$l; ++$i)
        {
            if (is_string($tpl[$i]))
            {
                $out .= $tpl[$i];
            }
            else
            {
                if (!isset($params[$tpl[$i]->name]))
                {
                    if ($tpl[$i]->optional)
                    {
                        continue;
                    }
                    else
                    {
                        throw new RuntimeException('Dromeo: Route "'.$this->name.'" (Pattern: "'.$this->route.'") missing parameter "'.$tpl[$i]->name.'"!');
                    }
                }
                else
                {
                    $param = (string)$params[$tpl[$i]->name];
                    if ($strict && !preg_match($tpl[$i]->re,$param, $m))
                    {
                        throw new RuntimeException('Dromeo: Route "'.$this->name.'" (Pattern: "'.$this->route.'") parameter "'.$tpl[$i]->name.'" value "'.$param.'" does not match pattern!');
                    }
                    $part = $tpl[$i]->tpl;
                    for($j=0,$k=count($part); $j<$k; ++$j)
                    {
                        $out .= true === $part[$j] ? $param : $part[$j];
                    }
                }
            }
        }
        return $out;
    }

    public function sub($match, &$data, $type = null, $originalInput = null, $originalKey = null)
    {
        if (!$this->isParsed || $this->literal) return $this;
        $odata = array();
        $givenInput = is_array($match[0]) ? $match[0][0] : $match[0];
        $isDifferentInput = is_string($originalInput) && ($originalInput !== $givenInput);
        foreach ($this->captures as $v => $g)
        {
            $groupIndex = $g[0];
            $groupTypecaster = $g[1];
            if (isset($match[$groupIndex]) && $match[$groupIndex])
            {
                if (is_array($match[$groupIndex]))
                {
                    if (!strlen($match[$groupIndex][0])) continue;
                    // if original input is given,
                    // get match from original input (eg with original case)
                    $matchedValue = $match[$groupIndex][0];
                    $matchedOriginalValue = $isDifferentInput ? substr($originalInput, $match[$groupIndex][1], strlen($matchedValue)) : $matchedValue;
                }
                else
                {
                    if (!strlen($match[$groupIndex])) continue;
                    // else what matched
                    $matchedValue = $match[$groupIndex];
                    $matchedOriginalValue = $matchedValue;
                }

                if ($type && isset($type[$v]))
                {
                    $typecaster = $type[$v];
                    if (is_string($typecaster) && isset(Dromeo::$TYPES[$typecaster]))
                        $typecaster = Dromeo::$TYPES[$typecaster];
                    $data[$v] = is_callable($typecaster) ? call_user_func($typecaster, $matchedValue) : $matchedValue;
                    $odata[$v] = is_callable($typecaster) ? call_user_func($typecaster, $matchedOriginalValue) : $matchedOriginalValue;
                }
                elseif ($groupTypecaster)
                {
                    $typecaster = $groupTypecaster;
                    $data[$v] = is_callable($typecaster) ? call_user_func($typecaster, $matchedValue) : $matchedValue;
                    $odata[$v] = is_callable($typecaster) ? call_user_func($typecaster, $matchedOriginalValue) : $matchedOriginalValue;
                }
                else
                {
                    $data[$v] = $matchedValue;
                    $odata[$v] = $matchedOriginalValue;
                }
            }
            elseif (!isset($data[$v]))
            {
                $data[$v] = null;
                $odata[$v] = null;
            }
        }
        if ($originalKey) $data[(string)$originalKey] = $odata;
        return $this;
    }
}

class Dromeo
{
    const VERSION = "1.1.2";

    // http://en.wikipedia.org/wiki/List_of_HTTP_status_codes
    public static $HTTP_STATUS = array(
    // 1xx Informational
     100=> "Continue"
    ,101=> "Switching Protocols"
    ,102=> "Processing"
    ,103=> "Early Hints"

    // 2xx Success
    ,200=> "OK"
    ,201=> "Created"
    ,202=> "Accepted"
    ,203=> "Non-Authoritative Information"
    ,204=> "No Content"
    ,205=> "Reset Content"
    ,206=> "Partial Content"
    ,207=> "Multi-Status"
    ,208=> "Already Reported"
    ,226=> "IM Used"

    // 3xx Redirection
    ,300=> "Multiple Choices"
    ,301=> "Moved Permanently"
    ,302=> "Found" //Previously "Moved temporarily"
    ,303=> "See Other"
    ,304=> "Not Modified"
    ,305=> "Use Proxy"
    ,306=> "Switch Proxy"
    ,307=> "Temporary Redirect"
    ,308=> "Permanent Redirect"

    // 4xx Client Error
    ,400=> "Bad Request"
    ,401=> "Unauthorized"
    ,402=> "Payment Required"
    ,403=> "Forbidden"
    ,404=> "Not Found"
    ,405=> "Method Not Allowed"
    ,406=> "Not Acceptable"
    ,407=> "Proxy Authentication Required"
    ,408=> "Request Timeout"
    ,409=> "Conflict"
    ,410=> "Gone"
    ,411=> "Length Required"
    ,412=> "Precondition Failed"
    ,413=> "Request Entity Too Large"
    ,414=> "Request-URI Too Long"
    ,415=> "Unsupported Media Type"
    ,416=> "Requested Range Not Satisfiable"
    ,417=> "Expectation Failed"
    ,418=> "I'm a teapot"
    ,419=> "Authentication Timeout"
    ,422=> "Unprocessable Entity"
    ,423=> "Locked"
    ,424=> "Failed Dependency"
    ,426=> "Upgrade Required"
    ,428=> "Precondition Required"
    ,429=> "Too Many Requests"
    ,431=> "Request Header Fields Too Large"
    ,440=> "Login Timeout"
    ,444=> "No Response"
    ,449=> "Retry With"
    ,450=> "Blocked by Windows Parental Controls"
    ,451=> "Unavailable For Legal Reasons"
    ,494=> "Request Header Too Large"
    ,495=> "Cert Error"
    ,496=> "No Cert"
    ,497=> "HTTP to HTTPS"
    ,498=> "Token expired/invalid"
    ,499=> "Client Closed Request"

    // 5xx Server Error
    ,500=> "Internal Server Error"
    ,501=> "Not Implemented"
    ,502=> "Bad Gateway"
    ,503=> "Service Unavailable"
    ,504=> "Gateway Timeout"
    ,505=> "HTTP Version Not Supported"
    ,506=> "Variant Also Negotiates"
    ,507=> "Insufficient Storage"
    ,508=> "Loop Detected"
    ,509=> "Bandwidth Limit Exceeded"
    ,510=> "Not Extended"
    ,511=> "Network Authentication Required"
    ,520=> "Origin Error"
    ,521=> "Web server is down"
    ,522=> "Connection timed out"
    ,523=> "Proxy Declined Request"
    ,524=> "A timeout occurred"
    ,598=> "Network read timeout error"
    ,599=> "Network connect timeout error"
    );

    private static $_patternOr = '/^([^|]+\\|.+)$/';
    private static $_group = '/\\((\\d+)\\)$/';

    private $_delims = null;
    private $_patterns = null;
    private $_routes = null;
    private $_named_routes = null;
    private $_fallback = false;
    private $_prefix = '';

    public static $TYPES = array();

    // build/glue together a uri component from a params object
    public static function glue_params($params)
    {
        $component = '';
        // http://php.net/manual/en/function.http-build-query.php (for '+' sign convention)
        if ($params) $component .= str_replace('+', '%20', http_build_query($params, '', '&'/*,  PHP_QUERY_RFC3986*/));
        return $component;
    }

    // unglue/extract params object from uri component
    public static function unglue_params($s)
    {
        $PARAMS = array();
        if ($s) parse_str($s, $PARAMS);
        return $PARAMS;
    }

    // parse and extract uri components and optional query/fragment params
    public static function parse_components($s, $query_p = 'query_params', $fragment_p = 'fragment_params')
    {
        $COMPONENTS = array();
        if ($s)
        {
            $COMPONENTS = parse_url($s);

            if ($query_p)
            {
                if (isset($COMPONENTS['query']) && $COMPONENTS['query'])
                    $COMPONENTS[$query_p] = self::unglue_params($COMPONENTS['query']);
                else
                    $COMPONENTS[$query_p] = array();
            }
            if ($fragment_p)
            {
                if (isset($COMPONENTS['fragment']) && $COMPONENTS['fragment'])
                    $COMPONENTS[$fragment_p] = self::unglue_params($COMPONENTS['fragment']);
                else
                    $COMPONENTS[$fragment_p] = array();
            }
        }
        return $COMPONENTS;
    }

    // build a url from baseUrl plus query/hash params
    public static function build_components($baseUrl, $query = null, $hash = null, $q = '?', $h = '#')
    {
        $url = '' . $baseUrl;
        if ($query)  $url .= $q . self::glue_params($query);
        if ($hash)  $url .= $h . self::glue_params($hash);
        return $url;
    }

    public static function to_method($method)
    {
        $method = isset($method) ? (is_array($method) ? array_map('strtolower', $method) : array(strtolower((string)$method))) : array('*');
        if (in_array('*', $method)) $method = array('*');
        sort($method);
        return $method;
    }

    public static function type_to_int($v)
    {
        $v = intval($v, 10);
        return !$v ? 0 : $v; // take account of nan to 0
    }

    public static function type_to_urldecode($v)
    {
        return urldecode($v);
    }

    public static function type_to_str($v)
    {
        return is_string($v) ? $v : strval($v);
    }

    public static function type_to_array($v)
    {
        return is_array($v) ? $v : array($v);
    }

    public static function type_to_params($v)
    {
        return is_string($v) ? self::ungle_params($v) : $v;
    }

    public static function defType($type, $caster)
    {
        if ($type && is_callable($caster)) self::$TYPES[$type] = $caster;
    }

    public static function TYPE($type)
    {
        if ($type && isset(self::$TYPES[$type])) return self::$TYPES[$type];
        return null;
    }

    // factory method, useful for continous method chaining
    public static function _($route_prefix = '')
    {
        return new self($route_prefix);
    }

    public function __construct($route_prefix = '')
    {
        $this->_delims = array('{', '}', '%', '%', ':');
        $this->_patterns = array();
        $this->definePattern('ALPHA',      '[a-zA-Z\\-_]+');
        $this->definePattern('ALNUM',      '[a-zA-Z0-9\\-_]+');
        $this->definePattern('NUMBR',      '[0-9]+');
        $this->definePattern('INT',        '[0-9]+',          'INT');
        $this->definePattern('PART',       '[^\\/?#]+');
        $this->definePattern('VAR',        '[^=?&#\\/]+',     'VAR');
        $this->definePattern('QUERY',      '\\?[^?#]+');
        $this->definePattern('FRAGMENT',   '#[^?#]+');
        $this->definePattern('URLENCODED', '[^\\/?#]+',       'URLENCODED');
        $this->definePattern('ALL',        '.+');
        $this->_routes = array();
        $this->_named_routes = array();
        $this->_fallback = false;
        $this->_prefix = (string)$route_prefix;
    }

    public function __destruct()
    {
        $this->dispose();
    }

    public function dispose()
    {
        $this->_delims = null;
        $this->_patterns = null;
        $this->_fallback = null;
        $this->_prefix = null;
        if ($this->_routes)
        {
            foreach ($this->_routes as $r)
            {
                $r->dispose();
            }
        }
        $this->_routes = null;
        $this->_named_routes = null;
        return $this;
    }

    public function reset()
    {
        $this->_routes = array();
        $this->_named_routes = array();
        $this->_fallback = false;
        return $this;
    }

    public function defineDelimiters($delims)
    {
        if (!empty($delims))
        {
            if (isset($delims[0])) $this->_delims[0] = $delims[0];
            if (isset($delims[1])) $this->_delims[1] = $delims[1];
            if (isset($delims[2])) $this->_delims[2] = $delims[2];
            if (isset($delims[3])) $this->_delims[3] = $delims[3];
            if (isset($delims[4])) $this->_delims[4] = $delims[4];
        }
        return $this;
    }

    public function definePattern($className, $subPattern, $typecaster = null)
    {
        if (
            !empty($typecaster) &&
            is_string($typecaster) &&
            isset(self::$TYPES[$typecaster])
        ) $typecaster = self::$TYPES[$typecaster];

        if (empty($typecaster) || !is_callable($typecaster)) $typecaster = null;
        $this->_patterns[$className] = array($subPattern, $typecaster);
        return $this;
    }

    public function dropPattern($className)
    {
        if (isset($this->_patterns[$className]))
            unset($this->_patterns[$className]);
        return $this;
    }

    public function defineType($type, $caster)
    {
        self::defType($type, $caster);
        return $this;
    }

    /*public function debug()
    {
        echo 'Routes: ' . print_r($this->_routes, true) . PHP_EOL;
        echo 'Fallback: ' . print_r($this->_fallback, true) . PHP_EOL;
    }*/

    // build/glue together a uri component from a params object
    public function glue($params)
    {
        return self::glue_params($params);
    }

    // unglue/extract params object from uri component
    public function unglue($s)
    {
        return self::unglue_params($s);
    }

    // parse and extract uri components and optional query/fragment params
    public function parse($s, $query_p = 'query_params', $fragment_p = 'fragment_params')
    {
        return self::parse_components($s, $query_p, $fragment_p);
    }

    // build a url from baseUrl plus query/hash params
    public function build($baseUrl, $query = null, $hash = null, $q = '?', $h = '#')
    {
        return self::build_components($baseUrl, $query, $hash, $q, $h);
    }

    public function redirect($url, $statusCode = 302, $statusMsg = true)
    {
        if ($url)
        {
            if (!headers_sent())
            {
                if ($statusMsg)
                {
                    if (true === $statusMsg)
                        $statusMsg = isset(self::$HTTP_STATUS[$statusCode]) ? self::$HTTP_STATUS[$statusCode] : '';

                    $protocol = $_SERVER["SERVER_PROTOCOL"];
                    if ('HTTP/1.1' != $protocol && 'HTTP/1.0' != $protocol)
                        $protocol = 'HTTP/1.0';

                    @header("$protocol $statusCode $statusMsg", true, $statusCode);
                    header("Location: $url", true, $statusCode);
                }
                else
                {
                    header("Location: $url", true, $statusCode);
                }
                exit;
            }
        }
        return $this;
    }

    public function on(/* var args here .. */)
    {
        $args = func_get_args(); $args_len = count($args);

        if (1 == $args_len)
        {
            $routes = is_array($args[0]) && isset($args[0][0]) && is_array($args[0][0])
                    ? $args[0]
                    : array($args[0]);
        }
        elseif (2 == $args_len && is_string($args[0]) && is_callable($args[1]))
        {
            $routes = array(array(
                'route'=> $args[0],
                'handler'=> $args[1],
                'method'=> '*',
                'defaults'=> array(),
                'types'=> null
            ));
        }
        else
        {
            $routes = $args;
        }
        self::addRoutes($this->_routes, $this->_named_routes, $this->_delims, $this->_patterns, $this->_prefix, $routes);
        return $this;
    }

    public function one(/* var args here .. */)
    {
        $args = func_get_args(); $args_len = count($args);

        if (1 == $args_len)
        {
            $routes = is_array($args[0]) && isset($args[0][0]) && is_array($args[0][0])
                    ? $args[0]
                    : array($args[0]);
        }
        elseif (2 == $args_len && is_string($args[0]) && is_callable($args[1]))
        {
            $routes = array(array(
                'route'=> $args[0],
                'handler'=> $args[1],
                'method'=> '*',
                'defaults'=> array(),
                'types'=> null
            ));
        }
        else
        {
            $routes = $args;
        }
        self::addRoutes($this->_routes, $this->_named_routes, $this->_delims, $this->_patterns, $this->_prefix, $routes, true);
        return $this;
    }

    public function off($route, $handler = null, $method = '*')
    {
        if (!$route) return $this;

        if (is_array($route))
        {
            $handler = isset($route['handler']) ? $route['handler'] : $handler;
            $method = isset($route['method']) ? $route['method'] : $method;
            $route = $route['route'];
            if (!$route) return $this;
            $route = (string)$route;
            $key = DromeoRoute::to_key($route, self::to_method($method));
            $r = null;
            foreach ($this->_routes as $rt)
            {
                if ($key === $rt->key)
                {
                    $r = $rt;
                    break;
                }
            }
            if (!$r) return $this;

            if ($handler && is_callable($handler))
            {
                $l = count($r->handlers);
                for ($i=$l-1; $i>=0; --$i)
                {
                    if ($handler === $r->handlers[$i]->handler)
                        array_splice($r->handlers, $i, 1);
                }
                if (empty($r->handlers))
                    self::clearRoute($this->_routes, $this->_named_routes, $key);
            }
            else
            {
                self::clearRoute($this->_routes, $this->_named_routes, $key);
            }
        }
        elseif (is_string($route) && strlen($route))
        {
            $route = (string)$route;
            $key = DromeoRoute::to_key($route, self::to_method($method));
            $r = null;
            foreach ($this->_routes as $rt)
            {
                if ($key === $rt->key)
                {
                    $r = $rt;
                    break;
                }
            }
            if (!$r) return $this;

            if ($handler && is_callable($handler))
            {
                $l = count($r->handlers);
                for ($i=$l-1; $i>=0; --$i)
                {
                    if ($handler === $r->handlers[$i]->handler)
                        array_splice($r->handlers, $i, 1);
                }
                if (empty($r->handlers))
                    self::clearRoute($this->_routes, $this->_named_routes, $key);
            }
            else
            {
                self::clearRoute($this->_routes, $this->_named_routes, $key);
            }
        }
        return $this;
    }

    public function fallback($handler = false)
    {
        if (false === $handler || null === $handler || is_callable($handler))
            $this->_fallback = $handler;
        return $this;
    }

    public function make($named_route, $params = array(), $strict = false)
    {
        return isset($this->_named_routes[$named_route]) ? $this->_named_routes[$named_route]->make($params, $strict) : null;
    }

    public function route($r, $method = "*", $breakOnFirstMatch = true, $originalR = null, $originalKey = null)
    {
        $proceed = true;
        $found = false;
        $r = (string)$r;
        $prefix = $this->_prefix;
        if ($prefix && strlen($prefix))
        {
            $proceed = ($prefix === substr($r, 0, strlen($prefix)));
        }
        if ($proceed)
        {
            $breakOnFirstMatch = false !== $breakOnFirstMatch;
            $method = $method ? strtolower((string)$method) : '*';
            $routes = array_merge(array(), $this->_routes); // copy, avoid mutation
            foreach ($routes as $route)
            {
                $match = $route->match($r, $method);
                if (!$match ) continue;

                $found = true;

                // copy handlers avoid mutation during calls
                // is this shallow or deep copy???
                // since using objects as array items, it should be shallow
                $handlers = array_merge(array(), $route->handlers);

                // make calls
                foreach ($handlers as &$handler)
                {
                    // handler is oneOff and already called
                    if ($handler->oneOff && $handler->called) continue;

                    // get params
                    $params = array(
                        'route'=> $r,
                        'method'=> $method,
                        'pattern'=> $route->route,
                        'fallback'=> false,
                        'data'=> array_merge_recursive(array(), $handler->defaults)
                    );
                    $route->sub($match, $params['data'], $handler->types, $originalR, $originalKey);

                    $handler->called = 1; // handler called
                    call_user_func($handler->handler, $params);
                }

                // remove called oneOffs
                /*for ($h=count($route->handlers)-1; $h>=0; $h--)
                {
                    // handler is oneOff and called once
                    $handler =& $route->handlers[$h];
                    if ( $handler->oneOff && $handler->called ) array_splice($route->handlers, $h, 1);
                }
                if ( empty($route->handlers) )
                    self::clearRoute( $this->_routes, $route->key );*/

                if ($breakOnFirstMatch) return true;
            }
            if ($found) return true;
        }

        if ($this->_fallback)
        {
            call_user_func($this->_fallback, array('route'=>$r,  'method'=>$method, 'pattern'=>null, 'fallback'=>true, 'data'=>null));
        }
        return false;
    }

    private static function clearRoute(&$routes, &$named_routes, $key)
    {
        for ($i=count($routes)-1; $i>=0; --$i)
        {
            if ($key === $routes[$i]->key)
            {
                if ($route->name && isset($named_routes[$route->name]))
                    unset($named_routes[$route->name]);
                $routes[$i]->dispose();
                array_splice($routes, $i, 1);
            }
        }
    }

    private static function addRoute(&$routes, &$named_routes, &$delims, &$patterns, $prefix, $route, $oneOff = false)
    {
        if (
            is_array($route) && isset($route['route']) && is_string($route['route']) && strlen($route['route']) &&
            isset($route['handler']) && is_callable($route['handler'])
        )
        {
            $oneOff = (true === $oneOff);
            $handler = $route['handler'];
            $defaults = isset($route['defaults']) ? (array)$route['defaults'] : array();
            $types = isset($route['types']) ? (array)$route['types'] : array();
            $name = isset($route['name']) ? (string)$route['name'] : null;
            $method = self::to_method(isset($route['method']) ? $route['method'] : null);

            $route = (string)$route['route'];
            $key = DromeoRoute::to_key($route, $method);

            $routeInstance = null;
            foreach ($routes  as &$rt)
            {
                if ($key === $rt->key)
                {
                    $routeInstance = $rt;
                    break;
                }
            }
            if (null === $routeInstance)
            {
                $routeInstance = new DromeoRoute($delims, $patterns, $route, $method, $name, $prefix);
                $routes[] = $routeInstance;
                if ($routeInstance->name && strlen($routeInstance->name)) $named_routes[$routeInstance->name] = $routeInstance;
            }
            $routeInstance->handlers[] = (object)array(
                'handler'=>$handler,
                'defaults'=>$defaults,
                'types'=>$types,
                'oneOff'=>$oneOff,
                'called'=>0
            );
        }
    }

    private static function addRoutes(&$routes, &$named_routes, &$delims, &$patterns, $prefix, $args, $oneOff = false)
    {
        foreach ((array)$args as $route)
        {
            self::addRoute($routes, $named_routes, $delims, $patterns, $prefix, $route, $oneOff);
        }
    }

    public static function makeRoute(&$_delims, &$_patterns, $route, $method = null, $prefix = null)
    {
        if (false === strpos($route, $_delims[0]))
        {
            // literal route
            return array($route, $prefix && strlen($prefix) ? $prefix . $route : $route, array(), $method, true, array($route));
        }

        $parts = self::split($route, $_delims[0], $_delims[1]);
        $l = count($parts);
        $isPattern = false;
        $pattern = '';
        $numGroups = 0;
        $captures = array();
        $tpl = array();
        if ($prefix && strlen($prefix))
            $pattern .= preg_quote($prefix, '/');

        for ($i=0; $i<$l; ++$i)
        {
            $part = $parts[$i];
            if ($isPattern)
            {
                $isOptional = false;
                $isCaptured = false;
                $patternTypecaster = null;

                // http://abc.org/{%ALFA%:user}{/%NUM%:?id(1)}
                $p = explode($_delims[4], $part);
                if (!strlen($p[0]))
                {
                    // http://abc.org/{:user}/{:?id}
                    // assume pattern is %PART%
                    $p[0] = $_delims[2] . 'PART' . $_delims[3];
                }
                $capturePattern = self::makePattern($_delims, $_patterns, $p[0]);

                if (count($p) > 1)
                {
                    $captureName = trim($p[1]);
                    $isOptional = (strlen($captureName) && '?' === substr($captureName,0, 1));
                    if ($isOptional) $captureName = substr($captureName, 1);

                    if (preg_match(self::$_group, $captureName, $m))
                    {
                        $captureName = substr($captureName, 0, -strlen($m[0]));
                        $captureIndex = intval($m[1], 10);
                        $patternTypecaster = isset($capturePattern[2][$captureIndex])
                                ? $capturePattern[2][$captureIndex]
                                : null;
                        if ($captureIndex >= 0 && $captureIndex < $capturePattern[1])
                        {
                            $captureIndex += $numGroups + 1;
                        }
                        else
                        {
                            $captureIndex = $numGroups + 1;
                        }
                    }
                    else
                    {
                        $patternTypecaster = $capturePattern[2][0]
                                ? $capturePattern[2][0]
                                : null;
                        $captureIndex = $numGroups + 1;
                    }

                    $isCaptured = (strlen($captureName) > 0);
                }

                $pattern .= $capturePattern[0];
                $numGroups += $capturePattern[1];
                if ($isOptional) $pattern .= '?';
                if ($isCaptured) $captures[$captureName] = array($captureIndex, $patternTypecaster);
                if ($isCaptured)
                    $tpl[] = (object)array(
                        'name'        => $captureName,
                        'optional'    => $isOptional,
                        're'          => '/^' . $capturePattern[4] . '$/',
                        'tpl'         => $capturePattern[3]
                    );
                $isPattern = false;
            }
            else
            {
                $pattern .= preg_quote($part, '/');
                $tpl[] = $part;
                $isPattern = true;
            }
        }
        return array($route, '/^' . $pattern . '$/', $captures, $method, false, $tpl);
    }

    private static function makePattern(&$_delims, &$_patterns, $pattern)
    {
        $numGroups = 0;
        $types = array();
        $pattern = self::split($pattern, $_delims[2], $_delims[3]);
        $p = array();
        $tpl = array();
        $tplPattern = null;
        $l = count($pattern);
        $isPattern = false;
        for ($i=0; $i<$l; ++$i)
        {
            if ($isPattern)
            {
                if (strlen($pattern[$i]))
                {
                    if (isset($_patterns[$pattern[$i]]))
                    {
                        $p[] = '(' . $_patterns[$pattern[$i]][0] . ')';
                        ++$numGroups;
                        // typecaster
                        if ($_patterns[$pattern[$i]][1]) $types[$numGroups] = $_patterns[$pattern[$i]][1];
                        if (null === $tplPattern) $tplPattern = $p[count($p)-1];
                    }
                    elseif (preg_match(self::$_patternOr, $pattern[$i], $m))
                    {
                        $p[ ] = '(' . implode('|', array_map('preg_quote', array_filter(explode('|', $m[1]), 'strlen'))) . ')';
                        ++$numGroups;
                        if (null === $tplPattern) $tplPattern = $p[count($p)-1];
                    }
                    elseif (strlen($pattern[$i]))
                    {
                        $p[] = '(' . preg_quote($pattern[$i], '/') . ')';
                        ++$numGroups;
                        if (null === $tplPattern) $tplPattern = $p[count($p)-1];
                    }
                }
                $tpl[] = true;
                $isPattern = false;
            }
            else
            {
                if (strlen($pattern[$i]))
                {
                    $p[] = preg_quote($pattern[ $i ], '/');
                    $tpl[] = $pattern[$i];
                }
                $isPattern = true;
            }
        }
        if (1 === count($p) && 1 === $numGroups)
        {
            $types[0] = isset($types[1]) ? $types[1] : null;
            $pat = implode('', $p);
            return array($pat, $numGroups, $types, $tpl, $tplPattern ? $tplPattern : $pat);
        }
        else
        {
            $types[0] = null;
            $pat = '(' . implode('', $p) . ')';
            return array($pat, $numGroups+1, $types, $tpl, $tplPattern ? $tplPattern : $pat);
        }
    }

    private static function split($s, $d1, $d2 = null)
    {
        if (($d1 === $d2) || !$d2)
        {
            return explode($d1, $s);
        }
        else
        {
            $parts = array();
            $s = explode($d1, $s);
            foreach ($s as $part)
            {
                $part = explode($d2, $part);
                $parts[] = $part[0];
                if (count($part) > 1) $parts[] = $part[1];
            }
            return $parts;
        }
    }
}
Dromeo::$TYPES['INTEGER']   = array('Dromeo','type_to_int');
Dromeo::$TYPES['STRING']    = array('Dromeo','type_to_str');
Dromeo::$TYPES['URLDECODE'] = array('Dromeo','type_to_urldecode');
Dromeo::$TYPES['ARRAY']     = array('Dromeo','type_to_array');
Dromeo::$TYPES['PARAMS']    = array('Dromeo','type_to_params');
// aliases
Dromeo::$TYPES['INT']       = Dromeo::$TYPES['INTEGER'];
Dromeo::$TYPES['STR']       = Dromeo::$TYPES['STRING'];
Dromeo::$TYPES['VAR']       = Dromeo::$TYPES['URLDECODE'];
Dromeo::$TYPES['URLENCODED']= Dromeo::$TYPES['PARAMS'];
}