<?php
/**
*
*   Dromeo
*   Simple and Flexible Pattern Routing Framework for PHP, JavaScript, Python
*   @version: 1.3.0
*
*   https://github.com/foo123/Dromeo
*
**/
if (!class_exists('Dromeo', false))
{
class DromeoException extends Exception
{
}
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
        for ($i=0,$l=count($tpl); $i<$l; ++$i)
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
                        throw new DromeoException('Dromeo: Route "'.$this->name.'" (Pattern: "'.$this->route.'") missing parameter "'.$tpl[$i]->name.'"!');
                    }
                }
                else
                {
                    $param = $params[$tpl[$i]->name];
                    if (!is_array($param)) $param = array($param);
                    $param = array_map('strval', $param);
                    if ($strict && !preg_match($tpl[$i]->re, $param[0], $m))
                    {
                        throw new DromeoException('Dromeo: Route "'.$this->name.'" (Pattern: "'.$this->route.'") parameter "'.$tpl[$i]->name.'" value "'.$param[0].'" does not match pattern!');
                    }
                    $part = $tpl[$i]->tpl;
                    for ($j=0,$p=0,$k=count($part); $j<$k; ++$j)
                    {
                        if (true === $part[$j])
                        {
                            $out .= (isset($param[$p]) ? $param[$p] : $param[0]);
                            ++$p;
                        }
                        else
                        {
                            $out .= $part[$j];
                        }
                    }
                }
            }
        }
        return $out;
    }

    public function sub($match, &$data, $type = null, $getter = null)
    {
        if (!$this->isParsed || $this->literal) return $this;
        $givenInput = is_array($match[0]) ? $match[0][0] : $match[0];
        $hasGetter = is_callable($getter);
        $captures = array();
        foreach ($this->captures as $v => $g)
        {
            $captures[] = array($v, $g);
        }
        usort($captures, function($a, $b) use ($match) {
            return (is_array($match[$a[1][0]]) && is_array($match[$b[1][0]])) ? ($match[$a[1][0]][1]-$match[$b[1][0]][1]) : ($a[1][0]-$b[1][0]);
        });
        foreach ($captures as $cap)
        {
            $v = $cap[0]; $g = $cap[1];
            $groupIndex = $g[0];
            $groupTypecaster = $g[1];
            if (isset($match[$groupIndex]) && $match[$groupIndex])
            {
                if (is_array($match[$groupIndex]))
                {
                    if (!strlen($match[$groupIndex][0])) continue;
                    $matchedValue = $match[$groupIndex][0];
                    if ($hasGetter)
                    {
                        // if getter is given,
                        // get true match from getter (eg with original case)
                        $matchedValueTrue = strval(call_user_func($getter, $v, $matchedValue, $match[$groupIndex][1], $match[$groupIndex][1]+strlen($matchedValue), $givenInput));
                    }
                    else
                    {
                        // else what matched
                        $matchedValueTrue = $matchedValue;
                    }
                }
                else
                {
                    if (!strlen($match[$groupIndex])) continue;
                    $matchedValue = $match[$groupIndex];
                    $matchedValueTrue = $matchedValue;
                }

                if ($type && isset($type[$v]))
                {
                    $typecaster = $type[$v];
                    if (is_string($typecaster) && isset(Dromeo::$TYPES[$typecaster]))
                        $typecaster = Dromeo::$TYPES[$typecaster];
                    $data[$v] = is_callable($typecaster) ? call_user_func($typecaster, $matchedValueTrue) : $matchedValueTrue;
                }
                elseif ($groupTypecaster)
                {
                    $typecaster = $groupTypecaster;
                    $data[$v] = is_callable($typecaster) ? call_user_func($typecaster, $matchedValueTrue) : $matchedValueTrue;
                }
                else
                {
                    $data[$v] = $matchedValueTrue;
                }
            }
            elseif (!isset($data[$v]))
            {
                $data[$v] = null;
            }
        }
        return $this;
    }
}

class Dromeo
{
    const VERSION = "1.3.0";

    private static $_patternOr = '/^([^|]+(\\|[^|]+)+)$/';
    private static $_group = '/\\((\\d+)\\)$/';

    private $_delims = null;
    private $_patterns = null;
    private $_routes = null;
    private $_named_routes = null;
    private $_fallback = false;
    private $_prefix = '';
    private $_top = null;
    public  $key = '';

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
    public static function _($prefix = '', $group = '', $top = null)
    {
        return new self($prefix, $group, $top);
    }

    public function __construct($prefix = '', $group = '', $top = null)
    {
        $this->_delims = array('{', '}', '%', '%', ':');
        $this->_patterns = array();
        $this->definePattern('ALPHA',      '[a-zA-Z\\-_]+');
        $this->definePattern('ALNUM',      '[a-zA-Z0-9\\-_]+');
        $this->definePattern('ASCII',      '[ -~]+');
        $this->definePattern('NUMBR',      '[0-9]+');
        $this->definePattern('INT',        '[0-9]+',          'INT');
        $this->definePattern('PART',       '[^\\/?#]+');
        $this->definePattern('VAR',        '[^=?&#\\/]+',     'VAR');
        $this->definePattern('QUERY',      '\\?[^?#]+');
        $this->definePattern('FRAGMENT',   '#[^?#]+');
        $this->definePattern('URLENCODED', '[^\\/?#]+',       'URLENCODED');
        $this->definePattern('ALL',        '.+');
        $this->definePattern('ANY',        '[\\s\\S]+');
        $this->_routes = array();
        $this->_named_routes = array();
        $this->_fallback = false;
        $this->_top = $top instanceof Dromeo ? $top : $this;
        $this->key = $this === $this->_top ? '' : ($this->_top->key . (string)$group);
        $this->_prefix = (string)$prefix;
    }

    public function __destruct()
    {
        $this->dispose();
    }

    public function dispose()
    {
        $this->_top = null;
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

    public function top()
    {
        return $this->_top;
    }

    public function isTop()
    {
        return (null === $this->_top) || ($this === $this->_top);
    }

    public function clone($group = '')
    {
        $cloned = new self($this->_prefix, $group, $this);
        $cloned->defineDelimiters($this->_delims);
        foreach ($this->_patterns as $className => $args)
        {
            $cloned->definePattern($className, $args[0], isset($args[1]) ? $args[1] : null);
        }
        return $cloned;
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

    public function onGroup($groupRoute, $handler)
    {
        $groupRoute = (string)$groupRoute;
        if (strlen($groupRoute) && is_callable($handler))
        {
            $groupRouter = $this->clone($groupRoute);
            $this->_routes[] = $groupRouter;
            call_user_func($handler, $groupRouter);
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
        foreach ($routes as $route)
        {
            $this->insertRoute($route, false);
        }
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
        foreach ($routes as $route)
        {
            $this->insertRoute($route, true);
        }
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
                if ($rt instanceof Dromeo)
                {
                    $rt->off($route, $handler, $method);
                }
                else
                {
                    if ($key === $rt->key)
                    {
                        $r = $rt;
                        break;
                    }
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
                {
                    $this->clearRoute($key);
                }
            }
            else
            {
                $this->clearRoute($key);
            }
        }
        elseif (is_string($route) && strlen($route))
        {
            $route = (string)$route;
            $key = DromeoRoute::to_key($route, self::to_method($method));
            $r = null;
            foreach ($this->_routes as $index => $rt)
            {
                if ($rt instanceof Dromeo)
                {
                    if ($route === $rt->key)
                    {
                        $r = $rt;
                        break;
                    }
                    else
                    {
                        $rt->off($route, $handler, $method);
                    }
                }
                else
                {
                    if ($key === $rt->key)
                    {
                        $r = $rt;
                        break;
                    }
                }
            }
            if (!$r) return $this;

            if ($r instanceof Dromeo)
            {
                array_splice($this->_routes, $index, 1);
                $r->dispose();
            }
            else
            {
                if ($handler && is_callable($handler))
                {
                    $l = count($r->handlers);
                    for ($i=$l-1; $i>=0; --$i)
                    {
                        if ($handler === $r->handlers[$i]->handler)
                            array_splice($r->handlers, $i, 1);
                    }
                    if (empty($r->handlers))
                    {
                        $this->clearRoute($key);
                    }
                }
                else
                {
                    $this->clearRoute($key);
                }
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

    public function route($r, $method = "*", $breakOnFirstMatch = true, $getter = null)
    {
        if (!$this->isTop() && empty($this->_routes)) return false;
        $proceed = true;
        $found = false;
        $r = (string)$r;
        $prefix = $this->_prefix . $this->key;
        if (strlen($prefix))
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
                if ($route instanceof Dromeo)
                {
                    // group router
                    $match = $route->route($r, $method, $breakOnFirstMatch, $getter);
                    if (!$match) continue;
                    $found = true;
                }
                else
                {
                    // simple route
                    $match = $route->match($r, $method);
                    if (!$match) continue;
                    $found = true;

                    // copy handlers avoid mutation during calls
                    // is this shallow or deep copy???
                    // since using objects as array items, it should be shallow
                    $handlers = array_merge(array(), $route->handlers);

                    // make calls
                    $to_remove = array();
                    foreach ($handlers as $index => &$handler)
                    {
                        // handler is oneOff and already called
                        if ($handler->oneOff && $handler->called)
                        {
                            array_unshift($to_remove, $index);
                            continue;
                        }

                        // get params
                        $params = array(
                            'route'=> $r,
                            'method'=> $method,
                            'pattern'=> $route->route,
                            'fallback'=> false,
                            'data'=> array_merge_recursive(array(), $handler->defaults)
                        );
                        $route->sub($match, $params['data'], $handler->types, $getter);

                        $handler->called = 1; // handler called
                        if ($handler->oneOff) array_unshift($to_remove, $index);
                        call_user_func($handler->handler, $params);
                    }

                    // remove called oneOffs
                    foreach ($to_remove as $index)
                    {
                        array_splice($route->handlers, $index, 1);
                    }
                    if (empty($route->handlers))
                    {
                        $this->clearRoute($route->key);
                    }
                }
                if ($breakOnFirstMatch) return true;
            }
            if ($found) return true;
        }

        if ($this->_fallback && $this->isTop())
        {
            call_user_func($this->_fallback, array(
                'route'=> $r,
                'method'=> $method,
                'pattern'=> null,
                'fallback'=> true,
                'data'=> null
            ));
        }
        return false;
    }

    public function _addNamedRoute($route)
    {
        if ($this->isTop())
        {
            if (($route instanceof DromeoRoute) && $route->name && strlen($route->name))
            {
                $this->_named_routes[$route->name] = $route;
            }
        }
        else
        {
            $this->top()->_addNamedRoute($route);
        }
        return $this;
    }

    public function _delNamedRoute($route)
    {
        if ($this->isTop())
        {
            if (($route instanceof DromeoRoute) && $route->name && isset($this->_named_routes[$route->name]))
            {
                unset($this->_named_routes[$route->name]);
            }
        }
        else
        {
            $this->top()->_delNamedRoute($route);
        }
        return $this;
    }

    private function insertRoute($route, $oneOff = false)
    {
        if (
            is_array($route) && isset($route['route']) && is_string($route['route']) /*&& strlen($route['route'])*/ &&
            isset($route['handler']) && is_callable($route['handler'])
        )
        {
            $oneOff = (true === $oneOff);
            $handler = $route['handler'];
            $defaults = isset($route['defaults']) ? (array)$route['defaults'] : array();
            $types = isset($route['types']) ? (array)$route['types'] : array();
            $name = isset($route['name']) ? (string)$route['name'] : null;
            $method = self::to_method(isset($route['method']) ? $route['method'] : null);

            $route = $this->key . (string)$route['route'];
            $key = DromeoRoute::to_key($route, $method);

            $routeInstance = null;
            foreach ($this->_routes as &$rt)
            {
                if ($key === $rt->key)
                {
                    $routeInstance = $rt;
                    break;
                }
            }
            if (null === $routeInstance)
            {
                $routeInstance = new DromeoRoute($this->_delims, $this->_patterns, $route, $method, $name, $this->_prefix);
                $this->_routes[] = $routeInstance;
                $this->_addNamedRoute($routeInstance);
            }
            $routeInstance->handlers[] = (object)array(
                'handler'=> $handler,
                'defaults'=> $defaults,
                'types'=> $types,
                'oneOff'=> $oneOff,
                'called'=> 0
            );
        }
    }

    private function clearRoute($key)
    {
        for ($i=count($this->_routes)-1; $i>=0; --$i)
        {
            if ($key === $this->_routes[$i]->key)
            {
                $route = $this->_routes[$i];
                array_splice($this->_routes, $i, 1);
                $this->_delNamedRoute($route);
                $route->dispose();
            }
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
        {
            $pattern .= preg_quote($prefix, '/');
        }

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
                if (!strlen(trim($p[0])))
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
                        if ($captureIndex > 0 && $captureIndex < $capturePattern[1])
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
                        $p[] = '(' . implode('|', array_map('preg_quote', array_filter(explode('|', $m[1]), 'strlen'))) . ')';
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
                    $p[] = preg_quote($pattern[$i], '/');
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