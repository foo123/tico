<?php
/**
*  Importer
*  a simple loader manager for classes and assets with dependencies for PHP, Python, Node.js / Browser / XPCOM Javascript
*
*  @version 1.1.4
*  https://github.com/foo123/Importer
**/
if ( !class_exists('Importer', false) )
{
function __importer_include_file__( $file, $require=false )
{
    // isolate included file from $this and other variables of importer class
    if ( $require )
        require_once($file);
    else
        @include($file);
}

class Importer
{
    const VERSION = '1.1.4';

    const D_S = '/';
    const DS_RE = '/\\/|\\\\/';
    const PROTOCOL = '://';
    const PROTOCOL_RE = '#PROTOCOL#';

    public static $BASE = './';
    protected static $DS = '/';

    // simulate python's "startswith" string method
    public static function startsWith( $str, $pre, $pos=0 )
    {
        return (bool)($pos === strpos($str, $pre, $pos));
        //return (bool)($pre === substr($str, $pos, strlen($pre)));
    }

    public static function remove_protocol( $p )
    {
        return str_replace( self::PROTOCOL, self::PROTOCOL_RE, $p );
    }

    public static function add_protocol( $p )
    {
        return str_replace( self::PROTOCOL_RE, self::PROTOCOL, $p );
    }

    // adapted from https://github.com/JosephMoniz/php-path
    public static function join_path( )
    {
        $args = func_get_args( );
        $argslen = count( $args );
        $DS = self::$DS; //DIRECTORY_SEPARATOR;

        if ( !$argslen )  return ".";

        // take care of protocol, if exists
        $path = implode( $DS, array_map( array(__CLASS__, 'remove_protocol'), $args ) );
        $plen = strlen( $path );

        if ( !$plen ) return ".";

        $isAbsolute    = $path[0];
        $trailingSlash = $path[$plen - 1];

        $peices = array_values( array_filter( preg_split( self::DS_RE, $path ), 'strlen' ) );

        $new_path = array( );
        $up = 0;
        $i = count($peices)-1;
        while ( $i >= 0 )
        {
            $last = $peices[ $i ];
            if ( ".." === $last )
            {
                $up++;
            }
            elseif ( "." !== $last )
            {
                if ( $up )  $up--;
                else  array_push( $new_path, $peices[ $i ] );
            }
            $i--;
        }

        $path = implode( $DS, array_reverse($new_path) );

        if ( !$path && !$isAbsolute )
        {
            $path = ".";
        }

        if ( $path && $trailingSlash === $DS )
        {
            $path .= $DS;
        }

        return ($isAbsolute === $DS ? $DS : "") . self::add_protocol( $path );
    }

    public static function join_path_url( )
    {
        $_DS = self::$DS;
        self::$DS = '/';
        $args = func_get_args( );
        $ret = call_user_func_array(array(__CLASS__,'join_path'), $args);
        self::$DS = $_DS;
        return $ret;
    }

    public static function attributes( $atts )
    {
        if ( empty($atts) ) return '';
        $out = array();
        foreach($atts as $k=>$v) $out[] = "{$k}=\"{$v}\"";
        return implode(' ', $out);
    }

    protected $base = null;
    protected $base_url = null;
    protected $_namespaces = null;
    protected $_namespaces0 = null;
    protected $_classmap = null;
    protected $_classes = null;
    protected $_assets = null;
    protected $_hooks = null;
    protected $_autoloader = 0;
    protected $_require = false;

    public static function _( $base='', $base_url='' )
    {
        return new self( $base, $base_url );
    }

    public function __construct( $base='', $base_url='' )
    {
        $this->_namespaces = array( '__global__'=>array( ) );
        $this->_namespaces0 = array( '__global__'=>array( ) );
        $this->_classmap = array( '__global__'=>array( ) );
        $this->_classes = array( '__global__'=>array( ) );
        $this->_assets = array( '__global__'=>array( ) );
        $this->_hooks = array( '__global__'=>array( ) );
        $this->_autoloader = 0;
        $this->_require = false;
        $this->base = '';
        $this->base_url = '';
        $this->base_path( $base, $base_url );
    }

    public function __destruct( )
    {
        $this->dispose( );
    }

    public function dispose( )
    {
        $this->unregister_autoload();
        $this->_namespaces = null;
        $this->_namespaces0 = null;
        $this->_classmap = null;
        $this->_classes = null;
        $this->_assets = null;
        $this->_hooks = null;
        $this->base = null;
        $this->base_url = null;
        $this->_require = null;
        $this->_autoloader = null;
        return $this;
    }

    public function auto_require( $enable )
    {
        $this->_require = (bool)$enable;
        return $this;
    }

    public function on( $hook, $handler, $ctx='__global__', $once=false )
    {
        if ( !empty($hook) && !empty($ctx) && is_callable($handler) )
        {
            if ( !isset($this->_hooks[$ctx]) ) $this->_hooks[$ctx] = array();
            if ( !isset($this->_hooks[$ctx][$hook]) ) $this->_hooks[$ctx][$hook] = array();
            $this->_hooks[$ctx][$hook][] = array($handler, true === $once, 0);
        }
        return $this;
    }

    public function one( $hook, $handler, $ctx='__global__' )
    {
        return $this->on( $hook, $handler, $ctx, true );
    }

    public function off( $hook, $handler, $ctx='__global__' )
    {
        if ( !empty($hook) && !empty($ctx) && !empty($this->_hooks[$ctx][$hook]) )
        {
            if ( true === $handler )
            {
                unset($this->_hooks[$ctx][$hook]);
            }
            elseif ( $handler )
            {
                $hooks =& $this->_hooks[$ctx][$hook];
                for($i=count($hooks)-1; $i>=0; $i--)
                {
                    if ( $handler === $hooks[$i][0] )
                        array_splice( $hooks, $i, 1 );
                }
            }
        }
        return $this;
    }

    public function trigger( $hook, $args=array(), $ctx='__global__' )
    {
        if ( !empty($ctx) && !empty($hook) && !empty($this->_hooks[$ctx][$hook]) )
        {
            $hooks =& $this->_hooks[$ctx][$hook];
            $args = (array)$args;
            foreach($hooks as $i=>&$h)
            {
                if ( $h[1] && $h[2] ) continue;
                $h[2] = 1; // called;
                $ret = call_user_func_array( $h[0], $args );
                if ( false === $ret ) break;
            }
            // remove called oneoffs
            for($i=count($hooks)-1; $i>=0; $i--)
            {
                if ( $hooks[$i][1] && $hooks[$i][2] )
                    array_splice( $hooks, $i, 1 );
            }
        }
        return $this;
    }

    public function base_path( $base='', $base_url='' )
    {
        if ( is_string( $base ) && !empty( $base ) ) $this->base = $base;
        elseif ( false === $base ) $this->base = '';

        if ( is_string( $base_url ) && !empty( $base_url ) ) $this->base_url = $base_url;
        elseif ( false === $base_url ) $this->base_url = '';

        return $this;
    }

    public function get_path( $path, $base='', $url=false )
    {
        if ( empty($path) ) return $base;

        elseif ( !empty($base) &&
            (self::startsWith($path, './') ||
                self::startsWith($path, '../') ||
                self::startsWith($path, '.\\') ||
                self::startsWith($path, '..\\'))
        )
            return true === $url ? self::join_path_url( $base, $path ) : self::join_path( $base, $path );

        else return $path;
    }

    public function path( $asset='' )
    {
        return $this->get_path( $asset, $this->base );
    }

    public function path_url( $asset='' )
    {
        return $this->get_path( $asset, $this->base_url, true );
    }

    public function register( $what, $defs, $ctx='__global__' )
    {
        if ( null == $ctx ) $ctx = '__global__';
        $what = strtolower((string)$what);
        if ( !empty($ctx) && is_array( $defs ) && !empty( $defs ) )
        {
            if ( ('psr-0' === $what) || ('namespaces0' === $what) )
            {
                if ( !isset($this->_namespaces0[$ctx]) ) $this->_namespaces0[$ctx] = array();
                foreach($defs as $namespace=>$path)
                {
                    $first = $namespace[0];
                    if ( !isset($this->_namespaces0[$ctx][$first]) )
                        $this->_namespaces0[$ctx][$first] = array();
                    //if ( '\\' !== substr($namespace, -1) ) $namespace .= '\\';
                    $path = is_callable($path) ? $path : (rtrim($this->path($path), '/\\') . DIRECTORY_SEPARATOR);
                    $this->_namespaces0[$ctx][$first][] = array($namespace, $path);
                }
            }
            elseif ( ('psr-4' === $what) || ('namespaces' === $what) )
            {
                if ( !isset($this->_namespaces[$ctx]) ) $this->_namespaces[$ctx] = array();
                foreach($defs as $namespace=>$path)
                {
                    $first = $namespace[0];
                    if ( !isset($this->_namespaces[$ctx][$first]) )
                        $this->_namespaces[$ctx][$first] = array();
                    if ( '\\' !== substr($namespace, -1) ) $namespace .= '\\';
                    $path = is_callable($path) ? $path : (rtrim($this->path($path), '/\\') . DIRECTORY_SEPARATOR);
                    $this->_namespaces[$ctx][$first][] = array($namespace, $path);
                }
            }
            elseif ( 'classes' === $what )
            {
                if ( !isset( $defs[0] ) || !is_array( $defs[0] ) ) $defs = array($defs); // make array of arrays
                if ( !isset($this->_classes[$ctx]) ) $this->_classes[$ctx] = array();
                if ( !isset($this->_classmap[$ctx]) ) $this->_classmap[$ctx] = array();
                foreach ($defs as $def)
                {
                    /* 0:class, 1:id, 2:path, 3:deps */
                    $classname = $def[0]; $id = $def[1]; $path = $def[2]; $deps = isset($def[3]) ? $def[3] : array();
                    if ( !empty( $classname ) && !empty( $id ) && !empty( $path ) )
                    {
                        $path = $this->path( $path );
                        $this->_classes[$ctx][ $id ] = array(
                            /* 0:class, 1:id, 2:path, 3:deps, 4:loaded */
                            $classname,
                            $id,
                            $path,
                            (array)$deps,
                            false
                        );
                        $this->_classmap[$ctx][ $classname ] = array($path, $id);
                    }
                }
            }
            elseif ( 'assets' === $what )
            {
                if ( !isset( $defs[0] ) || !is_array( $defs[0] ) ) $defs = array($defs); // make array of arrays
                if ( !isset($this->_assets[$ctx]) ) $this->_assets[$ctx] = array();
                foreach ($defs as $def)
                {
                    /* 0:type, 1:id, 2:asset, 3:deps, 4:extra props */
                    $type = $def[0]; $id = $def[1]; $asset = $def[2]; $deps = isset($def[3]) ? $def[3] : array();
                    $props = isset($def[4]) ? $def[4] : array();
                    if ( !empty( $type ) && !empty( $id ) && !empty( $asset ) )
                    {
                        $type = strtolower($type);
                        if ( 'scripts-composite' === $type || 'styles-composite' === $type || 'scripts-alt' === $type || 'styles-alt' === $type )
                        {
                            $asset = (array)$asset;
                        }
                        // maybe literal asset
                        elseif ( is_string( $asset ) )
                        {
                            $asset = $this->path_url( $asset );
                        }
                        $this->_assets[$ctx][ $id ] = array(
                            /* 0:type, 1:id, 2:asset, 3:deps, 4:props, 5:enqueued, 6:loaded */
                            $type, $id, $asset, (array)$deps, (array)$props, false, false
                        );
                    }
                }
            }
        }
        return $this;
    }

    protected function import_class( $id, $ctx='__global__', $require=null )
    {
        if ( null == $ctx ) $ctx = '__global__';
        $queue = array( $id );
        while ( !empty( $queue ) )
        {
            $id = $queue[0];
            $ctx2 = isset( $this->_classes[$ctx][$id] ) ? $ctx : '__global__';
            if ( isset( $this->_classes[$ctx2][$id] ) && !$this->_classes[$ctx2][$id][4] )
            {
                $classname = $this->_classes[$ctx2][$id][0];
                $loaded = class_exists( $classname, false ) || interface_exists( $classname, false );
                if ( !$loaded && version_compare(PHP_VERSION, '5.4.0', '>=') )
                    $loaded = $loaded || trait_exists( $classname, false );

                if ( !$loaded )
                {
                    $deps = $this->_classes[$ctx2][$id][3];
                    if ( !empty( $deps ) )
                    {
                        $needs_deps = false;
                        $numdeps = count($deps);
                        for ($i=$numdeps-1; $i>=0; $i--)
                        {
                            $dep = $deps[$i];
                            $ctx3 = isset( $this->_classes[$ctx][$dep] ) ? $ctx : '__global__';
                            if ( isset( $this->_classes[$ctx3][$dep] ) && !$this->_classes[$ctx3][$dep][4] )
                            {
                                $needs_deps = true;
                                array_unshift( $queue, $dep );
                            }
                        }
                        if ( $needs_deps ) continue;
                        else array_shift( $queue );
                    }
                    else
                    {
                        array_shift( $queue );
                    }
                    $this->_classes[$ctx2][$id][4] = true; // loaded

                    __importer_include_file__($this->_classes[$ctx2][$id][2], null===$require ? $this->_require : (bool)$require);

                    // hook here
                    $this->trigger("import-class", array(
                        // $importer, $id,      $classname,   $path
                        $this, $id, $this->_classes[$ctx2][$id][0], $this->_classes[$ctx2][$id][2]
                    ), $ctx)->trigger("import-class-{$id}", array(
                        // $importer, $id,      $classname,   $path
                        $this, $id, $this->_classes[$ctx2][$id][0], $this->_classes[$ctx2][$id][2]
                    ), $ctx);
                }
                else
                {
                    array_shift( $queue );
                    $this->_classes[$ctx2][$id][4] = true; // loaded
                    // trigger events, even if this class is already loaded somewhere else, but not this instance
                    // hook here
                    $this->trigger("import-class", array(
                        // $importer, $id,      $classname,   $path
                        $this, $id, $this->_classes[$ctx2][$id][0], $this->_classes[$ctx2][$id][2]
                    ), $ctx)->trigger("import-class-{$id}", array(
                        // $importer, $id,      $classname,   $path
                        $this, $id, $this->_classes[$ctx2][$id][0], $this->_classes[$ctx2][$id][2]
                    ), $ctx);
                }
            }
            else
            {
                array_shift( $queue );
            }
        }
        return $this;
    }

    protected function import_asset( $id, $ctx='__global__' )
    {
        if ( null == $ctx ) $ctx = '__global__';
        $out = array( );
        $queue = array( $id );
        while ( !empty( $queue ) )
        {
            $id = $queue[0];
            $ctx2 = isset( $this->_assets[$ctx][$id] ) ? $ctx : '__global__';
            if ( isset( $this->_assets[$ctx2][$id] ) && $this->_assets[$ctx2][$id][5] && !$this->_assets[$ctx2][$id][6] ) // enqueued but not loaded yet
            {
                $asset_def =& $this->_assets[$ctx2][$id];
                $type = $asset_def[0];
                $id = $asset_def[1];
                $asset = $asset_def[2];
                $deps = $asset_def[3];
                $props = $asset_def[4];
                if ( !empty( $deps ) )
                {
                    $needs_deps = false;
                    $numdeps = count($deps);
                    for ($i=$numdeps-1; $i>=0; $i--)
                    {
                        $dep = $deps[$i];
                        $ctx3 = isset( $this->_assets[$ctx][$dep] ) ? $ctx : '__global__';
                        if ( isset( $this->_assets[$ctx3][$dep] ) && !$this->_assets[$ctx3][$dep][6] )
                        {
                            $this->_assets[$ctx3][$dep][5] = true; // enqueued
                            $needs_deps = true;
                            array_unshift( $queue, $dep );
                        }
                    }
                    if ( $needs_deps ) continue;
                    else array_shift( $queue );
                }
                else
                {
                    array_shift( $queue );
                }
                $asset_def[6] = true; // loaded

                // hook here
                $ret = array();
                $this->trigger("import-asset", array(
                    // $importer, $id,      $type,   $asset
                    $this, $id, $type, $asset, &$ret
                ), $ctx)->trigger("import-asset-{$id}", array(
                    // $importer, $id,      $type,   $asset
                    $this, $id, $type, $asset, &$ret
                ), $ctx);

                if ( isset($ret['return']) )
                {
                    $out[] = $ret['return'];
                }
                else
                {
                    $is_style = (bool)('styles' === $type || 'styles-composite' === $type || 'styles-alt' === $type);
                    $is_script = (bool)('scripts' === $type || 'scripts-composite' === $type || 'scripts-alt' === $type);
                    $is_tpl = (bool)('templates' === $type);
                    $is_composite = (bool)('scripts-composite' === $type || 'styles-composite' === $type);
                    $is_alt = (bool)('scripts-alt' === $type || 'styles-alt' === $type);
                    $is_inlined = !$is_composite && !$is_alt && is_array($asset);
                    $asset_id = preg_replace( '/[\\-.\\/\\\\:]+/', '_', $id);
                    if ( $is_style )
                    {
                        $attributes = self::attributes(array_merge(array(
                            'type'  => 'text/css',
                            'media' => 'all'
                        ), $props));

                        if ( $is_inlined )
                        {
                            $out[] = "<style id=\"importer-inline-style-{$asset_id}\" {$attributes}>{$asset[0]}</style>";
                        }
                        elseif ( $is_composite )
                        {
                            foreach($asset as $pi=>$part)
                            {
                                if ( is_array($part) )
                                {
                                    $out[] = "<style id=\"importer-inline-style-{$asset_id}-part-{$pi}\" {$attributes}>{$part[0]}</style>";
                                }
                                else
                                {
                                    $out[] = "<link id=\"importer-style-{$asset_id}-part-{$pi}\" href=\"".$this->path_url($part)."\" rel=\"stylesheet\" {$attributes} />";
                                }
                            }
                        }
                        elseif ( $is_alt )
                        {
                            $out[] = $asset[0];
                        }
                        else
                        {
                            $out[] = "<link id=\"importer-style-{$asset_id}\" href=\"".$this->path_url($asset)."\" rel=\"stylesheet\" {$attributes} />";
                        }
                    }
                    elseif ( $is_script )
                    {
                        $attributes = self::attributes(array_merge(array(
                            'type'  => 'text/javascript'
                        ), $props));

                        if ( $is_inlined )
                        {
                            $out[] = "<script id=\"importer-inline-script-{$asset_id}\" {$attributes}>/*<![CDATA[*/ {$asset[0]} /*]]>*/</script>";
                        }
                        elseif ( $is_composite )
                        {
                            foreach($asset as $pi=>$part)
                            {
                                if ( is_array($part) )
                                {
                                    $out[] = "<script id=\"importer-inline-script-{$asset_id}-part-{$pi}\" {$attributes}>/*<![CDATA[*/ {$part[0]} /*]]>*/</script>";
                                }
                                else
                                {
                                    $out[] = "<script id=\"importer-script-{$asset_id}-part-{$pi}\" src=\"".$this->path_url($part)."\" {$attributes}></script>";
                                }
                            }
                        }
                        elseif ( $is_alt )
                        {
                            $out[] = $asset[0];
                        }
                        else
                        {
                            $out[] = "<script id=\"importer-script-{$asset_id}\" src=\"".$this->path_url($asset)."\" {$attributes}></script>";
                        }
                    }
                    elseif ( $is_tpl )
                    {
                        $attributes = self::attributes(array_merge(array(
                            'type'  => 'text/x-tpl'
                        ), $props));

                        $out[] = $is_inlined
                                ? ("<script id=\"importer-inline-tpl-{$asset_id}\" {$attributes}>{$asset[0]}</script>")
                                : ("<script id=\"importer-inline-tpl-{$asset_id}\" {$attributes}>".$this->get($asset)."</script>");
                    }
                    else
                    {
                        $out[] = $is_inlined ? $asset[0] : $this->get($asset);
                    }
                }
            }
            else
            {
                array_shift( $queue );
            }
        }
        return $out;
    }

    public function assets( $type='scripts', $ctx='__global__' )
    {
        if ( null == $ctx ) $ctx = '__global__';
        if ( empty($ctx) || empty($this->_assets[$ctx]) ) return "";
        $out = array( );
        $type = strtolower($type);
        $type_composite = $type . '-composite';
        $type_alt = $type . '-alt';
        foreach ($this->_assets[$ctx] as $asset_def)
        {
            if ( ($type === $asset_def[0] || $type_composite === $asset_def[0] || $type_alt === $asset_def[0]) && $asset_def[5] && !$asset_def[6] )
                $out = array_merge($out, $this->import_asset($asset_def[1], $ctx));
        }
        return implode("\n", $out);
    }

    public function enqueue( $type, $id, $asset_def=null, $ctx='__global__' )
    {
        $asset = null; $deps = null; $props = null;
        if ( is_array($asset_def) )
        {
            $asset = isset($asset_def[0]) ? $asset_def[0] : null;
            $deps = isset($asset_def[1]) ? $asset_def[1] : null;
            $props = isset($asset_def[2]) ? $asset_def[2] : null;
        }
        else
        {
            $ctx = $asset_def;
        }
        if ( null == $ctx ) $ctx = '__global__';
        if ( !empty($ctx) && !empty( $type ) && !empty( $id ) )
        {
            $ctx2 = isset( $this->_assets[$ctx][$id] ) ? $ctx : '__global__';
            if ( isset( $this->_assets[$ctx2][$id] ) )
            {
                $this->_assets[$ctx2][$id][5] = true; // enqueued
                // hook here
                $this->trigger('enqueue-asset', array(
                    // $importer, $id,      $type,   $asset
                    $this, $id, $type, $this->_assets[$ctx2][$id][2]
                ), $ctx)->trigger("enqueue-asset-{$id}", array(
                    // $importer, $id,      $type,   $asset
                    $this, $id, $type, $this->_assets[$ctx2][$id][2]
                ), $ctx);
            }
            elseif ( !empty( $asset ) )
            {
                $this->register('assets', array($type, $id, $asset, $deps, $props), $ctx);
                $this->_assets[$ctx][$id][5] = true; // enqueued
                // hook here
                $this->trigger('enqueue-asset', array(
                    // $importer, $id,      $type,   $asset
                    $this, $id, $type, $this->_assets[$ctx][$id][2]
                ), $ctx)->trigger("enqueue-asset-{$id}", array(
                    // $importer, $id,      $type,   $asset
                    $this, $id, $type, $this->_assets[$ctx][$id][2]
                ), $ctx);
            }
        }
        return $this;
    }

    public function get( $path, $opts=array() )
    {
        $default_value = isset($opts['default']) ? $opts['default'] : '';
        if ( !empty($opts['binary']) )
        {
            $file = $this->path( $path );
            $fp = fopen( $file, "rb" );
            if ( $fp )
            {
                $data = @fread( $fp, filesize($file) );
                fclose( $fp );
            }
            else $data = $default_value;
        }
        else
        {
            $file = $this->path( $path );
            $data = is_file( $file ) ? @file_get_contents( $file ) : $default_value;
        }
        return $data;
    }

    public function load( $classname, $class_def=null, $ctx='__global__' )
    {
        if ( is_array($classname) )
        {
            $ctx = $class_def;
            if ( null == $ctx ) $ctx = '__global__';
            //$ctx = is_string($path) ? $path : '__global__';
            foreach($classname as $class)
                $this->load( $class, $ctx );
        }
        else
        {
            $path = null; $deps = null;
            if ( is_array($class_def) )
            {
                $path = isset($class_def[0]) ? $class_def[0] : null;
                $deps = isset($class_def[1]) ? $class_def[1] : null;
            }
            else
            {
                $ctx = $class_def;
            }
            if ( null == $ctx ) $ctx = '__global__';
            if ( !isset( $this->_classes[$ctx][$classname] ) && !isset( $this->_classes['__global__'][$classname] ) && !empty($path) )
                $this->register('classes', array($classname, $classname, $this->path($path), $deps), $ctx);
            $ctx2 = isset( $this->_classes[$ctx][$classname] ) ? $ctx : '__global__';
            if ( isset( $this->_classes[$ctx2][$classname] ) && !$this->_classes[$ctx2][$classname][4] && file_exists( $this->_classes[$ctx2][$classname][2] ) )
                $this->import_class($classname, $ctx2);
        }
        return $this;
    }

    private function triggerLoad($id, $class, $path, $ctx='__global__')
    {
        $this->trigger("import-class", array(
            // $importer, $id,      $classname,   $path
            $this, $id, $class, $path
        ), $ctx);

        $this->trigger("import-class-{$id}", array(
            // $importer, $id,      $classname,   $path
            $this, $id, $class, $path
        ), $ctx);

        return $this;
    }

    public function __autoload__( $class )
    {
        $ctx = '__global__'; // anyway to add custom context here??

        if ( isset($this->_classmap[$ctx][$class]) )
        {
            // try to load a simple class from classmap first, if exists
            //$this->import_class($this->_classmap[$ctx][$class][1]);
            __importer_include_file__($this->_classmap[$ctx][$class][0], $this->_require);
            // hook here
            list($path, $id) = $this->_classmap[$ctx][$class];
            $this->triggerLoad($id, $class, $path, $ctx);
            return true;
        }

        if ( '__global__' !== $ctx )
        {
            // try also the global ctx if different
            if ( isset($this->_classmap['__global__'][$class]) )
            {
                // try to load a simple class from classmap first, if exists
                //$this->import_class($this->_classmap['__global__'][$class][1]);
                __importer_include_file__($this->_classmap['__global__'][$class][0], $this->_require);
                // hook here
                list($path, $id) = $this->_classmap['__global__'][$class];
                $this->triggerLoad($id, $class, $path, '__global__');
                return true;
            }
        }

        $first = $class[0];
        // Psr-4 lookup
        $logicalPathPsr4 = strtr($class, '\\', DIRECTORY_SEPARATOR) . '.php';
        // Psr-4
        $namespaces = !empty($this->_namespaces[$ctx][$first]) ? $this->_namespaces[$ctx][$first] : null;
        if ( $namespaces )
        {
            foreach($namespaces as $namespace)
            {
                if ( 0 === strpos($class, $namespace[0]) )
                {
                    if ( is_callable($namespace[1]) )
                    {
                        $ret = call_user_func($namespace[1], $class);
                        $loaded = true === $ret || class_exists( $class, false ) || interface_exists( $class, false );
                        if ( !$loaded && version_compare(PHP_VERSION, '5.4.0', '>=') )
                            $loaded = $loaded || trait_exists( $class, false );
                        if ( $loaded )
                        {
                            $this->triggerLoad($class, $class, '', $ctx);
                            return true;
                        }
                    }
                    else
                    {
                        $file = $namespace[1] . str_replace('\\', DIRECTORY_SEPARATOR, substr($class, strlen($namespace[0]))) . '.php';
                        if ( file_exists($file) )
                        {
                            __importer_include_file__($file, $this->_require);
                            $this->triggerLoad($class, $class, $file, $ctx);
                            return true;
                        }
                    }
                }
            }
        }
        // Psr-0 lookup
        if ( false !== ($pos=strrpos($class, '\\')) )
        {
            // namespaced class name
            $logicalPathPsr0 = substr($logicalPathPsr4, 0, $pos + 1).strtr(substr($logicalPathPsr4, $pos + 1), '_', DIRECTORY_SEPARATOR);
        }
        else
        {
            // PEAR-like class name
            $logicalPathPsr0 = strtr($class, '_', DIRECTORY_SEPARATOR) . '.php';
        }
        // Psr-0
        $namespaces = !empty($this->_namespaces0[$ctx][$first]) ? $this->_namespaces0[$ctx][$first] : null;
        if ( $namespaces )
        {
            foreach($namespaces as $namespace)
            {
                if ( 0 === strpos($class, $namespace[0]) )
                {
                    if ( is_callable($namespace[1]) )
                    {
                        $ret = call_user_func($namespace[1], $class);
                        $loaded = true === $ret || class_exists( $class, false ) || interface_exists( $class, false );
                        if ( !$loaded && version_compare(PHP_VERSION, '5.4.0', '>=') )
                            $loaded = $loaded || trait_exists( $class, false );
                        if ( $loaded )
                        {
                            $this->triggerLoad($class, $class, '', $ctx);
                            return true;
                        }
                    }
                    else
                    {
                        $file = $namespace[1] . $logicalPathPsr0;
                        if ( file_exists($file) )
                        {
                            __importer_include_file__($file, $this->_require);
                            $this->triggerLoad($class, $class, $file, $ctx);
                            return true;
                        }
                    }
                }
            }
        }

        if ( '__global__' !== $ctx )
        {
            // if ctx different from global, try global ctx also
            // Psr-4
            $namespaces = !empty($this->_namespaces['__global__'][$first]) ? $this->_namespaces['__global__'][$first] : null;
            if ( $namespaces )
            {
                foreach($namespaces as $namespace)
                {
                    if ( 0 === strpos($class, $namespace[0]) )
                    {
                        if ( is_callable($namespace[1]) )
                        {
                            $ret = call_user_func($namespace[1], $class);
                            $loaded = true === $ret || class_exists( $class, false ) || interface_exists( $class, false );
                            if ( !$loaded && version_compare(PHP_VERSION, '5.4.0', '>=') )
                                $loaded = $loaded || trait_exists( $class, false );
                            if ( $loaded )
                            {
                                $this->triggerLoad($class, $class, '', '__global__');
                                return true;
                            }
                        }
                        else
                        {
                            $file = $namespace[1] . str_replace('\\', DIRECTORY_SEPARATOR, substr($class, strlen($namespace[0]))) . '.php';
                            if ( file_exists($file) )
                            {
                                __importer_include_file__($file, $this->_require);
                                $this->triggerLoad($class, $class, $file, '__global__');
                                return true;
                            }
                        }
                    }
                }
            }
            // Psr-0
            $namespaces = !empty($this->_namespaces0['__global__'][$first]) ? $this->_namespaces0['__global__'][$first] : null;
            if ( $namespaces )
            {
                foreach($namespaces as $namespace)
                {
                    if ( 0 === strpos($class, $namespace[0]) )
                    {
                        if ( is_callable($namespace[1]) )
                        {
                            $ret = call_user_func($namespace[1], $class);
                            $loaded = true === $ret || class_exists( $class, false ) || interface_exists( $class, false );
                            if ( !$loaded && version_compare(PHP_VERSION, '5.4.0', '>=') )
                                $loaded = $loaded || trait_exists( $class, false );
                            if ( $loaded )
                            {
                                $this->triggerLoad($class, $class, '', '__global__');
                                return true;
                            }
                        }
                        else
                        {
                            $file = $namespace[1] . $logicalPathPsr0;
                            if ( file_exists($file) )
                            {
                                __importer_include_file__($file, $this->_require);
                                $this->triggerLoad($class, $class, $file, '__global__');
                                return true;
                            }
                        }
                    }
                }
            }
        }
    }

    public function register_autoload( $prepend=false )
    {
        if ( 1 > $this->_autoloader )
        {
            if ( version_compare(PHP_VERSION, '5.3.0', '>=') )
            {
                spl_autoload_register(array($this, '__autoload__'), true, $prepend);
            }
            else
            {
                spl_autoload_register(array($this, '__autoload__'));
            }
            $this->_autoloader++;
        }
        return $this;
    }

    public function unregister_autoload( )
    {
        if ( 0 < $this->_autoloader )
        {
            spl_autoload_unregister(array($this, '__autoload__'));
            $this->_autoloader--;
        }
        return $this;
    }
}
Importer::$BASE = dirname(__FILE__);
}
