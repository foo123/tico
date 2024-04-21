<?php
/**
*   CacheManager
*   Simple, barebones cache manager for PHP, JavaScript, Python
*
*   @version 1.0.0
*   https://github.com/foo123/CacheManager
*
**/

if (!class_exists('CacheManager', false))
{
class CacheManagerException extends Exception
{
    public function __construct($message = "", $code = 0, $previous = null)
    {
        parent::__construct($message, $code, $previous);
    }
}
class CacheManager
{
    const VERSION = '1.0.0';

    private $opts = null;

    public function __construct()
    {
        $this->opts = array();
        // some default options
        $this->option('get_key', null);
        $this->option('set_key', null);
        $this->option('del_key', null);
        $this->option('cache_dur_sec', 1 * 24 * 60 * 60/*1 day in seconds*/);
        $this->option('cache_dir', '');
        $this->option('separator', '!');
        $this->option('salt', '');
    }

    public function option($key, $val = null)
    {
        $nargs = func_num_args();
        if (1 == $nargs)
        {
            return isset($this->opts[$key]) ? $this->opts[$key] : null;
        }
        elseif (1 < $nargs)
        {
            $this->opts[$key] = $val;
        }
        return $this;
    }

    public function get($key)
    {
        $getter = $this->option('get_key');
        $cache_dir = $this->option('cache_dir');
        if (is_callable($getter))
        {
            return call_user_func($getter, $key);
        }
        elseif (!empty($cache_dir) /*&& file_exists($cache_dir)*/)
        {
            $file = $cache_dir . DIRECTORY_SEPARATOR . $this->hmac($key);
            try {
                $data = @file_get_contents($file);
            } catch(Exception $e) {
                $data = false;
            }
            if (false !== $data)
            {
                $separator = $this->option('separator');
                $sep = strpos($data, $separator, 0);
                if (false !== $sep)
                {
                    $expiration = substr($data, 0, $sep);
                    if (time() <= intval($expiration))
                    {
                        $content = substr($data, $sep+strlen($separator));
                        return $content;
                    }
                }
            }
        }
        return null;
    }

    public function set($key, $content)
    {
        $setter = $this->option('set_key');
        $cache_dir = $this->option('cache_dir');
        $duration = $this->option('cache_dur_sec');
        if (is_callable($setter))
        {
            return call_user_func($setter, $key, $content, $duration);
        }
        elseif (!empty($cache_dir) /*&& file_exists($cache_dir)*/)
        {
            $file = $cache_dir . DIRECTORY_SEPARATOR . $this->hmac($key);
            $separator = $this->option('separator');
            try {
                $res = @file_put_contents($file, ((string)(time()+$duration)).$separator.$content);
            } catch(Exception $e) {
                $res = false;
            }
            return false !== $res;
        }
        return false;
    }

    public function del($key)
    {
        $deleter = $this->option('del_key');
        $cache_dir = $this->option('cache_dir');
        if (is_callable($deleter))
        {
            return call_user_func($deleter, $key);
        }
        elseif (!empty($cache_dir) /*&& file_exists($cache_dir)*/)
        {
            $file = $cache_dir . DIRECTORY_SEPARATOR . $this->hmac($key);
            try {
                $res = @unlink($file);
            } catch(Exception $e) {
                $res = false;
            }
            return false !== $res;
        }
        return false;
    }

    private function hmac($key)
    {
        $salt = $this->option('salt');
        return hash_hmac('md5', $key, (string)($salt ? $salt : ''));
    }
}
}