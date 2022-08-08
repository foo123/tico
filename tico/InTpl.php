<?php
/**
*
* InTpl: simple php templates supporting template inheritance
* @version 1.1.2
* https://github.com/foo123/InTpl
*
**/

if ( !class_exists('InTpl', false) )
{
class InTpl
{
    const VERSION = '1.1.2';

    private $_super = null;
    private $_sprout = null;
    private $_blocks = null;

    public $tplDirs = array();
    public $blocks = null;
    public $tpl = null;
    public $found = null;
    public $data = null;

    public static function Tpl($tpl, $tplDirs = array())
    {
        return $tpl instanceof InTpl ? $tpl : new InTpl($tpl, $tplDirs);
    }

    public function __construct($tpl, $tplDirs = array())
    {
        $this->tpl = is_array($tpl) ? $tpl : (string) $tpl;
        $this->_super = null;
        $this->_sprout = null;
        $this->_blocks = array();
        $this->blocks = array();
        $this->data = array();
        $this->tplDirs = (array) $tplDirs;
        $this->found = null;
    }

    public function findTpl($tpl, $dirs = array())
    {
        $found = false;
        $filename = ltrim($tpl, '/\\');
        foreach ($dirs as $dir)
        {
            $dir = rtrim($dir, '/\\');
            $path = $dir . DIRECTORY_SEPARATOR . $filename;
            if (file_exists($path))
            {
                $found = $path;
                break;
            }
        }
        return $found;
    }

    public function super()
    {
        if ($this->_super && (null === $this->_sprout))
        {
            // need to parse/render super tpl here early
            // in order to have access to $this->super()->block(..) calls
            // any way to minimise double parsing/rendering of super tpl??
            $this->_sprout = $this->_super->render($this->data);
        }
        return $this->_super;
    }

    public function extend($super)
    {
        $this->_super = InTpl::Tpl($super, $this->tplDirs);
        $this->_sprout = null;
        return $this;
    }

    public function start($name, $echo = true)
    {
        $this->_blocks[$name] = (bool) $echo;
        ob_start();
        return $this;
    }

    public function end($name/*, $echo = true*/)
    {
        if (! isset($this->_blocks[$name])) return $this;
        $echo = $this->_blocks[$name];
        $this->_blocks[$name] = ob_get_clean();
        if ($echo) echo isset($this->blocks[$name]) ? $this->blocks[$name] : $this->_blocks[$name];
        return $this;
    }

    public function block($name, $echo = true)
    {
        $output = isset($this->_blocks[$name]) ? $this->_blocks[$name] : '';
        if ($echo)
        {
            echo $output;
            return $this;
        }
        else
        {
            return $output;
        }
    }

    public function render($data = array())
    {
        if (empty($this->tpl))
            return '';

        if (null === $this->found)
        {
            if (is_array($this->tpl))
            {
                // may define a list of possible templates
                foreach ($this->tpl as $t)
                {
                    $this->found = $this->findTpl($t, $this->tplDirs);
                    if ($this->found) break;
                }
                unset($t);
            }
            else
            {
                $this->found = $this->findTpl($this->tpl, $this->tplDirs);
            }
        }

        if (! $this->found)
            return '';

        $this->data = (array) $data;
        unset($data);
        extract($this->data, EXTR_SKIP);

        ob_start();
        @include($this->found);
        $output = ob_get_clean();

        if ($this->_super)
        {
            if (
                (null != $this->_sprout)
                && empty($this->_blocks) && empty($this->blocks)
            )
            {
                return $this->_sprout;
            }
            else
            {
                $this->_super->blocks = array_merge($this->_blocks, $this->blocks);
                return $this->_super->render($this->data);
            }
        }
        else
        {
            return $output;
        }
    }
}
}