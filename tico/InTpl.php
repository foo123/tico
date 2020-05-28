<?php
/**
*
* InTpl: simple php templates supporting template inheritance
* @version 1.0.0
* https://github.com/foo123/InTpl
*
*/
if ( !class_exists('InTpl', false) )
{
class InTpl
{
    const VERSION = '1.0.0';

    protected $_super = null;
    protected $_sprout = null;
    protected $_blocks = null;
    public $blocks = null;
    public $tpl = null;
    public $data = null;

    public static function Tpl( $tpl )
    {
        return $tpl instanceof InTpl ? $tpl : new InTpl($tpl);
    }

    public function __construct( $tpl)
    {
        $this->tpl = $tpl;
        $this->_super = null;
        $this->_sprout = null;
        $this->_blocks = array();
        $this->blocks = array();
        $this->data = array();
    }

    public function super( )
    {
        if ( $this->_super && (null === $this->_sprout) )
        {
            // need to parse/render super tpl here early
            // in order to have access to $this->super()->block(..) calls
            // anyway to minimise double parsing/rendering of super tpl??
            $this->_sprout = $this->_super->render( $this->data );
        }
        return $this->_super;
    }

    public function extend( $super )
    {
        $this->_super = InTpl::Tpl( $super );
        $this->_sprout = null;
        return $this;
    }

    public function start( $name )
    {
        $this->_blocks[$name] = '';
        ob_start();
        return $this;
    }

    public function end( $name )
    {
        $this->_blocks[$name] = ob_get_clean();
        echo isset($this->blocks[$name]) ? $this->blocks[$name] : $this->_blocks[$name];
        return $this;
    }

    public function block( $name )
    {
        echo isset($this->_blocks[$name]) ? $this->_blocks[$name] : '';
        return $this;
    }

    public function render( $data=array() )
    {
        if ( empty($this->tpl) ) return '';

        $this->data = (array)$data;
        extract($this->data, EXTR_SKIP);

        ob_start();
        @include($this->tpl);
        $output = ob_get_clean();

        if ( $this->_super )
        {
            if ( (null != $this->_sprout)
                && empty($this->_blocks) && empty($this->blocks) )
            {
                return $this->_sprout;
            }
            else
            {
                $this->_super->blocks = array_merge($this->_blocks, $this->blocks);
                return $this->_super->render( $this->data );
            }
        }
        else
        {
            return $output;
        }
    }
}
}