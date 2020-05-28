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

    protected $_blocks = null;
    public $blocks = null;
    public $super = null;
    protected $supout = '';
    public $tpl = null;
    public $data = null;

    public static function Tpl( $tpl )
    {
        return $tpl instanceof InTpl ? $tpl : new InTpl($tpl);
    }

    public function __construct( $tpl)
    {
        $this->tpl = $tpl;
        $this->super = null;
        $this->_blocks = array();
        $this->blocks = array();
        $this->data = array();
    }

    public function extend( $super )
    {
        $this->super = InTpl::Tpl( $super );
        // need to parse/render super tpl here early
        // in order to have access to $this->super->block(..) calls
        // anyway to minimise double parsing/rendering of super tpl??
        $this->supout = $this->super->render( $this->data );
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

    public function render( $_______DATA________=array() )
    {
        if ( empty($this->tpl) ) return '';

        $this->data = (array)$_______DATA________;
        extract($this->data, EXTR_SKIP);

        ob_start();
        @include($this->tpl);
        $output = ob_get_clean();

        if ( $this->super )
        {
            if ( empty($this->_blocks) && empty($this->blocks) )
            {
                return $this->supout;
            }
            else
            {
                $this->super->blocks = array_merge($this->_blocks, $this->blocks);
                return $this->super->render( $this->data );
            }
        }
        else
        {
            return $output;
        }
    }
}
}