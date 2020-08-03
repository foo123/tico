<?php $this->extend('content.tpl.php'); ?>

<?php $this->start('content'); ?>
<p><?php echo tico()->get('model')->getMsg(); ?> <?php echo $msg; ?>, you visited <?php echo $count; ?> time(s)</p>
<?php $this->end('content'); ?>
