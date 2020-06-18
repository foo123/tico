<?php $this->extend(tico()->path('/views/content.tpl.php')); ?>

<?php $this->start('content'); ?>
<p><?php echo tico()->get('model')->getMsg(); ?> <?php echo $msg; ?></p>
<?php $this->end('content'); ?>
