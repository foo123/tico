<?php $this->extend(tico()->path('/views/content.tpl.php')); ?>

<?php $this->start('content'); ?>
<p>Hello <?php echo $msg; ?></p>
<?php $this->end('content'); ?>
