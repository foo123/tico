<?php $this->extend(tico()->path('/views/layout/base.tpl.php')); ?>

<?php $this->start('title'); ?><?php echo $title; ?><?php $this->end('title'); ?>

<?php $this->start('content'); ?>
Page Content
<?php $this->end('content'); ?>
