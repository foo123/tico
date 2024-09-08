<?php $this->extend('layout/base.tpl.php'); ?>

<?php $this->start('title'); ?><?php echo $title; ?><?php $this->end('title'); ?>

<?php $this->start('content'); ?>
<p>Root: <?php echo $msg; ?></p>
<p>"<?php echo tico()->requestPath(); ?>", "<?php echo tico()->currentUrl(false); ?>"</p>
<?php $this->end('content'); ?>
