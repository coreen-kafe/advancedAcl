<?php

$this->data['header'] = 'Deny Access';

$this->data['head'] = <<<EOF
<meta name="robots" content="noindex, nofollow" />
<meta name="googlebot" content="noarchive, nofollow" />
EOF;

$this->includeAtTemplateBase('includes/header-coreen.php');
?>
<!-- layout-container -->
<div id="layout-container">
	<div id="container">
		<!-- container-body -->
		<div id="container-body">
			<div id="contents">
				<h1 class="title-txt"> Deny Access</h1>
				<p><strong>You are here because of the following reasons.</strong></p>

				<div class="box-blue">
					<p><?php echo $this->data['msg']; ?></p>
				</div>

				<p class="email-form">
				<form method="get" style="display:inline;" action="logout.php">
				<input type="hidden" name="StateId" value="<?php echo $this->data['id']; ?>" />
				<input type="submit" class="btn-purple" name="cancel" value="Logout" />
				</form>

				<button class="btn-gray" onclick="location.replace('<?php echo $this->data['sp_url']; ?>');" />Return Service</button>
				</div>
				</p>
			</div>
		</div>
		<!-- //container-body -->
	</div>
</div>
<!-- //layout-container -->
<?php
$this->includeAtTemplateBase('includes/footer-coreen.php');
