<?php
	if (!array_key_exists('StateId', $_REQUEST)) {
		throw new SimpleSAML_Error_BadRequest(
			'Missing required StateId query parameter.'
		);
	}

	$id = $_REQUEST['StateId'];
	$state = SimpleSAML_Auth_State::loadState($id, 'userAcl');	
	$sp_url = $state['useracl:spurl'];
	$tmp = explode(':', $state['useracl:error']);
	$errMsg = $tmp[0];
	$errAttr = isset($tmp[1]) ? $tmp[1] : '';
	$msg = '';
	switch ($errMsg) {
		case 'blockIp':
			$msg = '접근 차단된 IP('.$_SERVER['REMOTE_ADDR'].')입니다.';
		break;
		case 'notAllowUser':
			$msg = '허용되지 않는 사용자 속성('.$errAttr.')입니다.';
		break;
		case 'denyUser':
			$msg = '접근 차단된 사용자 속성('.$errAttr.')입니다.';
		break;
		case 'errorConfig':
			$msg = '해당 SP의 allow 정책과 deny 정책이 동시에 설정되어 있습니다.';
		break;
	}	
?>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" lang="ko" xml:lang="ko">
<head>
<title>Warning</title>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
<meta http-equiv="X-UA-Compatible" content="IE=edge, chrome=1" />
<meta name="keywords" content="플랜아이" />
<meta name="description" content="플랜아이" />
<meta name="author" content="㈜플랜아이 1644-5580" />
<meta name="copyright" content="COPYRIGHTS© 2015 PLANI. ALL RIGHT RESERVED" />
<link type="text/css" rel="stylesheet" href="https://coreen-idp.kreonet.net/simplesaml/css/korean/common.css" />
<link type="text/css" rel="stylesheet" href="https://coreen-idp.kreonet.net/simplesaml/css/korean/layout.css" />
<body>
<div class="login-kreonet">

	<div class="login-kreonet-form" style="height:auto">
		<div>
		<img style="float: left; margin-right: 12px" src="https://coreen-idp.kreonet.net/simplesaml/resources/icons/checkmark.48x48.png" alt="Successful logout" /><p style="padding-top: 16px; ">
		You are here because of the following reasons.
		</div>

		<div id="confirmation" style="margin-top: 1em" >
		<p><?php echo $msg; ?></p>

		<form method="get" style="display:inline;" action="logout.php">
		<input type="hidden" name="StateId" value="<?php echo $id; ?>" />
		<input type="submit" class="btn-sky" style="width:auto" name="cancel" value="Logout" />
		</form>

		<input type="button" value="Service Provider" class="btn-black" onclick="location.replace('<?php echo $sp_url; ?>');" />
		</div>
	</div>

	<!-- layout-footer -->
	<div id="layout-footer">
		<div id="footer">
			<p id="copyright">Copyright &copy; 2015- KREONET. All Right Reserved. 
			Designated trademarks and brands are the property of KREONET/COREEN.</p>
			<p>Use of this Web site constitutes acceptances of the COREEN/KREONET <a href="https://coreen.kreonet.net/user_agreement" target="_blank">User Agreement</a> and <a href="https://coreen.kreonet.net/privacy_policy" target="_blank">Privacy Policy.</a></p>
		</div>
	</div>		
	<!-- //layout-footer -->
</div>

</body>
</html>
