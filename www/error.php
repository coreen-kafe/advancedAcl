<?php
	$globalConfig = SimpleSAML_Configuration::getInstance();

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

	$t = new SimpleSAML_XHTML_Template($globalConfig, 'advancedAcl:error.php');
	$t->data['msg'] = $msg;
	$t->data['id'] = $id;
	$t->data['sp_url'] = $sp_url;
	$t->show();
?>
