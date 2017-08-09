<?php

if (!array_key_exists('StateId', $_REQUEST)) {
	throw new SimpleSAML_Error_BadRequest(
		'Missing required StateId query parameter.'
	);
}

$id = $_REQUEST['StateId'];
$state = SimpleSAML_Auth_State::loadState($id, 'userAcl');	
$idp = SimpleSAML_IdP::getByState($state);
$auth = $idp->getConfig()->getString('auth');

$session = SimpleSAML_Session::getSessionFromRequest();
$session->doLogout($auth);

$sp_url = $state['useracl:spurl'];
SimpleSAML_Utilities::redirectTrustedURL($sp_url);