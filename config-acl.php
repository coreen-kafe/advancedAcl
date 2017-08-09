<?php

$config = array(
	'roles' => array(
		'http://demo-sp.plani.co.kr/simplesaml/module.php/saml/sp/metadata.php/default-sp' => array(
			/*
			'allow' => array(
				'addressBlock' => array('211.228.18.1', '211.228.18.3', '211.228.18.195'),
				'attributeFormat' => 'friendlyName',
				'attributes' => array(
					'eduPersonPrincipalName' => array('testking@coreen.or.kr'),
					'uid' => array('myID', 'yourID', ),
					'eduPersonPrincipalName' => array('myID@a.b'),
					'eduPersonAffiliation' => array('staff', 'faculty'),
				)
			)
			*/
			'deny' => array(
				'addressBlock' => array('211.228.18.1', '211.228.18.3', '211.228.18.194'), // 195
				'attributeFormat' => 'friendlyName',
				'attributes' => array(
					'uid' => array('testking', ),
					//'eduPersonPrincipalName' => array('testking@coreen.or.kr'),
				)
			)
		)
	)
);