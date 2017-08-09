<?php

/**
 * AdvancedACL Authentication Processing filter
 *
 *
 *	'roles' => array(
 *		'https://myentityID' => array(
 *			'allow' => array(
 *				'addressBlock' => array('192.168.10.0/24'),
 *				'attributeFormat' => 'friendlyName',
 *				'attributes' => array(
 *					'uid' => array('myID', 'yourID', ),
 *					'eduPersonPrincipalName' => array('myID@a.b'),
 *					'eduPersonAffiliation' => array('staff', 'faculty'),
 *				)
 *			),
 *			'deny' => array(
 *				'addressBlock' => array('192.168.10.0/24'),
 *				'attributeFormat' => 'oid',
 *				'attributes' => array(
 *					'uid' => array('myID', 'yourID', ),
 *					'eduPersonPrincipalName' => array('myID@a.b'),
 *					'eduPersonAffiliation' => array('staff', 'faculty'),
 *				)
 *			)
 *		)
 *	)
 *
 *
 *
 *
 *
 * @package simpleSAMLphp
 */
class sspmod_advancedAcl_Auth_Process_UserAcl extends SimpleSAML_Auth_ProcessingFilter
{
	/** @var 접근제어 규칙 */
	private $roles;

	/** @var name2oid */
	private $attrs;

	/** @var state */
	private $state;

    public function __construct($config, $reserved) 
	{
		parent::__construct($config, $reserved);
		$this->roles = array();
		$this->attrs = array();
		$this->state = array();
    }

	/**
	 * 사용자 속성 체크
	 *
	 * @param array  $roles    접근제어 규칙.
	 * @param array  $user     사용자속성.
	 * @param string $key_type 사용자속성 비교방법.
	 * @param string &$attr    체킹 속성 키.
	 */
	private function attr_match($roles, $user, $key_type, &$attr = '')
	{
		foreach ($roles as $r => $v) {
			$r = ($key_type === 'oid') ? $this->attrs[$r] : $r; // 사용자 키 형태

			$role_val = is_array($v) ? $v : array($v); // 무조건 배열로 만들기
			$user_val = isset($user[$r]) ? $user[$r] : ''; // 사용자 속성

			foreach ($user_val as $uv) {
				if (!in_array($uv, $role_val)) {
					$attr = $uv;
					return false;
				}
			}
		}
		$attr = $uv;
		return true;
	}

	/**
	 * IP 체크
	 *
	 * //echo net_match('192.168.17.1/16', '192.168.15.1')."\n"; // returns true
	 * //echo net_match('127.0.0.1/255.255.255.255', '127.0.0.2')."\n"; // returns false
	 * //echo net_match('10.0.0.1', '10.0.0.1')."\n"; // returns true
     *
	 * @param string $network 대상 IP.
	 * @param string $ip      비교 IP.
	 */
	private function net_match($network, $ip) 
	{
		  // determines if a network in the form of 192.168.17.1/16 or
		  // 127.0.0.1/255.255.255.255 or 10.0.0.1 matches a given ip
		  $ip_arr = explode('/', $network);
		  $network_long = ip2long($ip_arr[0]);

		  if (empty($ip_arr[1])) {
			  $ip_arr[1] = '';
		  }

		  $x = ip2long($ip_arr[1]);
		  $mask =  long2ip($x) == $ip_arr[1] ? $x : 0xffffffff << (32 - $ip_arr[1]);
		  $ip_long = ip2long($ip);

		  // echo ">".$ip_arr[1]."> ".decbin($mask)."\n";
		  return ($ip_long & $mask) == ($network_long & $mask);
	}

	/**
	 * 자격여부를 확인하여 미자격시 에러페이지 이동
	 *
	 * @param boolean $isEligible 자격여부.
	 * @param string  &$error     에러코드.
	 */
	private function enter($isEligible = true, $error = '')
	{
		//SimpleSAML_Logger::notice('ROLE:: '.json_encode($this->roles));

        if ($isEligible === false) {
			//SimpleSAML_Logger::notice(json_encode($state));
            $url = SimpleSAML_Module::getModuleURL('advancedAcl/error.php');
			$this->state['useracl:error'] = $error;

			$sp_url_tmp = parse_url($this->state['SPMetadata']['AssertionConsumerService'][0]['Location']);
			$sp_url = $sp_url_tmp['scheme'].'://'.$sp_url_tmp['host'];
			$this->state['useracl:spurl'] = $sp_url;

			$id  = SimpleSAML_Auth_State::saveState($this->state, 'userAcl');
			SimpleSAML_Utilities::redirectTrustedURL($url, array('StateId' => $id));
        }

		return;
	}

	/**
	 * Loads and merges in a file with a attribute map.
	 *
	 * @param string $fileName  Name of attribute map file. Expected to be in the attributenamemapdir.
	 */
	private function loadMapFile($fileName) {
		$config = SimpleSAML_Configuration::getInstance();
		$filePath = $config->getPathValue('attributenamemapdir', 'attributemap/') . $fileName . '.php';

		if(!file_exists($filePath)) {
			throw new Exception('Could not find attributemap file: ' . $filePath);
		}

		$attributemap = NULL;
		include($filePath);
		if(!is_array($attributemap)) {
			throw new Exception('Attribute map file "' . $filePath . '" didn\'t define an attribute map.');
		}

		$this->attrs = $attributemap;
	}

    /**
     * Apply filter.
     *
     * @param array &$request the current request
     */
    public function process(&$state)
    {
        assert('is_array($state)');
        assert('array_key_exists("UserID", $state)');
        assert('array_key_exists("Destination", $state)');
        assert('array_key_exists("entityid", $state["Destination"])');
        assert('array_key_exists("metadata-set", $state["Destination"])');		
        assert('array_key_exists("entityid", $state["Source"])');
        assert('array_key_exists("metadata-set", $state["Source"])');

		$config = SimpleSAML_Configuration::getOptionalConfig('config-acl.php');
		$this->roles = $config->getArray('roles');
		$this->loadMapFile('name2oid');
		
		$this->state = $state;
        $spEntityId = $state['Destination']['entityid'];
        $idpEntityId = $state['Source']['entityid'];
        $attributes = $state['Attributes'];

		// entityID가 목록에 없는 경우, 모든 서비스 제공자에 대해 access allow
		if (!empty($this->roles[$spEntityId])) {
		
			$current_role = $this->roles[$spEntityId]; // 선택된 규칙			

			// entityID에 대해 allow만 있는 경우, allow된 규칙을 갖는 사용자만 access allow		
			if (empty($current_role['deny']) && (!empty($current_role['allow']))) {
				$check_role = $current_role['allow']['attributes'];
				$check_role_type = $current_role['allow']['attributeFormat'];
				$check_ip = empty($current_role['allow']['addressBlock']) ? array() : $current_role['allow']['addressBlock'];

				$check_ip_ok = false;
				foreach ($check_ip as $bip) {
					if ($this->net_match($bip, $_SERVER['REMOTE_ADDR'])) {
						$check_ip_ok = true;
					}
				}

				if ($check_ip_ok === false) {
					$this->enter(false, 'blockIp');
				}

				if ($this->attr_match($check_role, $attributes, $check_role_type, $attr) === false) {
					$this->enter(false, 'notAllowUser:'.$attr);
				}
			}

			// entityID에 대해 deny만 있는 경우, deny된 규칙을 갖는 사용자만 access deny
			if (empty($current_role['allow']) && (!empty($current_role['deny']))) {
				$check_role = $current_role['deny']['attributes'];
				$check_role_type = $current_role['deny']['attributeFormat'];
				$check_ip = empty($current_role['deny']['addressBlock']) ? array() : $current_role['deny']['addressBlock'];

				foreach ($check_ip as $bip) {
					if ($this->net_match($bip, $_SERVER['REMOTE_ADDR'])) {
						$this->enter(false, 'blockIp');
					}
				}

				if ($this->attr_match($check_role, $attributes, $check_role_type, $attr) === true) {
					$this->enter(false, 'denyUser:'.$attr);
				}
			}

			// entityID에 대해 allow와 deny가 함께 있는 경우, 오류
			if ((!empty($current_role['deny'])) && (!empty($current_role['allow']))) {
				$this->enter(false, 'errorConfig');
			}

		}

		$this->enter();
    }
}
