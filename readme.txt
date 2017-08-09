## 모듈 적용방법

0. 주요파일들을 simplesamlphp/modules 등의 디렉토리에 복사합니다.

simplesamlphp/config/config-acl.php
simplesamlphp/modules/advancedAcl/lib/Auth/Process/UserAcl.php
simplesamlphp/modules/advancedAcl/www/error.php
simplesamlphp/modules/advancedAcl/enable

1. simplesamlphp/config/config-acl.php 의 설정

접근제어 목록 작성 규칙에 맞게 설정합니다.

2. simplesamlphp/config/config.php 의 설정

 authproc.ip 항목중 아래의 같은 형태로 적용합니다.

    'authproc.idp' => array(
		9 => 'advancedAcl:UserAcl',


3. 정상적으로 설정이 적용되고 있는지 확인합니다.




## 참고

• 접근제어 방법
   1. entityID가 목록에 없는 경우, 모든 서비스 제공자에 대해 access allow
   2. entityID에 대해 allow만 있는 경우, allow된 규칙을 갖는 사용자만 access allow
   3. entityID에 대해 deny만 있는 경우, deny된 규칙을 갖는 사용자만 access deny
   4. entityID에 대해 allow와 deny가 함께 있는 경우, 오류

• 규칙
   1. addressBlock값이 null 이면 addressBlock을 이용하지 않음
   2. attributeFormat은 friendlyName이거나 oid 값을 가져야 함
      friendlyName일 경우, attributes array의 속성값을 friendyName으로 이용
      oid일 경우, attributes array의 속성값을 oid로 변환한 후 이용
   3. attributes값을 기준으로 접근제어. 예를 들어,
      entityID => ‘https://myentityID’,
      allow => array{
        attributeFormat => ‘friendlyName’,
        attributes => array {
              ‘eduPersonPrincipalName’ => array{ ‘myID@a.b’, ‘youID@a.b’, },
              ‘eduPersonAffiliation’ => { ‘staff’, ‘faculty’, },
        },
      },
      위의 경우, entityID가 https://myentityID인 서비스 제공자에 대해, 
      eduPersonPrincipalName에 myID@a.b 또는(OR) youID@a.b가 포함되어 있고(AND)
      eduPersonAffiliation에 staff 또는(OR) faculty가 포함되어 있으면 접근 허가 함.



