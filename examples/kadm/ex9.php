<?php

$config = array(
	'realm' => 'SPRINGFIELD',
	'admin_server' => 'homer.springfield'
);

// need to specify the realm in principal,
// otherwise krb5.conf default realm is used
$conn = new KADM5('testpw/admin@SPRINGFIELD', 'asdfgh', false, $config);

$princ = $conn->getPrincipal("testuser@SPRINGFIELD");
var_dump($princ->getAttributes());
var_dump($princ->getAuxAttributes());
var_dump($princ->getPropertyArray());
var_dump($princ->getTLData());

$princ->setTLData(array(new KADM5TLData(KRB5_TL_DB_ARGS, "tktpolicy=")));
var_dump($princ->getTLData());
$princ->save();
var_dump($princ->getPropertyArray());
var_dump($princ->getTLData());
