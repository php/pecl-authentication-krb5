--TEST--
Testing initPassword() with verify_keytab
--SKIPIF--
<?php
if(!file_exists(dirname(__FILE__) . '/config.php')) { echo "skip config missing"; return; }
if(!include(dirname(__FILE__) . '/config.php')) return;
?>
--FILE--
<?php
include(dirname(__FILE__) . '/config.php');

// Twice: the keytab was used after its iteration had been ended wrongly,
// which aborted the process (MIT: k5_mutex_lock assertion)
for($i = 0; $i < 2; $i++) {
	$client = new KRB5CCache();
	if($use_config) {
		$client->setConfig(dirname(__FILE__) . '/krb5.ini');
	}
	$client->initPassword($client_principal, $client_password, array('verify_keytab' => $server_keytab));
	var_dump($client->getPrincipal() === $client_principal);
}
?>
--EXPECT--
bool(true)
bool(true)
