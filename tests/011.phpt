--TEST--
Testing storeCredentials() into a KRB5CCache's own ccache, destroyed with it
--SKIPIF--
<?php
if(!file_exists(dirname(__FILE__) . '/config.php')) { echo "skip config missing"; return; }
if(!include(dirname(__FILE__) . '/config.php')) return;
if(!method_exists('GSSAPIContext', 'storeCredentials')) { echo "skip gss_store_cred_into not available"; return; }
?>
--FILE--
<?php
include(dirname(__FILE__) . '/config.php');
$client = new KRB5CCache();
if($use_config) {
	$client->setConfig(dirname(__FILE__) . '/krb5.ini');
}
$client->initPassword($client_principal, $client_password);
$gssapi = new GSSAPIContext();
$gssapi->acquireCredentials($client);

// Every KRB5CCache holds a unique MEMORY ccache; its name can be handed to
// storeCredentials() (and e.g. KRB5CCNAME), and it is destroyed with the
// object, so nothing is left behind in the process.
$target = new KRB5CCache();
$name = $target->getName();
var_dump(strncmp($name, 'MEMORY:', 7) === 0);
var_dump($gssapi->storeCredentials($name));
var_dump($target->getPrincipal() === $client_principal);

$probe = new KRB5CCache();
$probe->open($name);
var_dump($probe->getPrincipal() === $client_principal);

unset($target);
try {
	(new KRB5CCache())->open($name);
	echo "still there\n";
} catch (Exception $e) {
	echo "destroyed\n";
}
?>
--EXPECT--
bool(true)
bool(true)
bool(true)
bool(true)
destroyed
