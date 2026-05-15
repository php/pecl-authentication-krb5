--TEST--
Testing for credential export and import
--SKIPIF--
<?php
if(!file_exists(dirname(__FILE__) . '/config.php')) { echo "skip config missing"; return; }
if(!include(dirname(__FILE__) . '/config.php')) return;
if(!method_exists('GSSAPIContext', 'exportCredentials')) { echo "skip gss_export_cred not available"; return; }
?>
--FILE--
<?php
include(dirname(__FILE__) . '/config.php');
$client = new KRB5CCache();
if($use_config) {
	$client->setConfig(dirname(__FILE__) . '/krb5.ini');
}

$client->initPassword($client_principal, $client_password, array('forwardable' => true, 'proxiable' => true));

$server = new KRB5CCache();
if($use_config) {
	$server->setConfig(dirname(__FILE__) . '/krb5.ini');
}

$server->initKeytab($server_principal, $server_keytab);

$cgssapi = new GSSAPIContext();
$sgssapi = new GSSAPIContext();

$cgssapi->acquireCredentials($client);
$sgssapi->acquireCredentials($server);

$token = '';
$token2 = '';
$principal = '';
$ret_flags = 0;
$time_rec = 0;
$deleg = new KRB5CCache();

// Establish a context with delegation to obtain delegated credentials
var_dump($cgssapi->initSecContext($server_principal, null, GSS_C_DELEG_FLAG, null, $token));
var_dump($sgssapi->acceptSecContext($token, $token2, $principal, $ret_flags, $time_rec, $deleg));
var_dump(count($deleg->getEntries()));

// Acquire credentials from the delegated ccache, then export them
$dgssapi = new GSSAPIContext();
$dgssapi->acquireCredentials($deleg, $principal, GSS_C_INITIATE);

$exported = $dgssapi->exportCredentials();
var_dump(is_string($exported) && strlen($exported) > 0);

// Import the exported credentials into a fresh context and use them
$igssapi = new GSSAPIContext();
var_dump($igssapi->importCredentials($exported));

$s2gssapi = new GSSAPIContext();
$s2gssapi->acquireCredentials($server);

$token = '';
$token2 = '';
$principal2 = '';

var_dump($igssapi->initSecContext($server_principal, null, null, null, $token));
var_dump($s2gssapi->acceptSecContext($token, $token2, $principal2, $ret_flags, $time_rec, $deleg));
var_dump($principal2 === $principal);

?>
--EXPECTF--
bool(true)
bool(true)
int(1)
bool(true)
bool(true)
bool(true)
bool(true)
bool(true)
