--TEST--
Testing null for optional string arguments
--SKIPIF--
<?php
if(!file_exists(dirname(__FILE__) . '/config.php')) { echo "skip config missing"; return; }
if(!include(dirname(__FILE__) . '/config.php')) return;
?>
--FILE--
<?php
include(dirname(__FILE__) . '/config.php');
// config.php hides E_DEPRECATED; PHP 8.1+ deprecates null for non-nullable
// internal string parameters
error_reporting(E_ALL);

$client = new KRB5CCache();
if($use_config) {
	$client->setConfig(dirname(__FILE__) . '/krb5.ini');
}
$client->initPassword($client_principal, $client_password);
var_dump(count($client->getTktAttrs(null)) > 0);

$gssapi = new GSSAPIContext();
$gssapi->acquireCredentials($client, null);
$gssapi->initSecContext($server_principal, null, 0, 0, $token);
var_dump(strlen($token) > 0);
?>
--EXPECT--
bool(true)
bool(true)
