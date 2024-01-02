--TEST--
Testing for GSSAPI channel binding
--SKIPIF--
<?php 
if(!file_exists(dirname(__FILE__) . '/config.php')) { echo "skip config missing"; return; }
if(!include(dirname(__FILE__) . '/config.php')) return; 
?>
--FILE--
<?php
include(dirname(__FILE__) . '/config.php');
$client = new KRB5CCache();
if($use_config) {
	$client->setConfig(dirname(__FILE__) . '/krb5.ini');	
}

$client->initPassword($client_principal, $client_password, array('tkt_life' => 360));

$server = new KRB5CCache();
if($use_config) {
        $server->setConfig(dirname(__FILE__) . '/krb5.ini');
}

$server->initKeytab($server_principal, $server_keytab);

$cgssapi = new GSSAPIContext();
$sgssapi = new GSSAPIContext();

$cgssapi->acquireCredentials($client, $client_principal, GSS_C_INITIATE);
$sgssapi->acquireCredentials($server);

$token = '';
$ret_flags = 0;
$timerec = 0;
$otoken = '';
$oprinc = '';
$deleg = new KRB5CCache();


$tbindings = new GSSAPIChannelBinding();
var_dump($tbindings->getInitiatorAddress());
var_dump($tbindings->getInitiatorAddressType());
var_dump($tbindings->getAcceptorAddress());
var_dump($tbindings->getAcceptorAddressType());
var_dump($tbindings->getApplicationData());

$tbindings->setApplicationData('fooobar');
var_dump($tbindings->getApplicationData());
$tbindings->setInitiatorAddress(123,'initiator');
$tbindings->setAcceptorAddress(53,'acceptor');
var_dump($tbindings->getInitiatorAddress());
var_dump($tbindings->getAcceptorAddress());


$ibindings = new GSSAPIChannelBinding();
$abindings = new GSSAPIChannelBinding();

var_dump($cgssapi->initSecContext($server_principal, null, null, null, $token, $ret_flags, $timerec, $ibindings));
var_dump($sgssapi->acceptSecContext($token, $otoken, $oprinc, $ret_flags, $timerec, $deleg, $abindings));


// initator provides app data
$cgssapi = new GSSAPIContext();
$sgssapi = new GSSAPIContext();

$cgssapi->acquireCredentials($client, $client_principal, GSS_C_INITIATE);
$sgssapi->acquireCredentials($server);
$ibindings = new GSSAPIChannelBinding();
$ibindings->setApplicationData('fooooo');
$abindings = new GSSAPIChannelBinding();

var_dump($cgssapi->initSecContext($server_principal, null, null, null, $token, $ret_flags, $timerec, $ibindings));
var_dump(@$sgssapi->acceptSecContext($token, $otoken, $oprinc, $ret_flags, $timerec, $deleg, $abindings));


// acceptor provides app data
$cgssapi = new GSSAPIContext();
$sgssapi = new GSSAPIContext();

$cgssapi->acquireCredentials($client, $client_principal, GSS_C_INITIATE);
$sgssapi->acquireCredentials($server);
$ibindings = new GSSAPIChannelBinding();
$abindings = new GSSAPIChannelBinding();
$abindings->setApplicationData('fooooo');

var_dump($cgssapi->initSecContext($server_principal, null, null, null, $token, $ret_flags, $timerec, $ibindings));
var_dump(@$sgssapi->acceptSecContext($token, $otoken, $oprinc, $ret_flags, $timerec, $deleg, $abindings));


// acceptor provides app data
$cgssapi = new GSSAPIContext();
$sgssapi = new GSSAPIContext();

$cgssapi->acquireCredentials($client, $client_principal, GSS_C_INITIATE);
$sgssapi->acquireCredentials($server);
$ibindings = new GSSAPIChannelBinding();
$ibindings->setApplicationData('fooooo');
$abindings = new GSSAPIChannelBinding();
$abindings->setApplicationData('fooooo');

var_dump($cgssapi->initSecContext($server_principal, null, null, null, $token, $ret_flags, $timerec, $ibindings));
var_dump($sgssapi->acceptSecContext($token, $otoken, $oprinc, $ret_flags, $timerec, $deleg, $abindings));
?>
--EXPECTF--
NULL
int(0)
NULL
int(0)
NULL
string(7) "fooobar"
string(9) "initiator"
string(8) "acceptor"
bool(true)
bool(true)
bool(true)
bool(false)
bool(true)
bool(false)
bool(true)
bool(true)
