<?php
if(!extension_loaded('krb5')) {
	die('KRB5 Extension not installed');
}


// to disable channel binding, omit the $binding parameter in the constructor
$binding = new GSSAPIChannelBinding();
$binding->setApplicationData(sprintf(
    'tls-server-end-point:%s',
    pack('H*', str_replace(':', '', 
        // Certificate fingerprint:
	// if the certificate uses a MD-5,SHA-1,SHA-256 based signature scheme => the SHA-256 fingerprint
	// for any other scheme, the associcated hash
	'00:E2:C3:A6:A6:C2:2B:60:52:23:DC:4B:E2:E0:E5:C6:EE:86:19:0D:73:3B:11:BA:3B:60:DB:BF:51:21:61:D4')),
));

$serverpinc = 'HTTP/myhostname.domain@REALM';
$auth = new KRB5NegotiateAuth('/etc/krb5.keytab', $serverprinc, $binding);

if($auth->doAuthentication()) {
	echo 'Success - authenticated as ' . $auth->getAuthenticatedUser() . "\n";
	
	try {
		$cc = new KRB5CCache();
		$auth->getDelegatedCredentials($cc);
		echo "Delegated:\n";
		var_dump($cc->getEntries());
	} catch (Exception $error) {
		echo "Delegated: no\n";
	}

	// to enforce channel binding on the server side, check this flag
	echo 'Channel bound: ' . ($auth->isChannelBound() ? 'yes' : 'no') . "\n";
} else {
	if(empty($_SERVER['PHP_AUTH_USER'])) {
		header('HTTP/1.1 401 Unauthorized');
		header('WWW-Authenticate: Basic', false);
	} else {
		// verify basic authentication data
		echo 'authenticated using BASIC method<br />';
	}
}

?>
