<?php

$princ = 'cpwtest@SPRINGFIELD';
try {
	KRB5CCache::changePassword($princ, 'oldpassword', 'newpassword');
	echo "oldpassword -> newpassword\n";
} catch (Exception $e) {
	KRB5CCache::changePassword($princ, 'newpassword', 'oldpassword');
	echo "newpassword -> oldpassword\n";
}

?>
