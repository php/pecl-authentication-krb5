<?php
$conn = new KADM5('test2/admin', 'test.keytab', true);

$princ = new KADM5Principal('testlala');
$princ->setExpiryTime(2342342);

$conn->createPrincipal($princ, 'testpass');

var_dump($princ);
var_dump($princ->getPropertyArray());

//$princ->resetFailedAuthCount();
$princ->save();

$princ->delete();

unset($princ);

?>
