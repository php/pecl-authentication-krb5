<?php
$conn = new KADM5('test2/admin', 'test.keytab', true);
$newpol = new KADM5Policy('testing');
$newpol->setMinPasswordLength(10);
$newpol->setMinPasswordClasses(3);
$conn->createPolicy($newpol);

$princ = new KADM5Principal('testuser');
$conn->createPrincipal($princ , 'testpass');

// either of this should work
//$princ->setPolicy($conn->getPolicy('testing'));
$princ->setPolicy($newpol);
//$princ->setPolicy('testing');

$princ->save();
