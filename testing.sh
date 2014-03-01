#!/bin/bash

VERSIONS="1.8 1.9 1.10 1.11 1.12"

for VERSION in $VERSIONS
do
	echo "Running tests for KRB5 $VERSION"
	KRB5DIR=/opt/krb5/$VERSION/

	test -f Makefile && make distclean
	phpize --clean &&
	phpize &&
	./configure --with-krb5config=$KRB5DIR/bin/krb5-config --with-krb5kadm &&
	make &&
	cp testing.config.php tests/config.php &&
	make test NO_INTERACTION=yes &> test.${VERSION}.out
done
