#!/bin/bash

PHP_VERSIONS="5.6 7.0"
VERSIONS="1.8 1.9 1.10 1.11 1.12"

for PHP_VERSION in $PHP_VERSIONS
do
	PHP_PATH=/usr/lib/php$PHP_VERSION/
	for VERSION in $VERSIONS
	do
		echo "Running tests for KRB5 $VERSION"
		KRB5DIR=/opt/krb5/$VERSION/

		test -f Makefile && make distclean &> /dev/null
		phpize --clean &> /dev/null &&
		$PHP_PATH/bin/phpize
		( aclocal; autoconf; autoheader; automake
		./configure --with-php-config=$PHP_PATH/bin/php-config --with-krb5config=$KRB5DIR/bin/krb5-config --with-krb5kadm &&
		make ) 2>&1 > test.${PHP_VERSION}-${VERSION}.build.out &&
		cp testing.config.php tests/config.php &&
		make test NO_INTERACTION=yes &> test.${PHP_VERSION}-${VERSION}.out
		cat test.${PHP_VERSION}-${VERSION}.out
	done
done
