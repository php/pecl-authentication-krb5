PHP_ARG_WITH(krb5, for kerberos support,
 [  --with-krb5             Include generic kerberos5/GSSAPI support]
 )

PHP_ARG_WITH(krb5kadm, for kerberos KADM5 support,
 [  --with-krb5kadm	    Include KADM5 Kerberos Administration Support - MIT only],
 no, no
 )

if test "$PHP_KRB5" != "no" -o "$PHP_KRB5KADM" != "no"; then
	echo $PHP_KRB5KADM
	if test "$PHP_KRB5KADM" != "no"; then

	 	AC_MSG_CHECKING([whether KADM is exported])
		if test -f /usr/include/kadm5/admin.h ; then
 			AC_MSG_RESULT([yes])
	 		AC_DEFINE([HAVE_OFFICIAL_KADM5], [], [Having officially exported KADM5 interface])
	 	else
 			AC_MSG_RESULT([no])
		
			AC_MSG_CHECKING([for MIT KADM5 headers])
	
			if test "$PHP_KRB5KADM" = "yes" ; then
				AC_MSG_RESULT([using bundled headers])
				PHP_ADD_INCLUDE(./bundle)
			else
				HEADERS="kdb.h kadm5/admin.h kadm5/kadm_err.h"
				for FILE in $HEADERS ; do
					if test -r $PHP_KRB5/src/$FILE ; then
						AC_MSG_RESULT([not found])
						AC_MSG_ERROR([Make sure that $PHP_KRB5 points to a configured and built MIT krb5 source])
						exit
					fi
				done
				AC_MSG_RESULT([found])
				PHP_ADD_INCLUDE($PHP_KRB5/include)
			fi
			PHP_ADD_INCLUDE(/usr/include/et)
		fi
	fi

	test "$PHP_KRB5" = "yes" && PHP_KRB5="/usr/ /usr/local"

	AC_MSG_CHECKING([for MIT kerberos/GSSAPI libraries in $PHP_KRB5])
	for DIRECTORY in $PHP_KRB5; do
		test -r "$DIRECTORY/lib/libgssapi_krb5.so" && test -r "$DIRECTORY/lib/libkrb5.so" && KERBEROS_DIR=$DIRECTORY && break

		test -r "$DIRECTORY/lib64/libgssapi_krb5.so" && test -r "$DIRECTORY/lib64/libkrb5.so" && KERBEROS_DIR=$DIRECTORY && break
	done

	PHP_ADD_INCLUDE(/usr/include/et)


	if test -z "$KERBEROS_DIR" ; then
		AC_MSG_RESULT([not found])

		AC_MSG_CHECKING([for Heimdal kerberos/GSSAPI libraries])
		for DIRECTORY in $PHP_KRB5 ; do
			test -r "$DIRECTORY/lib/libgssapi.so" && test -r "$DIRECTORY/lib/libkrb5.so" && KERBEROS_DIR=$DIRECTORY && break
			
			test -r "$DIRECTORY/lib64/libgssapi.so" && test -r "$DIRECTORY/lib64/libkrb5.so" && KERBEROS_DIR=$DIRECTORY && break
		done


		if test -z "$KERBEROS_DIR" ; then
			AC_MSG_RESULT([not found])
		else
			AC_MSG_RESULT([found])
			IMPLEMENTATION="heimdal"
			AC_DEFINE(HAVE_KRB5_HEIMDAL, [], [Do we have Heimdal kerberos library])
		fi
	else
		AC_MSG_RESULT([found])
		IMPLEMENTATION="mit"
		AC_DEFINE(HAVE_KRB5_MIT, [], [Do we have MIT kerberos library])
	fi

	echo "dir: $KERBEROS_DIR"



	if test -z "$IMPLEMENTATION"; then
		AC_MSG_ERROR([No kerberos libraries (MIT/Heimdal) found]);
		exit
	fi


	AC_CHECK_LIB(krb5, krb5_cc_new_unique, 
		[ AC_DEFINE(HAVE_KRB5_CC_NEW_UNIQUE, [], [Have krb5_cc_new_unique function]) ], 
		,
		[ -L $KERBEROS_DIR/lib ] )

	AC_CHECK_LIB(krb5, krb5_get_error_message,
		[ AC_DEFINE(HAVE_KRB5_GET_ERROR_MESSAGE, [], [Have krb5_get_error_message function]) ],
		,
		[ -L $KERBEROS_DIR/lib ] )

	AC_CHECK_LIB(krb5, krb5_random_confounder,
		[ AC_DEFINE(HAVE_KRB5_RANDOM_CONFOUNDER, [], [Have krb5_random_confounder function]) ],
		,
		[ -L $KERBEROS_DIR/lib ] )


	AC_CHECK_LIB(krb5, krb5_c_random_make_octets,
		[ AC_DEFINE(HAVE_KRB5_RANDOM_MAKE_OCTETS, [], [Have krb5_c_random_make_octets function]) ],
                ,
                [ -L $KERBEROS_DIR/lib ] )

	
	SOURCE_FILES="krb5.c negotiate_auth.c gssapi.c"

	
	PHP_ADD_LIBRARY_WITH_PATH(krb5, $KERBEROS_DIR/lib, KRB5_SHARED_LIBADD)

	echo $IMPLEMENTATION

	if test "$IMPLEMENTATION" = "heimdal"; then
		PHP_ADD_LIBRARY_WITH_PATH(gssapi, $KERBEROS_DIR/lib, KRB5_SHARED_LIBADD)
	else
		PHP_ADD_LIBRARY_WITH_PATH(gssapi_krb5, $KERBEROS_DIR/lib, KRB5_SHARED_LIBADD)
	fi

	
	if test "$PHP_KRB5KADM" != "no"; then
		PHP_ADD_LIBRARY_WITH_PATH(kadm5clnt, $KERBEROS_DIR/lib, KRB5_SHARED_LIBADD)
		SOURCE_FILES="${SOURCE_FILES} kadm.c kadm5_principal.c kadm5_policy.c"
		AC_DEFINE(HAVE_KADM5, [], [Enable KADM5 support])
	fi

	PHP_SUBST(KRB5_SHARED_LIBADD)



	CFLAGS="-Wall ${CFLAGS}"

	PHP_SUBST(CFLAGS)

	PHP_NEW_EXTENSION(krb5, $SOURCE_FILES, $ext_shared)

	PHP_INSTALL_HEADERS([ext/krb5], [php_krb5.h])
fi
