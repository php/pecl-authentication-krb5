PHP_ARG_WITH(krb5, for kerberos support,
 [  --with-krb5             Include generic kerberos5/GSSAPI support]
 )

PHP_ARG_WITH(krb5config, path to krb5config tool,
 [  --with-krb5config       Path to krb5config tool],
 no, no
 )

PHP_ARG_WITH(krb5kadm, for kerberos KADM5 support,
 [  --with-krb5kadm[=S]      Include KADM5 Kerberos Administration Support - MIT only],
 no, no
 )

if test "$PHP_KRB5" != "no" -o "$PHP_KRB5KADM" != "no"; then

	AC_PATH_PROG(PKG_CONFIG, pkg-config, no)
	if test "${PKG_CONFIG}" = "no" -o "$PHP_KRB5CONFIG" != no; then
		AC_MSG_CHECKING([for mit-krb5-gssapi via krb5config])
		if test "$PHP_KRB5CONFIG" == "yes"; then
			PHP_KRB5CONFIG=`which krb5-config`
		fi

		AC_MSG_CHECKING([whether we have krb5config])

		if test -x $PHP_KRB5CONFIG; then
			AC_MSG_RESULT($PHP_KRB5CONFIG)
		else
			AC_MSG_ERROR([no])
			exit
		fi		

		if test "$PHP_KRB5KADM" != "no"; then
			KRB5_LDFLAGS=`$PHP_KRB5CONFIG --libs krb5 gssapi kadm-client`
			KRB5_CFLAGS=`$PHP_KRB5CONFIG --cflags krb5 gssapi kadm-client`
		else
			KRB5_LDFLAGS=`$PHP_KRB5CONFIG --libs krb5 gssapi`
			KRB5_CFLAGS=`$PHP_KRB5CONFIG --cflags krb5 gssapi`
		fi
		KRB5_VERSION=`$PHP_KRB5CONFIG --version`
	else

		AC_MSG_CHECKING([for krb5-gssapi via pkg-config])
		if ${PKG_CONFIG} --exists krb5-gssapi krb5; then
			AC_MSG_RESULT([yes])
		else
			AC_MSG_ERROR([krb5-gssapi or krb5 not found -- install libkrb5-dev or equivalent])
		fi

		if test "$PHP_KRB5KADM" != "no"; then
			dnl Try kadm-client via pkg-config; fall back to the MIT library name.
			if ${PKG_CONFIG} --exists kadm-client 2>/dev/null; then
				KRB5_LDFLAGS=`${PKG_CONFIG} --libs-only-L krb5-gssapi krb5 kadm-client`
				KRB5_LIBS=`${PKG_CONFIG} --libs-only-l krb5-gssapi krb5 kadm-client`
				KRB5_CFLAGS=`${PKG_CONFIG} --cflags krb5-gssapi krb5 kadm-client`
			else
				KRB5_LDFLAGS=`${PKG_CONFIG} --libs-only-L krb5-gssapi krb5`
				KRB5_LIBS="`${PKG_CONFIG} --libs-only-l krb5-gssapi krb5` -lkadm5clnt_mit"
				KRB5_CFLAGS=`${PKG_CONFIG} --cflags krb5-gssapi krb5`
			fi
		else
			KRB5_LDFLAGS=`${PKG_CONFIG} --libs-only-L krb5-gssapi krb5`
			KRB5_LIBS=`${PKG_CONFIG} --libs-only-l krb5-gssapi krb5`
			KRB5_CFLAGS=`${PKG_CONFIG} --cflags krb5-gssapi krb5`
		fi
		KRB5_VERSION=`${PKG_CONFIG} --modversion krb5-gssapi`
	fi

	AC_MSG_CHECKING([for required linker flags])
	AC_MSG_RESULT([$KRB5_LDFLAGS $KRB5_LIBS])

	AC_MSG_CHECKING([for required compiler flags])
	AC_MSG_RESULT([$KRB5_CFLAGS])


	AC_MSG_CHECKING([for kerberos library version])
	AC_MSG_RESULT([$KRB5_VERSION])
	AC_DEFINE_UNQUOTED(KRB5_VERSION, ["$KRB5_VERSION"], [Kerberos library version])

	SOURCE_FILES="krb5.c negotiate_auth.c gssapi.c channel.c"

	if test "$PHP_KRB5KADM" != "no"; then
		SOURCE_FILES="${SOURCE_FILES} kadm.c kadm5_principal.c kadm5_policy.c kadm5_tldata.c"
		AC_DEFINE(HAVE_KADM5, [], [Enable KADM5 support])
	fi

	CFLAGS="-Wall ${CFLAGS} ${KRB5_CFLAGS}"
	LDFLAGS="${LDFLAGS} ${KRB5_LDFLAGS}"
	LIBS="${LIBS} ${KRB5_LIBS}"

	AC_CHECK_FUNCS(krb5_free_string)
	AC_CHECK_FUNCS(gss_acquire_cred_from)
	AC_CHECK_FUNCS(gss_export_cred)
	AC_CHECK_FUNCS(krb5_chpw_message)
	AC_CHECK_FUNCS(krb5_principal_get_realm)
	AC_CHECK_FUNCS(krb5_get_init_creds_opt_set_expire_callback)

	PHP_SUBST(CFLAGS)
	PHP_SUBST(LDFLAGS)
	PHP_NEW_EXTENSION(krb5, $SOURCE_FILES, $ext_shared)
	PHP_INSTALL_HEADERS([ext/krb5], [php_krb5.h php_krb5_compat.h php_krb5_gssapi.h])
fi
