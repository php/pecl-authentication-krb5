/**
* Copyright (c) 2008 Moritz Bechler
*
* Permission is hereby granted, free of charge, to any person obtaining a copy
* of this software and associated documentation files (the "Software"), to deal
* in the Software without restriction, including without limitation the rights
* to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
* copies of the Software, and to permit persons to whom the Software is
* furnished to do so, subject to the following conditions:
*
* The above copyright notice and this permission notice shall be included in
* all copies or substantial portions of the Software.
*
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
* IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
* FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
* AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
* LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
* OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
* THE SOFTWARE.
**/

#ifndef PHP_KRB5_H
#define PHP_KRB5_H

#ifdef ZTS
#include "TSRM.h"
#endif

#include "php.h"
#include "Zend/zend_exceptions.h"
#include "php_krb5_gssapi.h"

#ifdef HAVE_KADM5
#define KADM5_API_VERSION 2
#endif

#define PHP_SUCCESS SUCCESS

#define KRB5_PRIVATE 1

#include <krb5.h>
#include <gssapi/gssapi.h>
#include <gssapi/gssapi_krb5.h>

#define PHP_KRB5_EXT_NAME "krb5"
#define PHP_KRB5_VERSION "1.0.0"


extern zend_module_entry krb5_module_entry;
#define phpext_krb5_ptr &krb5_module_entry

#ifdef PHP_WIN32
#define PHP_KRB5_API __dllspec(dllexport)
#else
#define PHP_KRB5_API
#endif


PHP_MINIT_FUNCTION(krb5);
PHP_MSHUTDOWN_FUNCTION(krb5);
PHP_MINFO_FUNCTION(krb5);

zend_class_entry *krb5_ce_ccache;

typedef struct _krb5_ccache_object {
	zend_object std;
	krb5_context ctx;
	krb5_ccache cc;
	char *keytab;
} krb5_ccache_object;

krb5_error_code php_krb5_display_error(krb5_context ctx, krb5_error_code code, char* str TSRMLS_DC);


/* KRB5NegotiateAuth Object */
int php_krb5_negotiate_auth_register_classes(TSRMLS_D);

/* KADM5 glue */
#ifdef HAVE_KADM5
int php_krb5_kadm5_register_classes(TSRMLS_D);
#endif


/* PHP Compatability */
#if (PHP_MAJOR_VERSION == 5 && PHP_MINOR_VERSION == 1 && PHP_RELEASE_VERSION > 2) || (PHP_MAJOR_VERSION == 5 && PHP_MINOR_VERSION > 1) || (PHP_MAJOR_VERSION > 5)

#define INIT_STD_OBJECT(object, ce) zend_object_std_init(&(object), ce TSRMLS_CC);

#else

#define INIT_STD_OBJECT(object, ce) \
	{ 	\
		ALLOC_HASHTABLE(object.properties); \
		zend_hash_init(object.properties,0, NULL, ZVAL_PTR_DTOR, 0); \
		object.ce = ce; \
		object.guards = NULL; \
	}

#endif


#if (PHP_MAJOR_VERSION == 5 && PHP_MINOR_VERSION == 1 && PHP_RELEASE_VERSION > 2) || (PHP_MAJOR_VERSION == 5 && PHP_MINOR_VERSION > 1) || (PHP_MAJOR_VERSION > 5)
#define OBJECT_STD_DTOR(object) zend_object_std_dtor(&(object) TSRMLS_CC);
#else
#define OBJECT_STD_DTOR(object) \
	{ 	\
		if(object.guards) { \
			zend_hash_destroy(object.guards); \
			FREE_HASHTABLE(object.guards); \
		} \
		if(object.properties) { \
			zend_hash_destroy(object.properties); \
			FREE_HASHTABLE(object.properties); \
		} \
	}
#endif

#if defined(PHP_VERSION_ID) && PHP_VERSION_ID >= 50400
#define ARG_PATH "p"
#else
#define ARG_PATH "s"
#endif

#endif /* PHP_KRB5_H */
