#ifndef PHP_KRB5_COMPAT_H
#define PHP_KRB5_COMPAT_H

#if PHP_MAJOR_VERSION < 8

#define OBJ_FOR_PROP(zv) (zv)

#else

#define OBJ_FOR_PROP(zv) Z_OBJ_P(zv)

#define TSRMLS_D void
#define TSRMLS_DC
#define TSRMLS_C
#define TSRMLS_CC
#define TSRMLS_FETCH()

#endif

#include "zend_operators.h"

typedef size_t strsize_t;
/* removed/uneeded macros */
#define TSRMLS_CC
/* compatibility macros */
#define _RETURN_STRING(a)      RETURN_STRING(a)

#define _DECLARE_ZVAL(name) zval name ## _v; zval * name = &name ## _v
#define _ALLOC_INIT_ZVAL(name) ZVAL_NULL(name)
#define _RELEASE_ZVAL(name) zval_ptr_dtor(name)
#define _add_next_index_string add_next_index_string
#define _add_assoc_string(z, k, s) add_assoc_string_ex(z, k, strlen(k), s)
#define _add_assoc_string_ex add_assoc_string_ex
#define _add_assoc_stringl_ex add_assoc_stringl_ex

#define _ZVAL_STRINGL(a,b,c) ZVAL_STRINGL(a,b,c)
#define _ZVAL_STRING(a,b) ZVAL_STRING(a,b)
#define _RETVAL_STRINGL(a,b) RETVAL_STRINGL(a,b)
#define _RETVAL_STRING(a) RETVAL_STRING(a)

#define KRB5_CCACHE(zv) (krb5_ccache_object*)((char *)Z_OBJ_P(zv) - XtOffsetOf(krb5_ccache_object, std))
#define KRB5_NEGOTIATE_AUTH(zv)  (krb5_negotiate_auth_object*)((char *)Z_OBJ_P(zv) - XtOffsetOf(krb5_negotiate_auth_object, std))
#define KRB5_GSSAPI_CONTEXT(zv)  (krb5_gssapi_context_object*)((char *)Z_OBJ_P(zv) - XtOffsetOf(krb5_gssapi_context_object, std))
#define KRB5_GSS_CHANNEL(zv) (krb5_gss_channel_object*)((char *)Z_OBJ_P(zv) - XtOffsetOf(krb5_gss_channel_object, std))

#define KRB5_KADM(zv) (krb5_kadm5_object*)((char *)Z_OBJ_P(zv) - XtOffsetOf(krb5_kadm5_object, std))
#define KRB5_KADM_POLICY(zv) (krb5_kadm5_policy_object*)((char *)Z_OBJ_P(zv) - XtOffsetOf(krb5_kadm5_policy_object, std))
#define KRB5_KADM_PRINCIPAL(zv) (krb5_kadm5_principal_object*)((char *)Z_OBJ_P(zv) - XtOffsetOf(krb5_kadm5_principal_object, std))
#define KRB5_KADM_TLDATA(zv) (krb5_kadm5_tldata_object*)((char *)Z_OBJ_P(zv) - XtOffsetOf(krb5_kadm5_tldata_object, std))

static zend_always_inline zval* zend_compat_hash_index_find(HashTable *ht, zend_ulong idx)
{
	return zend_hash_index_find(ht, idx);
}

static zend_always_inline zval* zend_compat_hash_find(HashTable *ht, char *key, size_t len)
{
	zval *result;
	zend_string *key_str = zend_string_init(key, len-1, 0);
	result = zend_hash_find(ht, key_str);
	zend_string_release(key_str);
	return result;
}

#define KRB5_THIS_CCACHE KRB5_CCACHE(getThis())
#define KRB5_THIS_NEGOTIATE_AUTH KRB5_NEGOTIATE_AUTH(getThis())
#define KRB5_THIS_GSSAPI_CONTEXT KRB5_GSSAPI_CONTEXT(getThis())
#define KRB5_THIS_GSS_CHANNEL KRB5_GSS_CHANNEL(getThis())

#define KRB5_THIS_KADM KRB5_KADM(getThis())
#define KRB5_THIS_KADM_POLICY KRB5_KADM_POLICY(getThis())
#define KRB5_THIS_KADM_PRINCIPAL KRB5_KADM_PRINCIPAL(getThis())
#define KRB5_THIS_KADM_TLDATA KRB5_KADM_TLDATA(getThis())




#define INIT_STD_OBJECT(object, ce) zend_object_std_init(&(object), ce TSRMLS_CC);
#define OBJECT_STD_DTOR(object) zend_object_std_dtor(&(object) TSRMLS_CC);

#define ARG_PATH "p"
#define KRB5_SET_ERROR_HANDLING(type)  zend_replace_error_handling(type, NULL, NULL TSRMLS_CC)

#endif
