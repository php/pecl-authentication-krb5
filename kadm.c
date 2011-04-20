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

#include "php_krb5.h"
#include "php_krb5_kadm.h"



zend_object_handlers krb5_kadm5_handlers;


static function_entry krb5_kadm5_functions[] = {
	PHP_ME(KADM5, __construct, NULL, ZEND_ACC_CTOR | ZEND_ACC_PUBLIC)
	PHP_ME(KADM5, getPrincipal, NULL, ZEND_ACC_PUBLIC)
	PHP_ME(KADM5, getPrincipals, NULL, ZEND_ACC_PUBLIC)
	PHP_ME(KADM5, createPrincipal, NULL, ZEND_ACC_PUBLIC)
	PHP_ME(KADM5, getPolicy, NULL, ZEND_ACC_PUBLIC)
	PHP_ME(KADM5, createPolicy, NULL, ZEND_ACC_PUBLIC)
	PHP_ME(KADM5, getPolicies, NULL, ZEND_ACC_PUBLIC)
	{NULL, NULL, NULL}		
};

/* KADM5 ctor/dtor */

/* {{{ */
void php_krb5_free_kadm5_object(krb5_kadm5_object *obj) {

	if(obj->refcount > 0) {
		obj->refcount--;
		return;
	}

	if(obj) {
		kadm5_destroy(&obj->handle);
		krb5_free_context(obj->ctx);
		efree(obj);
	}
}
/* }}} */

/* {{{ */
static void php_krb5_kadm5_object_dtor(void *obj, zend_object_handle handle TSRMLS_DC)
{
	krb5_kadm5_object *object = (krb5_kadm5_object*)obj;
	zend_object_std_dtor(&(object->std) TSRMLS_CC);

	php_krb5_free_kadm5_object(object);
}
/* }}} */

/* {{{ */
zend_object_value php_krb5_kadm5_object_new(zend_class_entry *ce TSRMLS_DC)
{
	zend_object_value retval;
	krb5_kadm5_object *object;

	object = emalloc(sizeof(krb5_kadm5_object));
	object->refcount = 0;

	zend_object_std_init(&(object->std), ce TSRMLS_CC);

	zend_hash_copy(object->std.properties, &ce->default_properties,
					(copy_ctor_func_t) zval_add_ref, NULL,
					sizeof(zval*));

	retval.handle = zend_objects_store_put(object, php_krb5_kadm5_object_dtor, NULL, NULL TSRMLS_CC);

	retval.handlers = &krb5_kadm5_handlers;
	return retval;
}
/* }}} */

/* Register classes */
/* {{{ */
int php_krb5_kadm5_register_classes(TSRMLS_D) {
	zend_class_entry kadm5;

	/** register KADM5 **/
	INIT_CLASS_ENTRY(kadm5, "KADM5", krb5_kadm5_functions);
	krb5_ce_kadm5 = zend_register_internal_class(&kadm5 TSRMLS_CC);
	krb5_ce_kadm5->create_object = php_krb5_kadm5_object_new;
	memcpy(&krb5_kadm5_handlers, zend_get_std_object_handlers(), sizeof(zend_object_handlers));

	/** register KADM5Principal **/
	php_krb5_register_kadm5_principal(TSRMLS_C);

	/** register KADM5Policy **/
	php_krb5_register_kadm5_policy(TSRMLS_C);


	return SUCCESS;
}
/* }}} */

/* {{{ proto KADM5::__construct(string $principal, string $credentials, bool $use_keytab)
	Initialize a connection with the KADM server using the given credentials */
PHP_METHOD(KADM5, __construct)
{
	kadm5_ret_t retval;

	char *sprinc;
	int sprinc_len;

	char *spass = NULL;
	int spass_len;

	zend_bool use_keytab = 0;

	krb5_kadm5_object *obj;


	if(zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "ss|b", &sprinc, &sprinc_len,
					&spass, &spass_len,
					&use_keytab) == FAILURE) {
		RETURN_FALSE;
	}

	if(strlen(spass) == 0) {
		zend_throw_exception(NULL, "You may not specify an empty password or keytab", 0 TSRMLS_CC);
		return;
	}

	obj = (krb5_kadm5_object*)zend_object_store_get_object(getThis() TSRMLS_CC);

	if(krb5_init_context(&obj->ctx)) {
		zend_throw_exception(NULL, "Failed to initialize kerberos library", 0 TSRMLS_CC);
	}

		
	if(!use_keytab) {
#ifdef HAVE_OFFICIAL_KADM5
 		retval = kadm5_init_with_password(obj->ctx, sprinc, spass, KADM5_ADMIN_SERVICE, NULL, 
 						KADM5_STRUCT_VERSION, KADM5_API_VERSION_2, NULL, &obj->handle);
#else
  		retval = kadm5_init_with_password(sprinc, spass, KADM5_ADMIN_SERVICE, NULL, 
  						KADM5_STRUCT_VERSION, KADM5_API_VERSION_2, NULL, &obj->handle);
#endif
 
 	} else {
 
  		if((PG(safe_mode) && !php_checkuid(sprinc, NULL, CHECKUID_CHECK_FILE_AND_DIR)) ||
  			php_check_open_basedir(sprinc TSRMLS_CC)) {
  			RETURN_FALSE;
  		}
#ifdef HAVE_OFFICIAL_KADM5
 		retval = kadm5_init_with_skey(obj->ctx,sprinc, spass, KADM5_ADMIN_SERVICE, NULL, 
 						KADM5_STRUCT_VERSION, KADM5_API_VERSION_2, NULL, &obj->handle);
#else
 		retval = kadm5_init_with_skey(sprinc, spass, KADM5_ADMIN_SERVICE, NULL, 
  						KADM5_STRUCT_VERSION, KADM5_API_VERSION_2, NULL, &obj->handle);
#endif
	}

	if(retval != KADM5_OK) {
		zend_throw_exception(NULL, (char*)krb5_get_error_message(obj->ctx, (int)retval), (int)retval TSRMLS_CC);
	}
}
/* }}} */

/* {{{ proto KADM5Principal KADM5::getPrinicipal(string $principal)
	Fetch a principal entry by name */
PHP_METHOD(KADM5, getPrincipal)
{
	zval *dummy_retval, *ctor;
	zval *args[2];

	zval *sprinc = NULL;

	if(zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "z", &sprinc) == FAILURE) {
		RETURN_FALSE;
	}

	object_init_ex(return_value, krb5_ce_kadm5_principal);

	MAKE_STD_ZVAL(ctor);
	ZVAL_STRING(ctor, "__construct", 1);

	args[0] = sprinc;
	args[1] = getThis();

	MAKE_STD_ZVAL(dummy_retval);
	if(call_user_function(&krb5_ce_kadm5_principal->function_table,
							&return_value, ctor, dummy_retval, 2,
							args TSRMLS_CC) == FAILURE) {
		zval_dtor(ctor);
		zval_dtor(dummy_retval);
		zend_throw_exception(NULL, "Failed to instantiate KADM5Principal object", 0 TSRMLS_CC);
	}

	zval_ptr_dtor(&ctor);
	zval_ptr_dtor(&dummy_retval);
} /* }}} */

/* {{{ proto array KADM5::getPrinicipal([string $filter])
	Fetch an array of all principals matching $filter */
PHP_METHOD(KADM5, getPrincipals)
{
	kadm5_ret_t retval;
	krb5_kadm5_object *obj;

	char *sexp = NULL;
	int sexp_len;

	char **princs;
	int princ_count;

	int i;

	if(zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "|s", &sexp, &sexp_len) == FAILURE) {
		RETURN_FALSE;
	}

	obj = (krb5_kadm5_object*)zend_object_store_get_object(getThis() TSRMLS_CC);
	retval = kadm5_get_principals(obj->handle, sexp, &princs, &princ_count);

	if(retval) {
		zend_throw_exception(NULL, (char*) krb5_get_error_message(obj->ctx, (int)retval), (int)retval TSRMLS_CC);
		return;
	}

	array_init(return_value);

	for(i = 0; i < princ_count; i++) {
		add_next_index_string(return_value, princs[i], 1);
	}

	kadm5_free_name_list(obj->handle, princs, princ_count);
} /* }}} */

/* {{{ proto void KADM5::createPrincipal(KADM5Principal $principal [, string $password ])
	Creates a principal */
PHP_METHOD(KADM5, createPrincipal)
{
	kadm5_ret_t retval = 0;
	zval *princ = NULL, *princname = NULL;
	krb5_kadm5_principal_object *principal = NULL;
	krb5_kadm5_object *obj = NULL;

	zval *dummy_retval = NULL, *func = NULL;
	char *pw = NULL;
	int pw_len = 0;

	if(zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "O|s", &princ, krb5_ce_kadm5_principal, &pw, &pw_len) == FAILURE) {
		return;
	}

	principal = zend_object_store_get_object(princ TSRMLS_CC);
	obj = zend_object_store_get_object(getThis() TSRMLS_CC);

	princname = zend_read_property(krb5_ce_kadm5_principal, princ, "princname",
									sizeof("princname"),1 TSRMLS_CC);

	if(krb5_parse_name(obj->ctx, Z_STRVAL_P(princname),&principal->data.principal)) {
		zend_throw_exception(NULL, "Failed to parse principal name", 0 TSRMLS_CC);
		return;
	}
	principal->update_mask |= KADM5_PRINCIPAL;

	retval = kadm5_create_principal(obj->handle, &principal->data, principal->update_mask, pw);
	if(retval != KADM5_OK) {
		zend_throw_exception(NULL, (char*) krb5_get_error_message(obj->ctx, (int)retval), (int)retval TSRMLS_CC);
		return;
	}

	/* Update principal object */
	zend_update_property(krb5_ce_kadm5_principal, princ, "connection", sizeof("connection"), getThis() TSRMLS_CC);

	MAKE_STD_ZVAL(func);
	ZVAL_STRING(func, "load", 1);
	MAKE_STD_ZVAL(dummy_retval);
	if(call_user_function(&krb5_ce_kadm5_principal->function_table,
							&princ, func, dummy_retval, 0,
							NULL TSRMLS_CC) == FAILURE) {

		zval_ptr_dtor(&func);
		zval_ptr_dtor(&dummy_retval);

		zend_throw_exception(NULL, "Failed to update KADM5Principal object", 0 TSRMLS_CC);
		return;
	}

	zval_ptr_dtor(&func);
	zval_ptr_dtor(&dummy_retval);
}

/* {{{ proto KADM5Policy KADM5::getPolicy(string $policy)
	Fetches a policy */
PHP_METHOD(KADM5, getPolicy)
{
	zval *dummy_retval, *ctor;
	zval *args[2];

	zval *spolicy = NULL;

	if(zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "z", &spolicy) == FAILURE) {
		return;
	}

	object_init_ex(return_value, krb5_ce_kadm5_policy);

	MAKE_STD_ZVAL(ctor);
	ZVAL_STRING(ctor, "__construct", 1);

	args[0] = spolicy;
	args[1] = getThis();

	MAKE_STD_ZVAL(dummy_retval);
	if(call_user_function(&krb5_ce_kadm5_policy->function_table,
							&return_value, ctor, dummy_retval, 2,
							args TSRMLS_CC) == FAILURE) {
		zval_dtor(ctor);
		zval_dtor(dummy_retval);
		zend_throw_exception(NULL, "Failed to instantiate KADM5Policy object", 0 TSRMLS_CC);
		return;
	}

	zval_ptr_dtor(&ctor);
	zval_ptr_dtor(&dummy_retval);
} /* }}} */

/* {{{ proto void KADM5::createPolicy(KADM5Policy $policy)
	Creates a Policy */
PHP_METHOD(KADM5, createPolicy) {
	kadm5_ret_t retval;
	zval *zpolicy;
	krb5_kadm5_policy_object *policy;
	krb5_kadm5_object *obj;

	zval *dummy_retval, *func;

	if(zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "O", &zpolicy, krb5_ce_kadm5_policy) == FAILURE) {
		return;
	}

	policy = zend_object_store_get_object(zpolicy TSRMLS_CC);
	obj = zend_object_store_get_object(getThis() TSRMLS_CC);

	policy->update_mask |= KADM5_POLICY;

	policy->data.policy = policy->policy;
	retval = kadm5_create_policy(obj->handle, &policy->data, policy->update_mask);
	if(retval != KADM5_OK) {
		zend_throw_exception(NULL, (char*)krb5_get_error_message(obj->ctx, (int)retval), (int)retval TSRMLS_CC);
		return;
	}

	/* Update principal object */
	zend_update_property(krb5_ce_kadm5_policy, zpolicy, "connection", sizeof("connection"), getThis() TSRMLS_CC);

	MAKE_STD_ZVAL(func);
	ZVAL_STRING(func, "load", 1);
	MAKE_STD_ZVAL(dummy_retval);
	if(call_user_function(&krb5_ce_kadm5_policy->function_table,
							&zpolicy, func, dummy_retval, 0,
							NULL TSRMLS_CC) == FAILURE) {
		zval_ptr_dtor(&func);
		zval_ptr_dtor(&dummy_retval);
		zend_throw_exception(NULL, "Failed to update KADM5Policy object", 0 TSRMLS_CC);
		return;
	}

	zval_ptr_dtor(&func);
	zval_ptr_dtor(&dummy_retval);
} /* }}} */

/* {{{ proto array KADM5::getPolicies([string $filter])
	Fetches all policies */
PHP_METHOD(KADM5, getPolicies)
{
	kadm5_ret_t retval;
	krb5_kadm5_object *obj;

	char *sexp = NULL;
	int sexp_len;

	char **policies;
	int pol_count;

	int i;

	if(zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "|s", &sexp, &sexp_len) == FAILURE) {
		RETURN_FALSE;
	}

	obj = (krb5_kadm5_object*)zend_object_store_get_object(getThis() TSRMLS_CC);
	retval = kadm5_get_policies(obj->handle, sexp, &policies, &pol_count);

	if(retval) {
		zend_throw_exception(NULL, (char*)krb5_get_error_message(obj->ctx, (int)retval), (int)retval TSRMLS_CC);
		return;
	}

	array_init(return_value);

	for(i = 0; i < pol_count; i++) {
		add_next_index_string(return_value, policies[i], 1);
	}

	kadm5_free_name_list(obj->handle, policies, pol_count);
} /* }}} */
