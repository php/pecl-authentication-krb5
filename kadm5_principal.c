/**
* Copyright (c) 2007 Moritz Bechler
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

ZEND_BEGIN_ARG_INFO_EX(arginfo_KADM5Principal_none, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_KADM5Principal__construct, 0, 0, 1)
	ZEND_ARG_INFO(0, principal)
	ZEND_ARG_OBJ_INFO(0, connection, KADM5, 0)
	ZEND_ARG_INFO(0, noload)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_KADM5Principal_changePassword, 0, 0, 1)
	ZEND_ARG_INFO(0, password)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_KADM5Principal_rename, 0, 0, 1)
	ZEND_ARG_INFO(0, dst_name)
	ZEND_ARG_INFO(0, dst_pw)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_KADM5Principal_time, 0, 0, 1)
	ZEND_ARG_INFO(0, time)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_KADM5Principal_setKeyVNO, 0, 0, 1)
	ZEND_ARG_INFO(0, kvno)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_KADM5Principal_setPolicy, 0, 0, 1)
	ZEND_ARG_INFO(0, policy)
ZEND_END_ARG_INFO()

static zend_function_entry krb5_kadm5_principal_functions[] = {
	PHP_ME(KADM5Principal, __construct,             arginfo_KADM5Principal__construct,     ZEND_ACC_PUBLIC | ZEND_ACC_CTOR)
	PHP_ME(KADM5Principal, load,                    arginfo_KADM5Principal_none,           ZEND_ACC_PUBLIC)
	PHP_ME(KADM5Principal, save,                    arginfo_KADM5Principal_none,           ZEND_ACC_PUBLIC)
	PHP_ME(KADM5Principal, delete,                  arginfo_KADM5Principal_none,           ZEND_ACC_PUBLIC)
	PHP_ME(KADM5Principal, rename,                  arginfo_KADM5Principal_rename,         ZEND_ACC_PUBLIC)
	PHP_ME(KADM5Principal, changePassword,          arginfo_KADM5Principal_changePassword, ZEND_ACC_PUBLIC)
	PHP_ME(KADM5Principal, getPropertyArray,        arginfo_KADM5Principal_none,           ZEND_ACC_PUBLIC)
	PHP_ME(KADM5Principal, getName,                 arginfo_KADM5Principal_none,           ZEND_ACC_PUBLIC)
	PHP_ME(KADM5Principal, getExpiryTime,           arginfo_KADM5Principal_none,           ZEND_ACC_PUBLIC)
	PHP_ME(KADM5Principal, setExpiryTime,           arginfo_KADM5Principal_time,           ZEND_ACC_PUBLIC)
	PHP_ME(KADM5Principal, getLastPasswordChange,   arginfo_KADM5Principal_none,           ZEND_ACC_PUBLIC)
	PHP_ME(KADM5Principal, getPasswordExpiryTime,   arginfo_KADM5Principal_none,           ZEND_ACC_PUBLIC)
	PHP_ME(KADM5Principal, setPasswordExpiryTime,   arginfo_KADM5Principal_time,           ZEND_ACC_PUBLIC)
	PHP_ME(KADM5Principal, getMaxTicketLifetime,    arginfo_KADM5Principal_none,           ZEND_ACC_PUBLIC)
	PHP_ME(KADM5Principal, setMaxTicketLifetime,    arginfo_KADM5Principal_time,           ZEND_ACC_PUBLIC)
	PHP_ME(KADM5Principal, getMaxRenewableLifetime, arginfo_KADM5Principal_none,           ZEND_ACC_PUBLIC)
	PHP_ME(KADM5Principal, setMaxRenewableLifetime, arginfo_KADM5Principal_time,           ZEND_ACC_PUBLIC)
	PHP_ME(KADM5Principal, getLastModifier,         arginfo_KADM5Principal_none,           ZEND_ACC_PUBLIC)
	PHP_ME(KADM5Principal, getLastModificationDate, arginfo_KADM5Principal_none,           ZEND_ACC_PUBLIC)
	PHP_ME(KADM5Principal, getKeyVNO,               arginfo_KADM5Principal_none,           ZEND_ACC_PUBLIC)
	PHP_ME(KADM5Principal, setKeyVNO,               arginfo_KADM5Principal_setKeyVNO,      ZEND_ACC_PUBLIC)
	PHP_ME(KADM5Principal, getMasterKeyVNO,         arginfo_KADM5Principal_none,           ZEND_ACC_PUBLIC)
	PHP_ME(KADM5Principal, getAttributes,           arginfo_KADM5Principal_none,           ZEND_ACC_PUBLIC)
	PHP_ME(KADM5Principal, getAuxAttributes,        arginfo_KADM5Principal_none,           ZEND_ACC_PUBLIC)
	PHP_ME(KADM5Principal, getPolicy,               arginfo_KADM5Principal_none,           ZEND_ACC_PUBLIC)
	PHP_ME(KADM5Principal, setPolicy,               arginfo_KADM5Principal_setPolicy,      ZEND_ACC_PUBLIC)
	PHP_ME(KADM5Principal, clearPolicy,             arginfo_KADM5Principal_none,           ZEND_ACC_PUBLIC)
	PHP_ME(KADM5Principal, getLastSuccess,          arginfo_KADM5Principal_none,           ZEND_ACC_PUBLIC)
	PHP_ME(KADM5Principal, getLastFailed,           arginfo_KADM5Principal_none,           ZEND_ACC_PUBLIC)
	PHP_ME(KADM5Principal, getFailedAuthCount,      arginfo_KADM5Principal_none,           ZEND_ACC_PUBLIC)
	PHP_ME(KADM5Principal, resetFailedAuthCount,    arginfo_KADM5Principal_none,           ZEND_ACC_PUBLIC)
	PHP_FE_END
};

zend_object_handlers krb5_kadm5_principal_handlers;

/* KADM5Principal ctor/dtor */
static void php_krb5_kadm5_principal_object_dtor(void *obj, zend_object_handle handle TSRMLS_DC)
{
	krb5_kadm5_principal_object *object = (krb5_kadm5_principal_object*)obj;
	zend_object_std_dtor(&(object->std) TSRMLS_CC);

	if(object) {
		if(object->conn) {
			kadm5_free_principal_ent(object->conn->handle, &object->data);
			php_krb5_free_kadm5_object(object->conn);
		}

		efree(object);
	}
}

int php_krb5_register_kadm5_principal(TSRMLS_D) {
	zend_class_entry kadm5_principal;
	INIT_CLASS_ENTRY(kadm5_principal, "KADM5Principal", krb5_kadm5_principal_functions);
	krb5_ce_kadm5_principal = zend_register_internal_class(&kadm5_principal TSRMLS_CC);
	krb5_ce_kadm5_principal->create_object = php_krb5_kadm5_principal_object_new;
	memcpy(&krb5_kadm5_principal_handlers, zend_get_std_object_handlers(), sizeof(zend_object_handlers));
	return SUCCESS;
}


zend_object_value php_krb5_kadm5_principal_object_new(zend_class_entry *ce TSRMLS_DC)
{
	zend_object_value retval;
	krb5_kadm5_principal_object *object;
	extern zend_object_handlers krb5_kadm5_principal_handlers;

	object = emalloc(sizeof(krb5_kadm5_principal_object));

	memset(&object->data, 0, sizeof(kadm5_principal_ent_rec));
	object->loaded = FALSE;
	object->update_mask = 0;
	object->conn = NULL;

	zend_object_std_init(&(object->std), ce TSRMLS_CC);

#if PHP_VERSION_ID < 50399
	zend_hash_copy(object->std.properties, &ce->default_properties,
					(copy_ctor_func_t) zval_add_ref, NULL, 
					sizeof(zval*));
#else
	object_properties_init(&(object->std), ce);
#endif

	retval.handle = zend_objects_store_put(object, php_krb5_kadm5_principal_object_dtor, NULL, NULL TSRMLS_CC);
	retval.handlers = &krb5_kadm5_principal_handlers;
	return retval;
}

/* {{{ proto KADM5Principal KADM5Principal::__construct(string $principal [, KADM5 $connection [, boolean $noload] ])
 */
PHP_METHOD(KADM5Principal, __construct)
{

	char *sprinc = NULL;
	int sprinc_len;

	zend_bool noload = FALSE;
	zval *obj = NULL;
	zval *dummy_retval, *func;

	KRB5_SET_ERROR_HANDLING(EH_THROW);
	if(zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s|Ob", &sprinc, &sprinc_len, &obj, krb5_ce_kadm5, &noload) == FAILURE) {
		RETURN_NULL();
	}
	KRB5_SET_ERROR_HANDLING(EH_NORMAL);

	zend_update_property_string(krb5_ce_kadm5_principal, getThis(), "princname", sizeof("princname"), sprinc TSRMLS_CC);

	if(obj && Z_TYPE_P(obj) == IS_OBJECT) {
		zend_update_property(krb5_ce_kadm5_principal, getThis(), "connection", sizeof("connection"), obj TSRMLS_CC);

		if ( noload != TRUE ) {
			MAKE_STD_ZVAL(func);
			ZVAL_STRING(func, "load", 1);
			MAKE_STD_ZVAL(dummy_retval);
			if(call_user_function(&krb5_ce_kadm5_principal->function_table, 
									&getThis(), func, dummy_retval, 0, 
									NULL TSRMLS_CC) == FAILURE) {
				zval_ptr_dtor(&func);
				zval_ptr_dtor(&dummy_retval);
				zend_throw_exception(NULL, "Failed to update KADM5Principal object", 0 TSRMLS_CC);
				return;
			}

			zval_ptr_dtor(&func);
			zval_ptr_dtor(&dummy_retval);
		}
	}
}
/* }}} */

/* {{{ proto KADM5Principal KADM5Principal::load()
 */
PHP_METHOD(KADM5Principal, load)
{
	kadm5_ret_t retval;
	krb5_kadm5_principal_object *obj = (krb5_kadm5_principal_object*)zend_object_store_get_object(getThis() TSRMLS_CC);
	krb5_kadm5_object *kadm5;
	zval *connobj = NULL;
	zval *princname = NULL;

	if (zend_parse_parameters_none() == FAILURE) {
		return;
	}

	connobj = zend_read_property(krb5_ce_kadm5_principal, getThis(), "connection",
									sizeof("connection"),1 TSRMLS_CC);
	princname = zend_read_property(krb5_ce_kadm5_principal, getThis(), "princname", 
									sizeof("princname"),1 TSRMLS_CC);

	kadm5 = (krb5_kadm5_object*)zend_object_store_get_object(connobj TSRMLS_CC);
	if(!kadm5) {
		zend_throw_exception(NULL, "No valid connection available", 0 TSRMLS_CC);
		return;
	}

	if(krb5_parse_name(kadm5->ctx, Z_STRVAL_P(princname), &obj->data.principal)) {
		zend_throw_exception(NULL, "Failed to parse principal name", 0 TSRMLS_CC);
		return;
	}

	retval = kadm5_get_principal(kadm5->handle, obj->data.principal, &obj->data, KADM5_PRINCIPAL_NORMAL_MASK);
	if(retval != KADM5_OK) {
		zend_throw_exception(NULL, krb5_get_error_message(kadm5->ctx, (int)retval), (int)retval TSRMLS_CC);
		return;
	}

	obj->loaded = TRUE;
	obj->update_mask = 0;

	if(!obj->conn) {
		obj->conn = kadm5;
		kadm5->refcount++;
	}

	RETURN_TRUE;
}
/* }}} */

/* {{{ proto KADM5Principal KADM5Principal::save()
 */
PHP_METHOD(KADM5Principal, save)
{
	kadm5_ret_t retval;
	krb5_kadm5_principal_object *obj = (krb5_kadm5_principal_object*)zend_object_store_get_object(getThis() TSRMLS_CC);

	krb5_kadm5_object *kadm5;
	zval *connobj = NULL;

	if (zend_parse_parameters_none() == FAILURE) {
		return;
	}


	connobj = zend_read_property(krb5_ce_kadm5_principal, getThis(), "connection",
									sizeof("connection"),1 TSRMLS_CC);

	kadm5 = (krb5_kadm5_object*)zend_object_store_get_object(connobj TSRMLS_CC);
	if(!kadm5) {
		zend_throw_exception(NULL, "No valid connection available", 0 TSRMLS_CC);
		return;
	}

	if(obj->update_mask == 0) {
		RETURN_TRUE;
	}

	retval = kadm5_modify_principal(kadm5->handle, &obj->data, obj->update_mask);
	if(retval != KADM5_OK) {
		zend_throw_exception(NULL, krb5_get_error_message(kadm5->ctx, (int)retval), (int)retval TSRMLS_CC);
		return;
	}

	obj->update_mask = 0;

	RETURN_TRUE;
}
/* }}} */

/* {{{ proto KADM5Principal KADM5Principal::changePassword(string $password)
 */
PHP_METHOD(KADM5Principal, changePassword)
{
	kadm5_ret_t retval;
	krb5_kadm5_object *kadm5 = NULL;
	zval *connobj = NULL;
	zval *princname = NULL;

	char *newpass = NULL;
	int newpass_len;

	krb5_principal princ;

	if(zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", &newpass, &newpass_len) == FAILURE) {
		RETURN_FALSE;
	}

	connobj = zend_read_property(krb5_ce_kadm5_principal, getThis(), "connection", 
									sizeof("connection"),1 TSRMLS_CC);
	princname = zend_read_property(krb5_ce_kadm5_principal, getThis(), "princname", 
									sizeof("princname"),1 TSRMLS_CC);


	kadm5 = (krb5_kadm5_object*)zend_object_store_get_object(connobj TSRMLS_CC);
	if(!kadm5) {
		zend_throw_exception(NULL, "No valid connection available", 0 TSRMLS_CC);
		return;
	}
    
	convert_to_string(princname);

	if(krb5_parse_name(kadm5->ctx, Z_STRVAL_P(princname), &princ)) {
		zend_throw_exception(NULL, "Failed to parse principal name", 0 TSRMLS_CC);
		return;
	}

	retval = kadm5_chpass_principal(kadm5->handle, princ, newpass);
	krb5_free_principal(kadm5->ctx, princ);

	if(retval != KADM5_OK) {
		zend_throw_exception(NULL, krb5_get_error_message(kadm5->ctx, (int)retval), (int)retval TSRMLS_CC);
		return;
	}

	RETURN_TRUE;
}
/* }}} */

/* {{{ proto KADM5Principal KADM5Principal::delete()
 */
PHP_METHOD(KADM5Principal, delete)
{
	kadm5_ret_t retval;
	krb5_kadm5_principal_object *obj = (krb5_kadm5_principal_object*)zend_object_store_get_object(getThis() TSRMLS_CC);

	krb5_kadm5_object *kadm5;
	zval *connobj = NULL;

	if (zend_parse_parameters_none() == FAILURE) {
		return;
	}

	if ( ! obj->loaded ) {
		zend_throw_exception(NULL, "Object is not loaded", 0 TSRMLS_CC);
		return;
	}

	connobj = zend_read_property(krb5_ce_kadm5_principal, getThis(), "connection",
									sizeof("connection"),1 TSRMLS_CC);

	kadm5 = (krb5_kadm5_object*)zend_object_store_get_object(connobj TSRMLS_CC);
	if(!kadm5) {
		zend_throw_exception(NULL, "No valid connection available", 0 TSRMLS_CC);
		return;
	}


	retval = kadm5_delete_principal(kadm5->handle, obj->data.principal);
	if(retval != KADM5_OK) {
		zend_throw_exception(NULL, krb5_get_error_message(kadm5->ctx, (int)retval), (int)retval TSRMLS_CC);
		return;
	}
	obj->loaded = FALSE;

	RETURN_TRUE;
}
/* }}} */

/* {{{ proto KADM5Principal KADM5Principal::rename(string $dst_name [, string $dst_pw ])
 */
PHP_METHOD(KADM5Principal, rename)
{
	kadm5_ret_t retval;
	krb5_kadm5_principal_object *obj = (krb5_kadm5_principal_object*)zend_object_store_get_object(getThis() TSRMLS_CC);
	krb5_kadm5_object *kadm5;
	zval *connobj = NULL;
	char *dst_name = NULL, *dst_pw = NULL;
	int dst_name_len, dst_pw_len;
	krb5_principal dst_princ;

	if(zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s|s", &dst_name, &dst_name_len,
								&dst_pw, &dst_pw_len) == FAILURE) {
		RETURN_FALSE;
	}

	if ( ! obj->loaded ) {
		zend_throw_exception(NULL, "Object is not loaded", 0 TSRMLS_CC);
		return;
	}

	connobj = zend_read_property(krb5_ce_kadm5_principal, getThis(), "connection", 
									sizeof("connection"),1 TSRMLS_CC);

	kadm5 = (krb5_kadm5_object*)zend_object_store_get_object(connobj TSRMLS_CC);
	if(!kadm5) {
		zend_throw_exception(NULL, "No valid connection available", 0 TSRMLS_CC);
		return;
	}


	krb5_parse_name(kadm5->ctx, dst_name, &dst_princ);
	retval = kadm5_rename_principal(kadm5->handle, obj->data.principal, dst_princ);
	if(retval != KADM5_OK) {
		zend_throw_exception(NULL, krb5_get_error_message(kadm5->ctx, (int)retval), (int)retval TSRMLS_CC);
		return;
	}
	
	if(dst_pw) {
		retval = kadm5_chpass_principal(kadm5->handle, dst_princ, dst_pw);
		if(retval != KADM5_OK) {
			zend_throw_exception(NULL, krb5_get_error_message(kadm5->ctx, (int)retval), (int)retval TSRMLS_CC);
			return;
		}
	}

	retval = kadm5_get_principal(kadm5->handle, dst_princ, &obj->data, KADM5_PRINCIPAL_NORMAL_MASK);
	if(retval != KADM5_OK) {
		zend_throw_exception(NULL, krb5_get_error_message(kadm5->ctx, (int)retval), (int)retval TSRMLS_CC);
		return;
	}
}
/* }}} */

/** property accessors **/

/* {{{ proto KADM5Principal KADM5Principal::getPropertyArray()
 */
PHP_METHOD(KADM5Principal, getPropertyArray)
{
	krb5_kadm5_principal_object *obj = (krb5_kadm5_principal_object*)zend_object_store_get_object(getThis() TSRMLS_CC);

	krb5_kadm5_object *kadm5;
	zval *connobj = NULL;
	connobj = zend_read_property(krb5_ce_kadm5_principal, getThis(), "connection", 
									sizeof("connection"),1 TSRMLS_CC);

	if (zend_parse_parameters_none() == FAILURE) {
		return;
	}


	kadm5 = (krb5_kadm5_object*)zend_object_store_get_object(connobj TSRMLS_CC);
	if(!kadm5) {
		zend_throw_exception(NULL, "No valid connection available", 0 TSRMLS_CC);
		return;
	}

	array_init(return_value);

	char *tstring;
	if ( obj->data.principal != NULL ) {
		krb5_unparse_name(kadm5->ctx, obj->data.principal, &tstring);
		add_assoc_string(return_value, "princname", tstring, 1);
	} else {
		zval *val;
		val = zend_read_property(krb5_ce_kadm5_principal, getThis(), "princname", 
									sizeof("princname"),1 TSRMLS_CC);
		convert_to_string(val);
		add_assoc_string(return_value, "princname", Z_STRVAL_P(val), 1);
		zval_ptr_dtor(&val);
	}
	add_assoc_long(return_value, "princ_expire_time", obj->data.princ_expire_time);
	add_assoc_long(return_value, "last_pwd_change", obj->data.last_pwd_change);
	add_assoc_long(return_value, "pw_expiration", obj->data.pw_expiration);
	add_assoc_long(return_value, "max_life", obj->data.max_life);
	
	if ( obj->data.mod_name ) {
		krb5_unparse_name(kadm5->ctx, obj->data.mod_name, &tstring);
		add_assoc_string(return_value, "mod_name", tstring, 1);
	}

	add_assoc_long(return_value, "mod_date", obj->data.mod_date);
	add_assoc_long(return_value, "attributes", obj->data.attributes);
	add_assoc_long(return_value, "kvno", obj->data.kvno);
	add_assoc_long(return_value, "mkvno", obj->data.mkvno);
	if(obj->data.policy) add_assoc_string(return_value, "policy", obj->data.policy, 1);
	add_assoc_long(return_value, "aux_attributes", obj->data.aux_attributes);
	add_assoc_long(return_value, "max_renewable_life", obj->data.max_renewable_life);
	add_assoc_long(return_value, "last_success", obj->data.last_success);
	add_assoc_long(return_value, "last_failed", obj->data.last_failed);
	add_assoc_long(return_value, "fail_auth_count", obj->data.fail_auth_count);
}
/* }}} */

/* {{{ proto KADM5Principal KADM5Principal::getName()
 */
PHP_METHOD(KADM5Principal, getName)
{
	krb5_kadm5_principal_object *obj = (krb5_kadm5_principal_object*)zend_object_store_get_object(getThis() TSRMLS_CC);
	
	if (zend_parse_parameters_none() == FAILURE) {
		return;
	}
	if(obj->loaded) {
		char *princname;
		krb5_kadm5_object *kadm5;
		zval *connobj = NULL;

		connobj = zend_read_property(krb5_ce_kadm5_principal, getThis(), "connection", 
									sizeof("connection"),1 TSRMLS_CC);
		kadm5 = (krb5_kadm5_object*)zend_object_store_get_object(connobj TSRMLS_CC);

		krb5_unparse_name(kadm5->ctx,obj->data.principal,&princname);
		ZVAL_STRING(return_value, princname, 1);
		free(princname);
	} else {
		zval *val;
		val = zend_read_property(krb5_ce_kadm5_principal, getThis(), "princname", 
									sizeof("princname"),1 TSRMLS_CC);
		convert_to_string(val);
		ZVAL_STRING(return_value, Z_STRVAL_P(val), 1);
		zval_ptr_dtor(&val);
	}
}
/* }}} */

/* {{{ proto KADM5Principal KADM5Principal::getExpiryTime()
 */
PHP_METHOD(KADM5Principal, getExpiryTime)
{
	krb5_kadm5_principal_object *obj = (krb5_kadm5_principal_object*)zend_object_store_get_object(getThis() TSRMLS_CC);

	if (zend_parse_parameters_none() == FAILURE) {
		return;
	}

	RETURN_LONG(obj->data.princ_expire_time);
}
/* }}} */

/* {{{ proto KADM5Principal KADM5Principal::setExpiryTime(int $expiry_time)
 */
PHP_METHOD(KADM5Principal, setExpiryTime)
{
	krb5_kadm5_principal_object *obj = (krb5_kadm5_principal_object*)zend_object_store_get_object(getThis() TSRMLS_CC);
	long expiry_time;

	if(zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "l", &expiry_time) == FAILURE) {
		RETURN_FALSE;
	}

	obj->data.princ_expire_time = expiry_time;
	obj->update_mask |= KADM5_PRINC_EXPIRE_TIME;

	RETURN_TRUE;
}
/* }}} */

/* {{{ proto KADM5Principal KADM5Principal::getLastPasswordChange()
 */
PHP_METHOD(KADM5Principal, getLastPasswordChange)
{
	krb5_kadm5_principal_object *obj = (krb5_kadm5_principal_object*)zend_object_store_get_object(getThis() TSRMLS_CC);

	if (zend_parse_parameters_none() == FAILURE) {
		return;
	}
	RETURN_LONG(obj->data.last_pwd_change);
}
/* }}} */

/* {{{ proto KADM5Principal KADM5Principal::getPasswordExpiryTime()
 */
PHP_METHOD(KADM5Principal, getPasswordExpiryTime)
{
	krb5_kadm5_principal_object *obj = (krb5_kadm5_principal_object*)zend_object_store_get_object(getThis() TSRMLS_CC);

	if (zend_parse_parameters_none() == FAILURE) {
		return;
	}
	RETURN_LONG(obj->data.pw_expiration);
}
/* }}} */

/* {{{ proto KADM5Principal KADM5Principal::setPasswordExpiryTime(int $pwd_expiry_time)
 */
PHP_METHOD(KADM5Principal, setPasswordExpiryTime)
{
	krb5_kadm5_principal_object *obj = (krb5_kadm5_principal_object*)zend_object_store_get_object(getThis() TSRMLS_CC);
	long pwd_expiry_time;

	if(zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "l", &pwd_expiry_time) == FAILURE) {
		RETURN_FALSE;
	}

	obj->data.pw_expiration = pwd_expiry_time;
	obj->update_mask |= KADM5_PW_EXPIRATION;

	RETURN_TRUE;
}
/* }}} */

/* {{{ proto KADM5Principal KADM5Principal::getMaxTicketLifetime()
 */
PHP_METHOD(KADM5Principal, getMaxTicketLifetime)
{
	krb5_kadm5_principal_object *obj = (krb5_kadm5_principal_object*)zend_object_store_get_object(getThis() TSRMLS_CC);

	if (zend_parse_parameters_none() == FAILURE) {
		return;
	}
	RETURN_LONG(obj->data.max_life);
}
/* }}} */

/* {{{ proto KADM5Principal KADM5Principal::setMaxTicketLifetime(int $max_lifetime)
 */
PHP_METHOD(KADM5Principal, setMaxTicketLifetime)
{
	krb5_kadm5_principal_object *obj = (krb5_kadm5_principal_object*)zend_object_store_get_object(getThis() TSRMLS_CC);
	long max_lifetime;

	if(zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "l", &max_lifetime) == FAILURE) {
		RETURN_FALSE;
	}

	obj->data.max_life = max_lifetime;
	obj->update_mask |= KADM5_MAX_LIFE;

	RETURN_TRUE;
}
/* }}} */

/* {{{ proto KADM5Principal KADM5Principal::getMaxRenewableLifetime()
 */
PHP_METHOD(KADM5Principal, getMaxRenewableLifetime)
{
	krb5_kadm5_principal_object *obj = (krb5_kadm5_principal_object*)zend_object_store_get_object(getThis() TSRMLS_CC);

	if (zend_parse_parameters_none() == FAILURE) {
		return;
	}
	RETURN_LONG(obj->data.max_renewable_life);
}
/* }}} */

/* {{{ proto KADM5Principal KADM5Principal::setMaxRenewableLifetime(int $max_renewable_lifetime)
 */
PHP_METHOD(KADM5Principal, setMaxRenewableLifetime)
{
	krb5_kadm5_principal_object *obj = (krb5_kadm5_principal_object*)zend_object_store_get_object(getThis() TSRMLS_CC);
	long max_renewable_lifetime;

	if(zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "l", &max_renewable_lifetime) == FAILURE) {
		RETURN_FALSE;
	}

	obj->data.max_renewable_life = max_renewable_lifetime;
	obj->update_mask |= KADM5_MAX_RLIFE;

	RETURN_TRUE;
}
/* }}} */

/* {{{ proto KADM5Principal KADM5Principal::getLastModifier()
 */
PHP_METHOD(KADM5Principal, getLastModifier)
{
	char *princname;
	krb5_kadm5_principal_object *obj = (krb5_kadm5_principal_object*)zend_object_store_get_object(getThis() TSRMLS_CC);
	krb5_kadm5_object *kadm5;
	zval *connobj = NULL;

	if (zend_parse_parameters_none() == FAILURE) {
		return;
	}
	connobj = zend_read_property(krb5_ce_kadm5_principal, getThis(), "connection",
									sizeof("connection"),1 TSRMLS_CC);
	kadm5 = (krb5_kadm5_object*)zend_object_store_get_object(connobj TSRMLS_CC);
	
	if(obj->loaded) {
		krb5_unparse_name(kadm5->ctx,obj->data.mod_name,&princname);
		RETURN_STRING(princname, 1);
		free(princname);
	} else {
		RETURN_NULL();
	}
}
/* }}} */

/* {{{ proto KADM5Principal KADM5Principal::getLastModificationDate()
 */
PHP_METHOD(KADM5Principal, getLastModificationDate)
{
	krb5_kadm5_principal_object *obj = (krb5_kadm5_principal_object*)zend_object_store_get_object(getThis() TSRMLS_CC);

	if (zend_parse_parameters_none() == FAILURE) {
		return;
	}
	RETURN_LONG(obj->data.mod_date);
}
/* }}} */

/* {{{ proto KADM5Principal KADM5Principal::getKeyVNO()
 */
PHP_METHOD(KADM5Principal, getKeyVNO)
{
	krb5_kadm5_principal_object *obj = (krb5_kadm5_principal_object*)zend_object_store_get_object(getThis() TSRMLS_CC);

	if (zend_parse_parameters_none() == FAILURE) {
		return;
	}
	RETURN_LONG(obj->data.kvno);
}
/* }}} */

/* {{{ proto KADM5Principal KADM5Principal::setKeyVNO(int $kvno)
 */
PHP_METHOD(KADM5Principal, setKeyVNO)
{
	krb5_kadm5_principal_object *obj = (krb5_kadm5_principal_object*)zend_object_store_get_object(getThis() TSRMLS_CC);
	long kvno;

	if(zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "l", &kvno) == FAILURE) {
		RETURN_FALSE;
	}

	obj->data.kvno = kvno;
	obj->update_mask |= KADM5_KVNO;

	RETURN_TRUE;
}
/* }}} */

/* {{{ proto KADM5Principal KADM5Principal::getMasterKeyVNO()
 */
PHP_METHOD(KADM5Principal, getMasterKeyVNO)
{
	krb5_kadm5_principal_object *obj = (krb5_kadm5_principal_object*)zend_object_store_get_object(getThis() TSRMLS_CC);

	if (zend_parse_parameters_none() == FAILURE) {
		return;
	}
	RETURN_LONG(obj->data.mkvno);
}
/* }}} */

/* {{{ proto KADM5Principal KADM5Principal::getAttributes()
 */
PHP_METHOD(KADM5Principal, getAttributes)
{
	krb5_kadm5_principal_object *obj = (krb5_kadm5_principal_object*)zend_object_store_get_object(getThis() TSRMLS_CC);

	if (zend_parse_parameters_none() == FAILURE) {
		return;
	}
	RETURN_LONG(obj->data.attributes);
}
/* }}} */

/* {{{ proto KADM5Principal KADM5Principal::getAuxAttributes()
 */
PHP_METHOD(KADM5Principal, getAuxAttributes)
{
	krb5_kadm5_principal_object *obj = (krb5_kadm5_principal_object*)zend_object_store_get_object(getThis() TSRMLS_CC);

	if (zend_parse_parameters_none() == FAILURE) {
		return;
	}
	RETURN_LONG(obj->data.aux_attributes);
}
/* }}} */

/* {{{ proto KADM5Principal KADM5Principal::getPolicy()
 */
PHP_METHOD(KADM5Principal, getPolicy)
{
	krb5_kadm5_principal_object *obj = (krb5_kadm5_principal_object*)zend_object_store_get_object(getThis() TSRMLS_CC);
	zval *connobj = NULL;
	zval *func;
	zval *args[1];

	if (zend_parse_parameters_none() == FAILURE) {
		return;
	}
	if(obj->data.policy) {

		connobj = zend_read_property(krb5_ce_kadm5_principal, getThis(), "connection", 
									sizeof("connection"),1 TSRMLS_CC);
		
		MAKE_STD_ZVAL(func);
		ZVAL_STRING(func, "getPolicy", 1);
		MAKE_STD_ZVAL(args[0]);
		ZVAL_STRING(args[0], obj->data.policy, 1);
		
		if(call_user_function(&krb5_ce_kadm5_policy->function_table, 
								&connobj, func, return_value, 1, 
								args TSRMLS_CC) == FAILURE) {
			zval_ptr_dtor(&args[0]);
			zval_ptr_dtor(&func);
			zend_throw_exception(NULL, "Failed to instantiate KADM5Policy object", 0 TSRMLS_CC);
			return;
		}

		zval_ptr_dtor(&args[0]);
		zval_ptr_dtor(&func);
	}
}
/* }}} */

/* {{{ proto KADM5Principal KADM5Principal::setPolicy(mixed $policy)
 */
PHP_METHOD(KADM5Principal, setPolicy)
{
	krb5_kadm5_principal_object *obj = (krb5_kadm5_principal_object*)zend_object_store_get_object(getThis() TSRMLS_CC);
	zval *policy = NULL;
	krb5_kadm5_policy_object *pol;

	if(zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "|z", &policy) == FAILURE) {
		RETURN_FALSE;
	}

	if(obj->data.policy) {
		free(obj->data.policy);
	}

	switch(Z_TYPE_P(policy)) {

		case IS_NULL:
			if(obj->data.policy) {
				obj->data.policy = NULL;
				obj->update_mask |= KADM5_POLICY_CLR;
			}
			break;

		case IS_OBJECT:
			if(Z_OBJCE_P(policy) == krb5_ce_kadm5_policy) {
				pol = (krb5_kadm5_policy_object*)zend_object_store_get_object(policy TSRMLS_CC);

				obj->data.policy = strdup(pol->policy);
				obj->update_mask |= KADM5_POLICY;
				break;
			}

		default:
			//zval_copy_ctor(policy),
			//convert_to_string(policy);
			obj->data.policy = strdup(Z_STRVAL_P(policy));
			obj->update_mask |= KADM5_POLICY;
			//zval_ptr_dtor(&policy);
			break;

	}

	RETURN_TRUE;
}
/* }}} */

/* {{{ proto KADM5Principal KADM5Principal::clearPolicy()
 */
PHP_METHOD(KADM5Principal, clearPolicy)
{	
	krb5_kadm5_principal_object *obj = (krb5_kadm5_principal_object*)zend_object_store_get_object(getThis() TSRMLS_CC);

	if (zend_parse_parameters_none() == FAILURE) {
		return;
	}
	obj->data.policy = NULL;
	obj->update_mask |= KADM5_POLICY_CLR;

	RETURN_TRUE;
}
/* }}} */

/* {{{ proto KADM5Principal KADM5Principal::getLastSuccess()
 */
PHP_METHOD(KADM5Principal, getLastSuccess)
{
	krb5_kadm5_principal_object *obj = (krb5_kadm5_principal_object*)zend_object_store_get_object(getThis() TSRMLS_CC);

	if (zend_parse_parameters_none() == FAILURE) {
		return;
	}
	RETURN_LONG(obj->data.last_success);
}
/* }}} */

/* {{{ proto KADM5Principal KADM5Principal::getLastFailed()
 */
PHP_METHOD(KADM5Principal, getLastFailed)
{
	krb5_kadm5_principal_object *obj = (krb5_kadm5_principal_object*)zend_object_store_get_object(getThis() TSRMLS_CC);

	if (zend_parse_parameters_none() == FAILURE) {
		return;
	}
	RETURN_LONG(obj->data.last_failed);
}
/* }}} */

/* {{{ proto KADM5Principal KADM5Principal::getFailedAuthCount()
 */
PHP_METHOD(KADM5Principal, getFailedAuthCount)
{
	krb5_kadm5_principal_object *obj = (krb5_kadm5_principal_object*)zend_object_store_get_object(getThis() TSRMLS_CC);

	if (zend_parse_parameters_none() == FAILURE) {
		return;
	}
	RETURN_LONG(obj->data.fail_auth_count);
}
/* }}} */

/* {{{ proto KADM5Principal KADM5Principal::resetFailedAuthCount()
 */
PHP_METHOD(KADM5Principal, resetFailedAuthCount)
{
	krb5_kadm5_principal_object *obj = (krb5_kadm5_principal_object*)zend_object_store_get_object(getThis() TSRMLS_CC);
	
	if (zend_parse_parameters_none() == FAILURE) {
		return;
	}
	obj->data.fail_auth_count = 0;
	obj->update_mask |= KADM5_FAIL_AUTH_COUNT;
}
/* }}} */
