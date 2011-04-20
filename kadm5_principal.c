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


static function_entry krb5_kadm5_principal_functions[] = {
	PHP_ME(KADM5Principal, __construct, NULL, ZEND_ACC_PUBLIC | ZEND_ACC_CTOR)
	PHP_ME(KADM5Principal, load, NULL, ZEND_ACC_PUBLIC)
	PHP_ME(KADM5Principal, save, NULL, ZEND_ACC_PUBLIC)
	PHP_ME(KADM5Principal, delete, NULL, ZEND_ACC_PUBLIC)
	PHP_ME(KADM5Principal, rename, NULL, ZEND_ACC_PUBLIC)
	PHP_ME(KADM5Principal, changePassword, NULL, ZEND_ACC_PUBLIC)

	PHP_ME(KADM5Principal, getPropertyArray, NULL, ZEND_ACC_PUBLIC)

	PHP_ME(KADM5Principal, getName, NULL, ZEND_ACC_PUBLIC)
	PHP_ME(KADM5Principal, getExpiryTime, NULL, ZEND_ACC_PUBLIC)
	PHP_ME(KADM5Principal, setExpiryTime, NULL, ZEND_ACC_PUBLIC)
	PHP_ME(KADM5Principal, getLastPasswordChange, NULL, ZEND_ACC_PUBLIC)
	PHP_ME(KADM5Principal, getPasswordExpiryTime, NULL, ZEND_ACC_PUBLIC)
	PHP_ME(KADM5Principal, setPasswordExpiryTime, NULL, ZEND_ACC_PUBLIC)
	PHP_ME(KADM5Principal, getMaxTicketLifetime, NULL, ZEND_ACC_PUBLIC)
	PHP_ME(KADM5Principal, setMaxTicketLifetime, NULL, ZEND_ACC_PUBLIC)
	PHP_ME(KADM5Principal, getLastModifier, NULL, ZEND_ACC_PUBLIC)
	PHP_ME(KADM5Principal, getLastModificationDate, NULL, ZEND_ACC_PUBLIC)
	PHP_ME(KADM5Principal, getKeyVNO, NULL, ZEND_ACC_PUBLIC)
	PHP_ME(KADM5Principal, setKeyVNO, NULL, ZEND_ACC_PUBLIC)
	PHP_ME(KADM5Principal, getMasterKeyVNO, NULL, ZEND_ACC_PUBLIC)
	PHP_ME(KADM5Principal, getAttributes, NULL, ZEND_ACC_PUBLIC)
	PHP_ME(KADM5Principal, getAuxAttributes, NULL, ZEND_ACC_PUBLIC)
	PHP_ME(KADM5Principal, getPolicy, NULL, ZEND_ACC_PUBLIC)
	PHP_ME(KADM5Principal, setPolicy, NULL, ZEND_ACC_PUBLIC)
	PHP_ME(KADM5Principal, clearPolicy, NULL, ZEND_ACC_PUBLIC)
	PHP_ME(KADM5Principal, getLastSuccess, NULL, ZEND_ACC_PUBLIC)
	PHP_ME(KADM5Principal, getLastFailed, NULL, ZEND_ACC_PUBLIC)
	PHP_ME(KADM5Principal, getFailedAuthCount, NULL, ZEND_ACC_PUBLIC)
	PHP_ME(KADM5Principal, resetFailedAuthCount, NULL, ZEND_ACC_PUBLIC)
	{ NULL, NULL, NULL }
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

	zend_hash_copy(object->std.properties, &ce->default_properties,
					(copy_ctor_func_t) zval_add_ref, NULL, 
					sizeof(zval*));

	retval.handle = zend_objects_store_put(object, php_krb5_kadm5_principal_object_dtor, NULL, NULL TSRMLS_CC);
	retval.handlers = &krb5_kadm5_principal_handlers;
	return retval;
}

PHP_METHOD(KADM5Principal, __construct) 
{

	char *sprinc = NULL;
	int sprinc_len;

	zval *obj = NULL;
	zval *dummy_retval, *func;

	if(zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s|O", &sprinc, &sprinc_len, &obj, krb5_ce_kadm5) == FAILURE) {
		RETURN_NULL();
	}

	zend_update_property_string(krb5_ce_kadm5_principal, getThis(), "princname", sizeof("princname"), sprinc TSRMLS_CC);

	if(obj && Z_TYPE_P(obj) == IS_OBJECT) {
		zend_update_property(krb5_ce_kadm5_principal, getThis(), "connection", sizeof("connection"), obj TSRMLS_CC);

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

PHP_METHOD(KADM5Principal, load) 
{
	kadm5_ret_t retval;
	krb5_kadm5_principal_object *obj = (krb5_kadm5_principal_object*)zend_object_store_get_object(getThis() TSRMLS_CC);
	krb5_kadm5_object *kadm5;
	zval *connobj = NULL;
	zval *princname = NULL;

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

PHP_METHOD(KADM5Principal, save)
{
	kadm5_ret_t retval;
	krb5_kadm5_principal_object *obj = (krb5_kadm5_principal_object*)zend_object_store_get_object(getThis() TSRMLS_CC);

	krb5_kadm5_object *kadm5;
	zval *connobj = NULL;
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

PHP_METHOD(KADM5Principal, delete)
{
	kadm5_ret_t retval;
	krb5_kadm5_principal_object *obj = (krb5_kadm5_principal_object*)zend_object_store_get_object(getThis() TSRMLS_CC);

	krb5_kadm5_object *kadm5;
	zval *connobj = NULL;
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

PHP_METHOD(KADM5Principal, rename)
{
	kadm5_ret_t retval;
	krb5_kadm5_principal_object *obj = (krb5_kadm5_principal_object*)zend_object_store_get_object(getThis() TSRMLS_CC);
	krb5_kadm5_object *kadm5;
	zval *connobj = NULL;
	char *dst_name = NULL, *dst_pw = NULL;
	int dst_name_len, dst_pw_len;
	krb5_principal dst_princ;



	connobj = zend_read_property(krb5_ce_kadm5_principal, getThis(), "connection", 
									sizeof("connection"),1 TSRMLS_CC);

	kadm5 = (krb5_kadm5_object*)zend_object_store_get_object(connobj TSRMLS_CC);
	if(!kadm5) {
		zend_throw_exception(NULL, "No valid connection available", 0 TSRMLS_CC);
		return;
	}

	if(zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s|s", &dst_name, &dst_name_len,
								&dst_pw, &dst_pw_len) == FAILURE) {
		RETURN_FALSE;
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

/** property accessors **/

PHP_METHOD(KADM5Principal, getPropertyArray)
{
	krb5_kadm5_principal_object *obj = (krb5_kadm5_principal_object*)zend_object_store_get_object(getThis() TSRMLS_CC);

	krb5_kadm5_object *kadm5;
	zval *connobj = NULL;
	connobj = zend_read_property(krb5_ce_kadm5_principal, getThis(), "connection", 
									sizeof("connection"),1 TSRMLS_CC);

	kadm5 = (krb5_kadm5_object*)zend_object_store_get_object(connobj TSRMLS_CC);
	if(!kadm5) {
		zend_throw_exception(NULL, "No valid connection available", 0 TSRMLS_CC);
		return;
	}

	array_init(return_value);

	char *tstring;
	krb5_unparse_name(kadm5->ctx, obj->data.principal, &tstring);
	add_assoc_string(return_value, "princname", tstring, 1);
	add_assoc_long(return_value, "princ_expire_time", obj->data.princ_expire_time);
	add_assoc_long(return_value, "last_pwd_change", obj->data.last_pwd_change);
	add_assoc_long(return_value, "pw_expiration", obj->data.pw_expiration);
	add_assoc_long(return_value, "max_life", obj->data.max_life);
	krb5_unparse_name(kadm5->ctx, obj->data.mod_name, &tstring);
	add_assoc_string(return_value, "mod_name", tstring, 1);
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

PHP_METHOD(KADM5Principal, getName) 
{
	krb5_kadm5_principal_object *obj = (krb5_kadm5_principal_object*)zend_object_store_get_object(getThis() TSRMLS_CC);
	
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

PHP_METHOD(KADM5Principal, getExpiryTime) 
{
	krb5_kadm5_principal_object *obj = (krb5_kadm5_principal_object*)zend_object_store_get_object(getThis() TSRMLS_CC);
	RETURN_LONG(obj->data.princ_expire_time);
}

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

PHP_METHOD(KADM5Principal, getLastPasswordChange) 
{
	krb5_kadm5_principal_object *obj = (krb5_kadm5_principal_object*)zend_object_store_get_object(getThis() TSRMLS_CC);
	RETURN_LONG(obj->data.last_pwd_change);
}

PHP_METHOD(KADM5Principal, getPasswordExpiryTime) 
{
	krb5_kadm5_principal_object *obj = (krb5_kadm5_principal_object*)zend_object_store_get_object(getThis() TSRMLS_CC);
	RETURN_LONG(obj->data.pw_expiration);
}

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

PHP_METHOD(KADM5Principal, getMaxTicketLifetime) 
{
	krb5_kadm5_principal_object *obj = (krb5_kadm5_principal_object*)zend_object_store_get_object(getThis() TSRMLS_CC);
	RETURN_LONG(obj->data.max_life);
}


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

PHP_METHOD(KADM5Principal, getMaxRenewableLifetime) 
{
	krb5_kadm5_principal_object *obj = (krb5_kadm5_principal_object*)zend_object_store_get_object(getThis() TSRMLS_CC);
	RETURN_LONG(obj->data.max_renewable_life);
}


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

PHP_METHOD(KADM5Principal, getLastModifier) 
{
	char *princname;
	krb5_kadm5_principal_object *obj = (krb5_kadm5_principal_object*)zend_object_store_get_object(getThis() TSRMLS_CC);
	krb5_kadm5_object *kadm5;
	zval *connobj = NULL;
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

PHP_METHOD(KADM5Principal, getLastModificationDate) 
{
	krb5_kadm5_principal_object *obj = (krb5_kadm5_principal_object*)zend_object_store_get_object(getThis() TSRMLS_CC);
	RETURN_LONG(obj->data.mod_date);
}

PHP_METHOD(KADM5Principal, getKeyVNO) 
{
	krb5_kadm5_principal_object *obj = (krb5_kadm5_principal_object*)zend_object_store_get_object(getThis() TSRMLS_CC);
	RETURN_LONG(obj->data.kvno);
}

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

PHP_METHOD(KADM5Principal, getMasterKeyVNO) 
{
	krb5_kadm5_principal_object *obj = (krb5_kadm5_principal_object*)zend_object_store_get_object(getThis() TSRMLS_CC);
	RETURN_LONG(obj->data.mkvno);
}

PHP_METHOD(KADM5Principal, getAttributes) 
{
	krb5_kadm5_principal_object *obj = (krb5_kadm5_principal_object*)zend_object_store_get_object(getThis() TSRMLS_CC);
	RETURN_LONG(obj->data.attributes);
}

PHP_METHOD(KADM5Principal, getAuxAttributes) 
{
	krb5_kadm5_principal_object *obj = (krb5_kadm5_principal_object*)zend_object_store_get_object(getThis() TSRMLS_CC);
	RETURN_LONG(obj->data.aux_attributes);
}

PHP_METHOD(KADM5Principal, getPolicy)
{
	krb5_kadm5_principal_object *obj = (krb5_kadm5_principal_object*)zend_object_store_get_object(getThis() TSRMLS_CC);
	zval *connobj = NULL;
	zval *func;
	zval *args[1];

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

PHP_METHOD(KADM5Principal, clearPolicy)
{	
	krb5_kadm5_principal_object *obj = (krb5_kadm5_principal_object*)zend_object_store_get_object(getThis() TSRMLS_CC);

	obj->data.policy = NULL;
	obj->update_mask |= KADM5_POLICY_CLR;

	RETURN_TRUE;
}

PHP_METHOD(KADM5Principal, getLastSuccess)
{
	krb5_kadm5_principal_object *obj = (krb5_kadm5_principal_object*)zend_object_store_get_object(getThis() TSRMLS_CC);
	RETURN_LONG(obj->data.last_success);
}

PHP_METHOD(KADM5Principal, getLastFailed)
{
	krb5_kadm5_principal_object *obj = (krb5_kadm5_principal_object*)zend_object_store_get_object(getThis() TSRMLS_CC);
	RETURN_LONG(obj->data.last_failed);
}

PHP_METHOD(KADM5Principal, getFailedAuthCount)
{
	krb5_kadm5_principal_object *obj = (krb5_kadm5_principal_object*)zend_object_store_get_object(getThis() TSRMLS_CC);
	RETURN_LONG(obj->data.fail_auth_count);
}

PHP_METHOD(KADM5Principal, resetFailedAuthCount)
{
	krb5_kadm5_principal_object *obj = (krb5_kadm5_principal_object*)zend_object_store_get_object(getThis() TSRMLS_CC);
	
	obj->data.fail_auth_count = 0;
	obj->update_mask |= KADM5_FAIL_AUTH_COUNT;
}
