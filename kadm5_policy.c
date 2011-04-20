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

static function_entry krb5_kadm5_policy_functions[] = {
	PHP_ME(KADM5Policy, __construct, NULL, ZEND_ACC_PUBLIC | ZEND_ACC_CTOR)
	PHP_ME(KADM5Policy, load, NULL, ZEND_ACC_PUBLIC)
	PHP_ME(KADM5Policy, save, NULL, ZEND_ACC_PUBLIC)
	PHP_ME(KADM5Policy, delete, NULL, ZEND_ACC_PUBLIC)
	PHP_ME(KADM5Policy, getPropertyArray, NULL, ZEND_ACC_PUBLIC)

	PHP_ME(KADM5Policy, getName, NULL, ZEND_ACC_PUBLIC)
	PHP_ME(KADM5Policy, getMinPasswordLife, NULL, ZEND_ACC_PUBLIC)
	PHP_ME(KADM5Policy, setMinPasswordLife, NULL, ZEND_ACC_PUBLIC)
	PHP_ME(KADM5Policy, getMaxPasswordLife, NULL, ZEND_ACC_PUBLIC)
	PHP_ME(KADM5Policy, setMaxPasswordLife, NULL, ZEND_ACC_PUBLIC)
	PHP_ME(KADM5Policy, getMinPasswordLength, NULL, ZEND_ACC_PUBLIC)
	PHP_ME(KADM5Policy, setMinPasswordLength, NULL, ZEND_ACC_PUBLIC)
	PHP_ME(KADM5Policy, getMinPasswordClasses, NULL, ZEND_ACC_PUBLIC)
	PHP_ME(KADM5Policy, setMinPasswordClasses, NULL, ZEND_ACC_PUBLIC)
	PHP_ME(KADM5Policy, getHistoryNum, NULL, ZEND_ACC_PUBLIC)
	PHP_ME(KADM5Policy, setHistoryNum, NULL, ZEND_ACC_PUBLIC)
	PHP_ME(KADM5Policy, getReferenceCount, NULL, ZEND_ACC_PUBLIC)
	{ NULL, NULL, NULL }
};

zend_object_handlers krb5_kadm5_policy_handlers;

static void php_krb5_kadm5_policy_object_dtor(void *obj, zend_object_handle handle TSRMLS_DC)
{
	krb5_kadm5_policy_object *object = (krb5_kadm5_policy_object*)obj;
	zend_object_std_dtor(&(object->std) TSRMLS_CC);

	if(object) {
		if(object->policy) {
			efree(object->policy);
		}

		if(object->conn) {
			kadm5_free_policy_ent(object->conn->handle, &object->data);
			php_krb5_free_kadm5_object(object->conn);
		}
		efree(object);
	}
}

int php_krb5_register_kadm5_policy(TSRMLS_D) {
	zend_class_entry kadm5_policy;
	INIT_CLASS_ENTRY(kadm5_policy, "KADM5Policy", krb5_kadm5_policy_functions);
	krb5_ce_kadm5_policy = zend_register_internal_class(&kadm5_policy TSRMLS_CC);
	krb5_ce_kadm5_policy->create_object = php_krb5_kadm5_policy_object_new;
	memcpy(&krb5_kadm5_policy_handlers, zend_get_std_object_handlers(), sizeof(zend_object_handlers));
	return SUCCESS;
}

zend_object_value php_krb5_kadm5_policy_object_new(zend_class_entry *ce TSRMLS_DC) 
{
	zend_object_value retval;
	krb5_kadm5_policy_object *object;
	extern zend_object_handlers krb5_kadm5_policy_handlers;

	object = emalloc(sizeof(krb5_kadm5_policy_object));

	memset(&object->data, 0, sizeof(kadm5_policy_ent_rec));
	object->conn = NULL;
	object->update_mask = 0;
	
	zend_object_std_init(&(object->std), ce TSRMLS_CC);

	zend_hash_copy(object->std.properties, &ce->default_properties,
					(copy_ctor_func_t) zval_add_ref, NULL, 
					sizeof(zval*));

	retval.handle = zend_objects_store_put(object, php_krb5_kadm5_policy_object_dtor, NULL, NULL TSRMLS_CC);

	retval.handlers = &krb5_kadm5_policy_handlers;
	return retval;
}

PHP_METHOD(KADM5Policy, __construct)
{
	char *spolicy = NULL;
	int spolicy_len;

	krb5_kadm5_policy_object *obj;

	zval *connobj = NULL;
	zval *dummy_retval, *func;

	if(zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s|O", &spolicy, &spolicy_len, &connobj, krb5_ce_kadm5) == FAILURE) {
		RETURN_NULL();
	}

	obj = (krb5_kadm5_policy_object*)zend_object_store_get_object(getThis() TSRMLS_CC);
	obj->policy = estrndup(spolicy, spolicy_len);

	if(connobj && Z_TYPE_P(connobj) == IS_OBJECT) {
		zend_update_property(krb5_ce_kadm5_principal, getThis(), "connection", sizeof("connection"), connobj TSRMLS_CC);

		MAKE_STD_ZVAL(func);
		ZVAL_STRING(func, "load", 1);
		MAKE_STD_ZVAL(dummy_retval);
		if(call_user_function(&krb5_ce_kadm5_policy->function_table, 
								&getThis(), func, dummy_retval, 0, 
								NULL TSRMLS_CC) == FAILURE) {
			zval_ptr_dtor(&func);
			zval_ptr_dtor(&dummy_retval);
			zend_throw_exception(NULL, "Failed to update KADM5Policy object", 0 TSRMLS_CC);
			return;
		}

		zval_ptr_dtor(&func);
		zval_ptr_dtor(&dummy_retval);
	}
}

PHP_METHOD(KADM5Policy, load)
{
	kadm5_ret_t retval;
	krb5_kadm5_policy_object *obj = (krb5_kadm5_policy_object*)zend_object_store_get_object(getThis() TSRMLS_CC);
	krb5_kadm5_object *kadm5;
	zval *connobj = NULL;

	connobj = zend_read_property(krb5_ce_kadm5_principal, getThis(), "connection", 
									sizeof("connection"),1 TSRMLS_CC);

	kadm5 = (krb5_kadm5_object*)zend_object_store_get_object(connobj TSRMLS_CC);
	if(!kadm5) {
		zend_throw_exception(NULL, "No valid connection available", 0 TSRMLS_CC);
		return;
	}

	retval = kadm5_get_policy(kadm5->handle, obj->policy, &obj->data);
	if(retval != KADM5_OK || !obj->data.policy) {
		zend_throw_exception(NULL, krb5_get_error_message(kadm5->ctx, (int)retval), (int)retval TSRMLS_CC);
		return;
	}

	if(!obj->conn) {
		obj->conn = kadm5;
		kadm5->refcount++;
	}
}

PHP_METHOD(KADM5Policy, save)
{
	kadm5_ret_t retval;
	krb5_kadm5_policy_object *obj = (krb5_kadm5_policy_object*)zend_object_store_get_object(getThis() TSRMLS_CC);
	krb5_kadm5_object *kadm5;
	zval *connobj = NULL;

	connobj = zend_read_property(krb5_ce_kadm5_principal, getThis(), "connection", 
									sizeof("connection"),1 TSRMLS_CC);

	kadm5 = (krb5_kadm5_object*)zend_object_store_get_object(connobj TSRMLS_CC);
	if(!kadm5) {
		zend_throw_exception(NULL, "No valid connection available", 0 TSRMLS_CC);
		return;
	}

	retval = kadm5_modify_policy(kadm5->handle, &obj->data, obj->update_mask);
	if(retval != KADM5_OK) {
		zend_throw_exception(NULL, krb5_get_error_message(kadm5->ctx, (int)retval), (int)retval TSRMLS_CC);
		return;
	}
}

PHP_METHOD(KADM5Policy, delete)
{
	kadm5_ret_t retval;
	krb5_kadm5_policy_object *obj = (krb5_kadm5_policy_object*)zend_object_store_get_object(getThis() TSRMLS_CC);
	krb5_kadm5_object *kadm5;
	zval *connobj = NULL;

	connobj = zend_read_property(krb5_ce_kadm5_principal, getThis(), "connection", 
									sizeof("connection"),1 TSRMLS_CC);

	kadm5 = (krb5_kadm5_object*)zend_object_store_get_object(connobj TSRMLS_CC);
	if(!kadm5) {
		zend_throw_exception(NULL, "No valid connection available", 0 TSRMLS_CC);
		return;
	}

	retval = kadm5_delete_policy(kadm5->handle, obj->policy);
	if(retval != KADM5_OK) {
		zend_throw_exception(NULL, krb5_get_error_message(kadm5->ctx, (int)retval), (int)retval TSRMLS_CC);
		return;
	}
}


PHP_METHOD(KADM5Policy, getPropertyArray)
{
	krb5_kadm5_policy_object *obj = (krb5_kadm5_policy_object*)zend_object_store_get_object(getThis() TSRMLS_CC);

	array_init(return_value);
	add_assoc_string(return_value, "policy", obj->data.policy, 1);
	add_assoc_long(return_value, "pw_min_life", obj->data.pw_min_life);
	add_assoc_long(return_value, "pw_max_life", obj->data.pw_max_life);
	add_assoc_long(return_value, "pw_min_length", obj->data.pw_min_length);
	add_assoc_long(return_value, "pw_min_classes", obj->data.pw_min_classes);
	add_assoc_long(return_value, "pw_history_num", obj->data.pw_history_num);
	add_assoc_long(return_value, "policy_refcnt", obj->data.policy_refcnt);
}

PHP_METHOD(KADM5Policy, getName)
{
	krb5_kadm5_policy_object *obj = (krb5_kadm5_policy_object*)zend_object_store_get_object(getThis() TSRMLS_CC);
	RETURN_STRING(obj->policy, 1);
}

PHP_METHOD(KADM5Policy, getMinPasswordLife)
{
	krb5_kadm5_policy_object *obj = (krb5_kadm5_policy_object*)zend_object_store_get_object(getThis() TSRMLS_CC);
	RETURN_LONG(obj->data.pw_min_life);
}

PHP_METHOD(KADM5Policy, setMinPasswordLife)
{
	krb5_kadm5_policy_object *obj = (krb5_kadm5_policy_object*)zend_object_store_get_object(getThis() TSRMLS_CC);
	long int min_life;
	
	if(zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "l", &min_life) == FAILURE) {
		RETURN_FALSE;
	}

	obj->data.pw_min_life = min_life;
	obj->update_mask |= KADM5_PW_MIN_LIFE;
	RETURN_TRUE;
}

PHP_METHOD(KADM5Policy, getMaxPasswordLife)
{
	krb5_kadm5_policy_object *obj = (krb5_kadm5_policy_object*)zend_object_store_get_object(getThis() TSRMLS_CC);
	RETURN_LONG(obj->data.pw_max_life);
}

PHP_METHOD(KADM5Policy, setMaxPasswordLife)
{
	krb5_kadm5_policy_object *obj = (krb5_kadm5_policy_object*)zend_object_store_get_object(getThis() TSRMLS_CC);
	long int max_life;
	
	if(zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "l", &max_life) == FAILURE) {
		RETURN_FALSE;
	}

	obj->data.pw_max_life = max_life;
	obj->update_mask |= KADM5_PW_MAX_LIFE;
	RETURN_TRUE;
}


PHP_METHOD(KADM5Policy, getMinPasswordLength)
{
	krb5_kadm5_policy_object *obj = (krb5_kadm5_policy_object*)zend_object_store_get_object(getThis() TSRMLS_CC);
	RETURN_LONG(obj->data.pw_min_length);
}

PHP_METHOD(KADM5Policy, setMinPasswordLength)
{
	krb5_kadm5_policy_object *obj = (krb5_kadm5_policy_object*)zend_object_store_get_object(getThis() TSRMLS_CC);
	long int min_length;
	
	if(zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "l", &min_length) == FAILURE) {
		RETURN_FALSE;
	}

	obj->data.pw_min_length = min_length;
	obj->update_mask |= KADM5_PW_MIN_LENGTH;
	RETURN_TRUE;
}

PHP_METHOD(KADM5Policy, getMinPasswordClasses)
{
	krb5_kadm5_policy_object *obj = (krb5_kadm5_policy_object*)zend_object_store_get_object(getThis() TSRMLS_CC);
	RETURN_LONG(obj->data.pw_min_classes);
}

PHP_METHOD(KADM5Policy, setMinPasswordClasses)
{
	krb5_kadm5_policy_object *obj = (krb5_kadm5_policy_object*)zend_object_store_get_object(getThis() TSRMLS_CC);
	long int min_classes;
	
	if(zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "l", &min_classes) == FAILURE) {
		RETURN_FALSE;
	}

	obj->data.pw_min_classes = min_classes;
	obj->update_mask |= KADM5_PW_MIN_CLASSES;
	RETURN_TRUE;
}

PHP_METHOD(KADM5Policy, getHistoryNum)
{
	krb5_kadm5_policy_object *obj = (krb5_kadm5_policy_object*)zend_object_store_get_object(getThis() TSRMLS_CC);
	RETURN_LONG(obj->data.pw_history_num);
}

PHP_METHOD(KADM5Policy, setHistoryNum)
{
	krb5_kadm5_policy_object *obj = (krb5_kadm5_policy_object*)zend_object_store_get_object(getThis() TSRMLS_CC);
	long int history_num;
	
	if(zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "l", &history_num) == FAILURE) {
		RETURN_FALSE;
	}

	obj->data.pw_history_num = history_num;
	obj->update_mask |= KADM5_PW_HISTORY_NUM;
	RETURN_TRUE;
}

PHP_METHOD(KADM5Policy, getReferenceCount)
{
	krb5_kadm5_policy_object *obj = (krb5_kadm5_policy_object*)zend_object_store_get_object(getThis() TSRMLS_CC);
	RETURN_LONG(obj->data.policy_refcnt);
}
