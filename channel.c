/**
* Copyright (c) 2023 Moritz Bechler
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

#include "config.h"
#include "php_krb5.h"
#include "php_krb5_gssapi.h"

ZEND_BEGIN_ARG_INFO_EX(arginfo_GSSAPIChannelBinding_none, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_GSSAPIChannelBinding_typed, 0, 0, 0)
	ZEND_ARG_INFO(0, type)
	ZEND_ARG_INFO(0, data)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_GSSAPIChannelBinding_untyped, 0, 0, 0)
	ZEND_ARG_INFO(0, data)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_GSSAPIChannelBinding__construct, 0, 0, 0)
ZEND_END_ARG_INFO()

static zend_function_entry gss_channel_functions[] = {
	PHP_ME(GSSAPIChannelBinding, __construct, arginfo_GSSAPIChannelBinding__construct, ZEND_ACC_PUBLIC | ZEND_ACC_CTOR)
	PHP_ME(GSSAPIChannelBinding, getInitiatorAddress, arginfo_GSSAPIChannelBinding_none, ZEND_ACC_PUBLIC)
	PHP_ME(GSSAPIChannelBinding, getInitiatorAddressType, arginfo_GSSAPIChannelBinding_none, ZEND_ACC_PUBLIC)
	PHP_ME(GSSAPIChannelBinding, setInitiatorAddress, arginfo_GSSAPIChannelBinding_typed, ZEND_ACC_PUBLIC)
	PHP_ME(GSSAPIChannelBinding, getAcceptorAddress, arginfo_GSSAPIChannelBinding_none, ZEND_ACC_PUBLIC)
	PHP_ME(GSSAPIChannelBinding, getAcceptorAddressType, arginfo_GSSAPIChannelBinding_none, ZEND_ACC_PUBLIC)	
	PHP_ME(GSSAPIChannelBinding, setAcceptorAddress, arginfo_GSSAPIChannelBinding_typed, ZEND_ACC_PUBLIC)
	PHP_ME(GSSAPIChannelBinding, getApplicationData, arginfo_GSSAPIChannelBinding_none, ZEND_ACC_PUBLIC)
	PHP_ME(GSSAPIChannelBinding, setApplicationData, arginfo_GSSAPIChannelBinding_untyped, ZEND_ACC_PUBLIC)
	PHP_FE_END
};

zend_object_handlers gss_channel_handlers;
zend_class_entry *krb5_ce_gss_channel;

void php_krb5_gss_channel_object_free(zend_object *obj)
{
	krb5_gss_channel_object *object = (krb5_gss_channel_object*)((char *)obj - XtOffsetOf(krb5_gss_channel_object, std));
	if ( object->data.initiator_address.value ) {
		efree(object->data.initiator_address.value);
	}
	if ( object->data.acceptor_address.value ) {
		efree(object->data.acceptor_address.value);
	}
	if ( object->data.application_data.value ) {
		efree(object->data.application_data.value);
	}
}


int php_krb5_register_gss_channel() {


	zend_class_entry gss_channel;
	INIT_CLASS_ENTRY(gss_channel, "GSSAPIChannelBinding", gss_channel_functions);
	krb5_ce_gss_channel = zend_register_internal_class(&gss_channel);
	krb5_ce_gss_channel->create_object = php_krb5_gss_channel_object_new;
	memcpy(&gss_channel_handlers, zend_get_std_object_handlers(), sizeof(zend_object_handlers));
	gss_channel_handlers.offset = XtOffsetOf(krb5_gss_channel_object, std);
	gss_channel_handlers.free_obj = php_krb5_gss_channel_object_free;
	return SUCCESS;
}


zend_object* php_krb5_gss_channel_object_new(zend_class_entry *ce)
{
	krb5_gss_channel_object *object = ecalloc(1, sizeof(krb5_gss_channel_object) + zend_object_properties_size(ce));
	zend_object_std_init(&object->std, ce);
	object_properties_init(&object->std, ce);
	object->std.handlers = &gss_channel_handlers;
	memset(	&object->data, 0, sizeof(struct gss_channel_bindings_struct));
	return &object->std;
}




/* {{{ proto GSSAPIChannelBinding GSSAPIChannelBinding::__construct()
 */
PHP_METHOD(GSSAPIChannelBinding, __construct)
{
	KRB5_SET_ERROR_HANDLING(EH_THROW);
	if(zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "") == FAILURE) {
		RETURN_NULL();
	}
	KRB5_SET_ERROR_HANDLING(EH_NORMAL);
}
/* }}} */



/* {{{ proto string|null GSSAPIChannelBinding::getInitiatorAddress()
 */
PHP_METHOD(GSSAPIChannelBinding, getInitiatorAddress)
{
	KRB5_SET_ERROR_HANDLING(EH_THROW);
	if(zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "") == FAILURE) {
		RETURN_NULL();
	}
	KRB5_SET_ERROR_HANDLING(EH_NORMAL);
	krb5_gss_channel_object *object = KRB5_THIS_GSS_CHANNEL;	
	if ( object->data.initiator_address.value ) {
		_RETVAL_STRINGL((char*)object->data.initiator_address.value, object->data.initiator_address.length);
	} else {
		RETURN_NULL();
	}
}
/* }}} */

/* {{{ proto int GSSAPIChannelBinding::getInitiatorAddressType()
 */
PHP_METHOD(GSSAPIChannelBinding, getInitiatorAddressType)
{
	KRB5_SET_ERROR_HANDLING(EH_THROW);
	if(zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "") == FAILURE) {
		RETURN_NULL();
	}
	KRB5_SET_ERROR_HANDLING(EH_NORMAL);
	krb5_gss_channel_object *object = KRB5_THIS_GSS_CHANNEL;
	
	RETURN_LONG(object->data.initiator_addrtype);
}
/* }}} */

/* {{{ proto string|null GSSAPIChannelBinding::getAcceptorAddress()
 */
PHP_METHOD(GSSAPIChannelBinding, getAcceptorAddress)
{
	KRB5_SET_ERROR_HANDLING(EH_THROW);
	if(zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "") == FAILURE) {
		RETURN_NULL();
	}
	KRB5_SET_ERROR_HANDLING(EH_NORMAL);
	krb5_gss_channel_object *object = KRB5_THIS_GSS_CHANNEL;
	if ( object->data.acceptor_address.value ) {
		_RETVAL_STRINGL((char*)object->data.acceptor_address.value, object->data.acceptor_address.length);
	} else {
		RETURN_NULL();
	}
}
/* }}} */

/* {{{ proto int GSSAPIChannelBinding::getAcceptorAddressType()
 */
PHP_METHOD(GSSAPIChannelBinding, getAcceptorAddressType)
{
	KRB5_SET_ERROR_HANDLING(EH_THROW);
	if(zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "") == FAILURE) {
		RETURN_NULL();
	}
	KRB5_SET_ERROR_HANDLING(EH_NORMAL);
	krb5_gss_channel_object *object = KRB5_THIS_GSS_CHANNEL;
	
	RETURN_LONG(object->data.acceptor_addrtype);
}
/* }}} */

/* {{{ proto string|null GSSAPIChannelBinding::getApplicationData()
 */
PHP_METHOD(GSSAPIChannelBinding, getApplicationData)
{
	KRB5_SET_ERROR_HANDLING(EH_THROW);
	if(zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "") == FAILURE) {
		RETURN_NULL();
	}
	KRB5_SET_ERROR_HANDLING(EH_NORMAL);
	krb5_gss_channel_object *object = KRB5_THIS_GSS_CHANNEL;

	if ( object->data.application_data.value ) {
		_RETVAL_STRINGL((char*)object->data.application_data.value, object->data.application_data.length);
	} else {
		RETURN_NULL();
	}	
}
/* }}} */


/* {{{ proto void GSSAPIChannelBinding::setApplicationData(string data)
 */
PHP_METHOD(GSSAPIChannelBinding, setApplicationData)
{
	zval *zdata = NULL;
	KRB5_SET_ERROR_HANDLING(EH_THROW);
	if(zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "z/", &zdata) == FAILURE) {
		RETURN_NULL();
	}
	KRB5_SET_ERROR_HANDLING(EH_NORMAL);
	krb5_gss_channel_object *object = KRB5_THIS_GSS_CHANNEL;
	if ( !zdata ) { 
		object->data.application_data.length = 0;
		if ( object->data.application_data.value ) {
			efree(object->data.application_data.value);
			object->data.application_data.value = NULL;
		}
	} else {
		zend_string *data = zval_get_string(zdata);
		object->data.application_data.length = data->len;
		object->data.application_data.value = emalloc(data->len);
		memcpy(object->data.application_data.value, data->val, data->len);
	}
}
/* }}} */


/* {{{ proto void GSSAPIChannelBinding::setInitiatorAddress(long type, string data)
 */
PHP_METHOD(GSSAPIChannelBinding, setInitiatorAddress)
{
	zval *zdata = NULL;
	zend_long type = 0;
	KRB5_SET_ERROR_HANDLING(EH_THROW);
	if(zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "lz/", &type, &zdata) == FAILURE) {
		RETURN_NULL();
	}
	KRB5_SET_ERROR_HANDLING(EH_NORMAL);
	krb5_gss_channel_object *object = KRB5_THIS_GSS_CHANNEL;

	object->data.initiator_addrtype = type;
	if ( !zdata ) { 
		object->data.initiator_address.length = 0;
		if ( object->data.initiator_address.value ) {
			efree(object->data.initiator_address.value);
			object->data.initiator_address.value = NULL;
		}
	} else {
		zend_string *data = zval_get_string(zdata);
		object->data.initiator_address.length = data->len;
		object->data.initiator_address.value = emalloc(data->len);
		memcpy(object->data.initiator_address.value, data->val, data->len);
	}
}
/* }}} */


/* {{{ proto void GSSAPIChannelBinding::setAcceptorAddress(long type, string data)
 */
PHP_METHOD(GSSAPIChannelBinding, setAcceptorAddress)
{
	zval *zdata = NULL;
	zend_long type = 0;
	KRB5_SET_ERROR_HANDLING(EH_THROW);
	if(zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "lz/", &type, &zdata) == FAILURE) {
		RETURN_NULL();
	}
	KRB5_SET_ERROR_HANDLING(EH_NORMAL);
	krb5_gss_channel_object *object = KRB5_THIS_GSS_CHANNEL;
	
	object->data.acceptor_addrtype = type;
	if ( !zdata ) { 
		object->data.acceptor_address.length = 0;
		if ( object->data.acceptor_address.value ) {
			efree(object->data.acceptor_address.value);
			object->data.acceptor_address.value = NULL;
		}
	} else {
		zend_string *data = zval_get_string(zdata);
		object->data.acceptor_address.length = data->len;
		object->data.acceptor_address.value = emalloc(data->len);
		memcpy(object->data.acceptor_address.value, data->val, data->len);
	}
}
/* }}} */


