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

#ifndef PHP_KRB5_GSSAPI_H
#define PHP_KRB5_GSSAPI_H

#include <gssapi/gssapi.h>


extern zend_class_entry *krb5_ce_gss_channel;

PHP_METHOD(GSSAPIChannelBinding, __construct);
PHP_METHOD(GSSAPIChannelBinding, getInitiatorAddress);
PHP_METHOD(GSSAPIChannelBinding, getInitiatorAddressType);
PHP_METHOD(GSSAPIChannelBinding, setInitiatorAddress);
PHP_METHOD(GSSAPIChannelBinding, getAcceptorAddress);
PHP_METHOD(GSSAPIChannelBinding, getAcceptorAddressType);
PHP_METHOD(GSSAPIChannelBinding, setAcceptorAddress);
PHP_METHOD(GSSAPIChannelBinding, getApplicationData);
PHP_METHOD(GSSAPIChannelBinding, setApplicationData);


typedef struct _krb5_gss_channel_object {
	struct gss_channel_bindings_struct data;
        zend_object std;
} krb5_gss_channel_object;

int php_krb5_register_gss_channel();
zend_object* php_krb5_gss_channel_object_new(zend_class_entry *ce);
void php_krb5_gss_channel_object_free(zend_object *obj);


void php_krb5_gssapi_handle_error(OM_uint32 major, OM_uint32 minor TSRMLS_DC);
int php_krb5_gssapi_register_classes(TSRMLS_D);
int php_krb5_gssapi_shutdown(TSRMLS_D);


extern void php_krb5_gssapi_context_object_free(zend_object *obj TSRMLS_DC);
zend_object *php_krb5_gssapi_context_object_new(zend_class_entry *ce TSRMLS_DC);


#endif /* PHP_KRB5_GSSAPI_H */

