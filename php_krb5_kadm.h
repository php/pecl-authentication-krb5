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

#ifndef PHP_KRB5_KADM_H
#define PHP_KRB5_KADM_H

#include "config.h"

/* will be used in gssrpc/rpc_msg.h enum accept_stat */
#undef  SUCCESS
#define SUCCESS KRB5_SUCCESS
#include <kadm5/admin.h>
#undef  SUCCESS
/* default value in PHP and Kerberos */
#define SUCCESS 0

/* KADM5 Object */
	zend_class_entry *krb5_ce_kadm5;

	typedef struct _krb5_kadm5_object {
		zend_object std;
		void *handle;
		krb5_context ctx;
		kadm5_config_params config;
		int refcount;
	} krb5_kadm5_object;

	void php_krb5_free_kadm5_object(krb5_kadm5_object *obj);

	/* Kerberos Admin functions */
	PHP_METHOD(KADM5, __construct);
	PHP_METHOD(KADM5, getPrincipal);
	PHP_METHOD(KADM5, getPrincipals);
	PHP_METHOD(KADM5, createPrincipal);
	PHP_METHOD(KADM5, getPolicy);
	PHP_METHOD(KADM5, createPolicy);
	PHP_METHOD(KADM5, getPolicies);



/* KADM5Principal Object */
	zend_class_entry *krb5_ce_kadm5_principal;

	typedef struct _krb5_kadm5_principal_object {
		zend_object std;
		int loaded;
		long int update_mask;
		kadm5_principal_ent_rec data;
		krb5_kadm5_object *conn;
	} krb5_kadm5_principal_object;

	int php_krb5_register_kadm5_principal(TSRMLS_D);

	zend_object_value php_krb5_kadm5_principal_object_new(zend_class_entry *ce TSRMLS_DC);

	PHP_METHOD(KADM5Principal, __construct);
	PHP_METHOD(KADM5Principal, load);
	PHP_METHOD(KADM5Principal, save);
	PHP_METHOD(KADM5Principal, delete);
	PHP_METHOD(KADM5Principal, rename);

	PHP_METHOD(KADM5Principal, changePassword);

	PHP_METHOD(KADM5Principal, getPropertyArray);

	PHP_METHOD(KADM5Principal, getName);
	PHP_METHOD(KADM5Principal, getExpiryTime);
	PHP_METHOD(KADM5Principal, setExpiryTime);
	PHP_METHOD(KADM5Principal, getLastPasswordChange);
	PHP_METHOD(KADM5Principal, getPasswordExpiryTime);
	PHP_METHOD(KADM5Principal, setPasswordExpiryTime);
	PHP_METHOD(KADM5Principal, getMaxTicketLifetime);
	PHP_METHOD(KADM5Principal, setMaxTicketLifetime);
	PHP_METHOD(KADM5Principal, getLastModifier);
	PHP_METHOD(KADM5Principal, getLastModificationDate);
	PHP_METHOD(KADM5Principal, getKeyVNO);
	PHP_METHOD(KADM5Principal, setKeyVNO);
	PHP_METHOD(KADM5Principal, getMasterKeyVNO);
	PHP_METHOD(KADM5Principal, getAttributes);
	PHP_METHOD(KADM5Principal, getAuxAttributes);
	PHP_METHOD(KADM5Principal, getPolicy);
	PHP_METHOD(KADM5Principal, setPolicy);
	PHP_METHOD(KADM5Principal, clearPolicy);
	PHP_METHOD(KADM5Principal, getLastSuccess);
	PHP_METHOD(KADM5Principal, getLastFailed);
	PHP_METHOD(KADM5Principal, getFailedAuthCount);
	PHP_METHOD(KADM5Principal, resetFailedAuthCount);
	PHP_METHOD(KADM5Principal, getMaxRenewableLifetime);
	PHP_METHOD(KADM5Principal, setMaxRenewableLifetime);



/* KADM5Policy Object */
	zend_class_entry *krb5_ce_kadm5_policy;

	typedef struct _krb5_kadm5_policy_object {
		zend_object std;
		char *policy;
		long int update_mask;
		kadm5_policy_ent_rec data;
		krb5_kadm5_object *conn;
	} krb5_kadm5_policy_object;


	int php_krb5_register_kadm5_policy(TSRMLS_D);

	zend_object_value php_krb5_kadm5_policy_object_new(zend_class_entry *ce TSRMLS_DC);

	PHP_METHOD(KADM5Policy, __construct);
	PHP_METHOD(KADM5Policy, __destruct);
	PHP_METHOD(KADM5Policy, load);
	PHP_METHOD(KADM5Policy, save);
	PHP_METHOD(KADM5Policy, delete);

	PHP_METHOD(KADM5Policy, getPropertyArray);

	PHP_METHOD(KADM5Policy, getName);
	PHP_METHOD(KADM5Policy, getMinPasswordLife);
	PHP_METHOD(KADM5Policy, setMinPasswordLife);
	PHP_METHOD(KADM5Policy, getMaxPasswordLife);
	PHP_METHOD(KADM5Policy, setMaxPasswordLife);
	PHP_METHOD(KADM5Policy, getMinPasswordLength);
	PHP_METHOD(KADM5Policy, setMinPasswordLength);
	PHP_METHOD(KADM5Policy, getMinPasswordClasses);
	PHP_METHOD(KADM5Policy, setMinPasswordClasses);
	PHP_METHOD(KADM5Policy, getHistoryNum);
	PHP_METHOD(KADM5Policy, setHistoryNum);
	PHP_METHOD(KADM5Policy, getReferenceCount);




#endif
