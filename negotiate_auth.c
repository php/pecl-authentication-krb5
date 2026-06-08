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
#include "php_krb5_gssapi.h"
#include "config.h"
#include "SAPI.h"
#include "ext/standard/base64.h"
#include <math.h>
#include <netdb.h>
#include <sys/socket.h>

/* Class definition */
zend_object_handlers krb5_negotiate_auth_handlers;

zend_class_entry *krb5_ce_negotiate_auth;
typedef struct _krb5_negotiate_auth_object {
	gss_name_t servname;
	gss_name_t authed_user;
	gss_cred_id_t delegated;
	zend_bool channel_bound;
	zval chan_bindings;
#ifdef HAVE_GSS_ACQUIRE_CRED_FROM
	gss_key_value_set_desc cred_store;
#endif
	zend_object std;
} krb5_negotiate_auth_object;



static void php_krb5_negotiate_auth_object_free(zend_object *obj TSRMLS_DC);
zend_object *php_krb5_ticket_object_new(zend_class_entry *ce TSRMLS_DC);

ZEND_BEGIN_ARG_INFO_EX(arginfo_KRB5NegotiateAuth_none, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_KRB5NegotiateAuth__construct, 0, 0, 1)
	ZEND_ARG_INFO(0, keytab)
	ZEND_ARG_INFO(0, spn)
	ZEND_ARG_OBJ_INFO(0, channel, GSSAPIChannelBinding, 1)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_KRB5NegotiateAuth_getDelegatedCredentials, 0, 0, 1)
	ZEND_ARG_OBJ_INFO(0, ccache, KRB5CCache, 0)
ZEND_END_ARG_INFO()

PHP_METHOD(KRB5NegotiateAuth, __construct);
PHP_METHOD(KRB5NegotiateAuth, doAuthentication);
PHP_METHOD(KRB5NegotiateAuth, getDelegatedCredentials);
PHP_METHOD(KRB5NegotiateAuth, getAuthenticatedUser);
PHP_METHOD(KRB5NegotiateAuth, isChannelBound);

static zend_function_entry krb5_negotiate_auth_functions[] = {
	PHP_ME(KRB5NegotiateAuth, __construct,             arginfo_KRB5NegotiateAuth__construct,              ZEND_ACC_PUBLIC | ZEND_ACC_CTOR)
	PHP_ME(KRB5NegotiateAuth, doAuthentication,        arginfo_KRB5NegotiateAuth_none,                    ZEND_ACC_PUBLIC)
	PHP_ME(KRB5NegotiateAuth, getDelegatedCredentials, arginfo_KRB5NegotiateAuth_getDelegatedCredentials, ZEND_ACC_PUBLIC)
	PHP_ME(KRB5NegotiateAuth, getAuthenticatedUser,    arginfo_KRB5NegotiateAuth_none,                    ZEND_ACC_PUBLIC)
	PHP_ME(KRB5NegotiateAuth, isChannelBound,          arginfo_KRB5NegotiateAuth_none,                    ZEND_ACC_PUBLIC)
	PHP_FE_END
};


/** Registration **/

static void php_krb5_negotiate_auth_object_free_data(krb5_negotiate_auth_object* object) {
	OM_uint32 minor_status = 0;

	if ( object->servname ) {
		free(object->servname);
	}

	if ( Z_TYPE(object->chan_bindings) != IS_NULL ) {
		zval_ptr_dtor(&object->chan_bindings);
	}

	if ( object->delegated != GSS_C_NO_CREDENTIAL ) {
		gss_release_cred(&minor_status, &object->delegated);
	}

	if ( object->authed_user != GSS_C_NO_NAME ) {
		gss_release_name(&minor_status, &object->authed_user);
	}

#ifdef HAVE_GSS_ACQUIRE_CRED_FROM
	if ( object->cred_store.elements != NULL ) {
		efree((void*)object->cred_store.elements->value);
		efree(object->cred_store.elements);
	}
#endif
}
/* {{{ */
static void php_krb5_negotiate_auth_object_free(zend_object *obj TSRMLS_DC)
{
	krb5_negotiate_auth_object *object = (krb5_negotiate_auth_object*)((char *)obj - XtOffsetOf(krb5_negotiate_auth_object, std));
	php_krb5_negotiate_auth_object_free_data(object);
	zend_object_std_dtor(obj);
}
/* }}} */




static void setup_negotiate_auth(krb5_negotiate_auth_object *object TSRMLS_DC) {
	object->authed_user = GSS_C_NO_NAME;
	object->servname = GSS_C_NO_NAME;
	object->delegated = GSS_C_NO_CREDENTIAL;
}

/* {{{ */
zend_object *php_krb5_negotiate_auth_object_new(zend_class_entry *ce TSRMLS_DC)
{
	krb5_negotiate_auth_object *object;
	object = ecalloc(1, sizeof(krb5_negotiate_auth_object) + zend_object_properties_size(ce));

	setup_negotiate_auth(object TSRMLS_CC);

	zend_object_std_init(&object->std, ce TSRMLS_CC);
	object_properties_init(&object->std, ce);
	ZVAL_NULL(&object->chan_bindings);
	object->std.handlers = &krb5_negotiate_auth_handlers;
	return &object->std;
}
/* }}} */

/* {{{ */
int php_krb5_negotiate_auth_register_classes(TSRMLS_D) {
	zend_class_entry negotiate_auth;

	INIT_CLASS_ENTRY(negotiate_auth, "KRB5NegotiateAuth", krb5_negotiate_auth_functions);
	krb5_ce_negotiate_auth = zend_register_internal_class(&negotiate_auth TSRMLS_CC);
	krb5_ce_negotiate_auth->create_object = php_krb5_negotiate_auth_object_new;
	memcpy(&krb5_negotiate_auth_handlers, zend_get_std_object_handlers(), sizeof(zend_object_handlers));
	krb5_negotiate_auth_handlers.offset = XtOffsetOf(krb5_negotiate_auth_object, std);
	krb5_negotiate_auth_handlers.free_obj = php_krb5_negotiate_auth_object_free;

	return SUCCESS;
}
/* }}} */


/** KRB5NegotiateAuth Methods **/
/* {{{ proto bool KRB5NegotiateAuth::__construct( string $keytab [, string $spn [, GSSAPIChannelBinding binding]] )
   Initialize KRB5NegotitateAuth object with a keytab to use  */
PHP_METHOD(KRB5NegotiateAuth, __construct)
{

	OM_uint32 status, minor_status;
	krb5_negotiate_auth_object *object;
	char *keytab;
	zval *spn = NULL;
	gss_buffer_desc nametmp;
	strsize_t keytab_len = 0;
	zval *zchannel = NULL;

	KRB5_SET_ERROR_HANDLING(EH_THROW);
	if(zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, ARG_PATH "|z/O!", &keytab, &keytab_len, &spn, &zchannel, krb5_ce_gss_channel) == FAILURE) {
		RETURN_FALSE;
	}
	KRB5_SET_ERROR_HANDLING(EH_NORMAL);


	object = KRB5_THIS_NEGOTIATE_AUTH;

#ifdef HAVE_GSS_ACQUIRE_CRED_FROM
	char *kt_name = estrdup(keytab);
	gss_key_value_element_desc *keytab_element = emalloc(sizeof(gss_key_value_element_desc));
	keytab_element->key = "keytab";
	keytab_element->value = kt_name;
	object->cred_store.elements = keytab_element;
	object->cred_store.count = 1;
#endif

	if (zchannel != NULL) {
		ZVAL_OBJ_COPY(&object->chan_bindings, Z_OBJ_P(zchannel));
	}


	if ( spn != NULL && Z_TYPE_P((spn))==IS_LONG && zval_get_long(spn TSRMLS_CC) == 0) {
		object->servname = GSS_C_NO_NAME;
	}
	else if ( spn == NULL || Z_TYPE_P((spn))==IS_NULL ) {
		/** legacy behavior - try to find canonical server FQDN **/
		zval *server, *server_name;
		server = zend_compat_hash_find(&EG(symbol_table), "_SERVER", sizeof("_SERVER"));
		if ( server != NULL ) {
			server_name = zend_compat_hash_find(HASH_OF(server), "SERVER_NAME", sizeof("SERVER_NAME"));
			if ( server_name != NULL ) {
				char *hostname = Z_STRVAL_P(server_name);
				struct hostent* host = gethostbyname(hostname);

				if(!host) {
					zend_throw_exception(NULL, "Failed to get server FQDN - Lookup failure", 0 TSRMLS_CC);
					return;
				}



				nametmp.length = strlen(host->h_name) + 6;
				nametmp.value = emalloc(sizeof(char)*nametmp.length);
				snprintf(nametmp.value, nametmp.length, "HTTP@%s",host->h_name);

				status = gss_import_name(&minor_status, &nametmp,
								GSS_C_NT_HOSTBASED_SERVICE, &object->servname);

				if(GSS_ERROR(status)) {
					php_krb5_gssapi_handle_error(status, minor_status TSRMLS_CC);
					zend_throw_exception(NULL, "Could not parse server name", 0 TSRMLS_CC);
					return;
				}

				efree(nametmp.value);
			} else {
				zend_throw_exception(NULL, "Failed to get server FQDN", 0 TSRMLS_CC);
				return;
			}
		}
	} else {
		zend_string *spnstr = zval_get_string(spn TSRMLS_CC);
		nametmp.length = spnstr->len;
		nametmp.value = spnstr->val;

		status = gss_import_name(&minor_status, &nametmp,
						(gss_OID)GSS_KRB5_NT_PRINCIPAL_NAME, &object->servname);

		zend_string_release(spnstr);

		if(GSS_ERROR(status)) {
			php_krb5_gssapi_handle_error(status, minor_status TSRMLS_CC);
			zend_throw_exception(NULL, "Could not parse server name", 0 TSRMLS_CC);
			return;
		}
	}

#ifndef HAVE_GSS_ACQUIRE_CRED_FROM
	if(krb5_gss_register_acceptor_identity(keytab) != GSS_S_COMPLETE) {
		zend_throw_exception(NULL, "Failed to use credential cache", 0 TSRMLS_CC);
		return;
	}
#endif
} /* }}} */

/* {{{ proto bool KRB5NegotiateAuth::doAuthentication(  )
   Performs Negotiate/GSSAPI authentication  */
PHP_METHOD(KRB5NegotiateAuth, doAuthentication)
{
	zend_string *token = NULL;
	krb5_negotiate_auth_object *object;

	OM_uint32 status = 0;
	OM_uint32 minor_status = 0;
	OM_uint32 ign_minor_status = 0;
	OM_uint32 flags;
	gss_ctx_id_t gss_context = GSS_C_NO_CONTEXT;
	gss_buffer_desc input_token;
	gss_buffer_desc output_token;
	gss_cred_id_t server_creds = GSS_C_NO_CREDENTIAL;
	gss_channel_bindings_t chan_bindings = GSS_C_NO_CHANNEL_BINDINGS;

	if (zend_parse_parameters_none() == FAILURE) {
		RETURN_FALSE;
	}

	object = KRB5_THIS_NEGOTIATE_AUTH;

	if(!object) {
		RETURN_FALSE;
	}


	/* get authentication data */
	zval *auth_header = NULL;

	HashTable* server_vars = Z_ARRVAL(PG(http_globals)[TRACK_VARS_SERVER]);

	if(server_vars && (auth_header = zend_compat_hash_find(server_vars, "HTTP_AUTHORIZATION", sizeof("HTTP_AUTHORIZATION"))) != NULL) {

		if(!strncasecmp(Z_STRVAL_P(auth_header), "negotiate", 9) == 0) {
 			// user agent did not provide negotiate authentication data
 			RETURN_FALSE;
 		}

		if(Z_STRLEN_P(auth_header) < 11) {
 			// user agent gave negotiate header but no data
 			zend_throw_exception(NULL, "Invalid negotiate authentication data given", 0 TSRMLS_CC);
 			return;
 		}
		token = php_base64_decode_ex((unsigned char*) Z_STRVAL_P(auth_header)+10, Z_STRLEN_P(auth_header) - 10, 1);
	} else {
		// No authentication data given by the user agent
		sapi_header_line ctr = {0};

		ctr.line = "WWW-Authenticate: Negotiate";
		ctr.line_len = strlen("WWW-Authenticate: Negotiate");
		ctr.response_code = 401;
		sapi_header_op(SAPI_HEADER_ADD, &ctr TSRMLS_CC);
		RETURN_FALSE;
	}

	if(!token) {
        	zend_throw_exception(NULL, "Failed to decode token data", 0 TSRMLS_CC);
		return;
	}


#ifdef HAVE_GSS_ACQUIRE_CRED_FROM
	status = gss_acquire_cred_from(&minor_status,
					object->servname,
					0,
					GSS_C_NO_OID_SET,
					GSS_C_ACCEPT,
					&object->cred_store,
					&server_creds,
					NULL,
					NULL);

#else
	status = gss_acquire_cred(&minor_status,
			object->servname,
			0,
			GSS_C_NO_OID_SET,
			GSS_C_ACCEPT,
			&server_creds,
			NULL,
			NULL);
#endif

	if(GSS_ERROR(status)) {
		zend_string_release(token);
		php_krb5_gssapi_handle_error(status, minor_status TSRMLS_CC);
		zend_throw_exception(NULL, "Error while obtaining server credentials", status TSRMLS_CC);
		RETURN_FALSE;
	}
	minor_status = 0;

	input_token.length = token->len;
	input_token.value = token->val;

	if ( Z_TYPE(object->chan_bindings) != IS_NULL ) {
		krb5_gss_channel_object *zchannelobj = KRB5_GSS_CHANNEL(&object->chan_bindings);
                chan_bindings = &zchannelobj->data;
	}

	status = gss_accept_sec_context(   &minor_status,
                                       &gss_context,
                                       server_creds,
                                       &input_token,
                                       chan_bindings,
                                       &object->authed_user,
                                       NULL,
                                       &output_token,
                                       &flags,
                                       NULL,
                                       &object->delegated);


	if(!(flags & GSS_C_DELEG_FLAG)) {
		object->delegated = GSS_C_NO_CREDENTIAL;
	}

#ifdef GSS_C_CHANNEL_BOUND_FLAG
	if((flags & GSS_C_CHANNEL_BOUND_FLAG) == GSS_C_CHANNEL_BOUND_FLAG) {
		object->channel_bound = TRUE;
	}
#endif

	if ( server_creds != GSS_C_NO_CREDENTIAL ) {

		gss_release_cred(&ign_minor_status, &server_creds);
	}

	zend_string_release(token);

	if(GSS_ERROR(status)) {
		php_krb5_gssapi_handle_error(status, minor_status TSRMLS_CC);
		zend_throw_exception(NULL, "Error while accepting security context", status TSRMLS_CC);
		RETURN_FALSE;
	}

	if(gss_context != GSS_C_NO_CONTEXT) {
		gss_delete_sec_context(&minor_status, &gss_context, GSS_C_NO_BUFFER);
	}

	if(output_token.length > 0) {
		zend_string *encoded = php_base64_encode(output_token.value, output_token.length);
		sapi_header_line ctr = {0};

		const char *prompt = "WWW-Authenticate: ";
		size_t promptLen = strlen(prompt);
		char *buf;

		ctr.line = buf = emalloc(promptLen + encoded->len + 1);
		strncpy(buf, prompt, promptLen + 1);
		strncpy(buf + promptLen, encoded->val, encoded->len + 1);
		buf[promptLen+encoded->len] = 0;
		ctr.response_code = 200;
		sapi_header_op(SAPI_HEADER_ADD, &ctr TSRMLS_CC);
		zend_string_release(encoded);

		efree(buf);
		gss_release_buffer(&minor_status, &output_token);
	}
	RETURN_TRUE;
} /* }}} */

/* {{{ proto string KRB5NegotiateAuth::getAuthenticatedUser(  )
   Gets the principal name of the authenticated user  */
PHP_METHOD(KRB5NegotiateAuth, getAuthenticatedUser)
{
	OM_uint32 status, minor_status;
	krb5_negotiate_auth_object *object;

	if (zend_parse_parameters_none() == FAILURE) {
		RETURN_FALSE;
	}
	object = KRB5_THIS_NEGOTIATE_AUTH;

	if(!object || !object->authed_user || object->authed_user == GSS_C_NO_NAME) {
		RETURN_FALSE;
	}

	gss_buffer_desc username_tmp;
	status = gss_display_name(&minor_status, object->authed_user, &username_tmp, NULL);

	if(GSS_ERROR(status)) {
		php_krb5_gssapi_handle_error(status, minor_status TSRMLS_CC);
		RETURN_FALSE;
	}

	_ZVAL_STRINGL(return_value, username_tmp.value, username_tmp.length);
	gss_release_buffer(&minor_status, &username_tmp);
} /* }}} */

/* {{{ proto bool KRB5NegotiateAuth::isChannelBound(  )
   Check whether channel binding was successful  */
PHP_METHOD(KRB5NegotiateAuth, isChannelBound)
{
	krb5_negotiate_auth_object *object;
	if (zend_parse_parameters_none() == FAILURE) {
		RETURN_FALSE;
	}
	object = KRB5_THIS_NEGOTIATE_AUTH;

	if(!object || !object->channel_bound) {
		RETURN_FALSE;
	}

	RETURN_TRUE;
} /* }}} */

/* {{{ proto void KRB5NegotiateAuth::getDelegatedCredentials( KRB5CCache $ccache )
   Fills a credential cache with the delegated credentials  */
PHP_METHOD(KRB5NegotiateAuth, getDelegatedCredentials)
{
	OM_uint32 status, minor_status;
	krb5_negotiate_auth_object *object;
	zval *zticket;
	krb5_ccache_object *ticket;
	krb5_error_code retval = 0;
	krb5_principal princ;

	object = KRB5_THIS_NEGOTIATE_AUTH;

	if(object->delegated == GSS_C_NO_CREDENTIAL) {
		zend_throw_exception(NULL, "No delegated credentials available", 0 TSRMLS_CC);
		return;
	}

	if(zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "O", &zticket, krb5_ce_ccache) == FAILURE) {
		return;
	}

	ticket = KRB5_CCACHE(zticket);
	if(!ticket) {
		zend_throw_exception(NULL, "Invalid KRB5CCache object given", 0 TSRMLS_CC);
		return;
	}


	/* use principal name for ccache initialization */
	gss_buffer_desc nametmp;
	status = gss_display_name(&minor_status, object->authed_user, &nametmp, NULL);
	if(GSS_ERROR(status)) {
		php_krb5_gssapi_handle_error(status, minor_status TSRMLS_CC);
		return;
	}

	if((retval = krb5_parse_name(ticket->ctx, nametmp.value, &princ))) {
		php_krb5_display_error(ticket->ctx, retval,  "Failed to parse principal name (%s)" TSRMLS_CC);
		return;
	}

	if((retval = krb5_cc_initialize(ticket->ctx, ticket->cc, princ))) {
		krb5_free_principal(ticket->ctx,princ);
		php_krb5_display_error(ticket->ctx, retval,  "Failed to initialize credential cache (%s)" TSRMLS_CC);
		return;
	}

	/* copy credentials to ccache */
	status = gss_krb5_copy_ccache(&minor_status, object->delegated, ticket->cc);

	if(GSS_ERROR(status)) {
		php_krb5_gssapi_handle_error(status, minor_status TSRMLS_CC);
		zend_throw_exception(NULL, "Failure while imporing delegated ticket", 0 TSRMLS_CC);
		return;
	}

} /* }}} */

