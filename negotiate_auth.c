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
#include "SAPI.h"
#include "ext/standard/base64.h"
#include <math.h>
#include <netdb.h>
#include <sys/socket.h>

/* Class definition */
zend_object_handlers krb5_negotiate_auth_handlers;

zend_class_entry *krb5_ce_negotiate_auth;
typedef struct _krb5_negotiate_auth_object {
	zend_object std;
	gss_name_t servname;
	gss_name_t authed_user;
	gss_cred_id_t delegated;
} krb5_negotiate_auth_object;

static void php_krb5_negotiate_auth_object_dtor(void *obj, zend_object_handle handle TSRMLS_DC);
zend_object_value php_krb5_negotiate_auth_object_new(zend_class_entry *ce TSRMLS_DC);

ZEND_BEGIN_ARG_INFO_EX(arginfo_KRB5NegotiateAuth_none, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_KRB5NegotiateAuth__construct, 0, 0, 1)
	ZEND_ARG_INFO(0, keytab)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_KRB5NegotiateAuth_getDelegatedCredentials, 0, 0, 1)
	ZEND_ARG_OBJ_INFO(0, ccache, KRB5CCache, 0)
ZEND_END_ARG_INFO()

PHP_METHOD(KRB5NegotiateAuth, __construct);
PHP_METHOD(KRB5NegotiateAuth, doAuthentication);
PHP_METHOD(KRB5NegotiateAuth, getDelegatedCredentials);
PHP_METHOD(KRB5NegotiateAuth, getAuthenticatedUser);

static zend_function_entry krb5_negotiate_auth_functions[] = {
	PHP_ME(KRB5NegotiateAuth, __construct,             arginfo_KRB5NegotiateAuth__construct,              ZEND_ACC_PUBLIC | ZEND_ACC_CTOR)
	PHP_ME(KRB5NegotiateAuth, doAuthentication,        arginfo_KRB5NegotiateAuth_none,                    ZEND_ACC_PUBLIC)
	PHP_ME(KRB5NegotiateAuth, getDelegatedCredentials, arginfo_KRB5NegotiateAuth_getDelegatedCredentials, ZEND_ACC_PUBLIC)
	PHP_ME(KRB5NegotiateAuth, getAuthenticatedUser,    arginfo_KRB5NegotiateAuth_none,                    ZEND_ACC_PUBLIC)
	PHP_FE_END
};


/** Registration **/
/* {{{ */
static void php_krb5_negotiate_auth_object_dtor(void *obj, zend_object_handle handle TSRMLS_DC)
{
	krb5_negotiate_auth_object *object = (krb5_negotiate_auth_object*)obj;
	OBJECT_STD_DTOR(object->std);

	efree(object);
} /* }}} */

/* {{{ */
zend_object_value php_krb5_negotiate_auth_object_new(zend_class_entry *ce TSRMLS_DC)
{
	zend_object_value retval;
	krb5_negotiate_auth_object *object;
	OM_uint32 status, minor_status;

	object = emalloc(sizeof(krb5_negotiate_auth_object));

	gss_buffer_desc nametmp;

	object->authed_user = GSS_C_NO_NAME;
	object->servname = GSS_C_NO_NAME;
	object->delegated = GSS_C_NO_CREDENTIAL;

	/* lookup server's FQDN */
	zval **server, **server_name;

	if(zend_hash_find(&EG(symbol_table), "_SERVER", sizeof("_SERVER"), (void**) &server) != FAILURE) {
		if(zend_hash_find(Z_ARRVAL_PP(server), "SERVER_NAME", sizeof("SERVER_NAME"), (void**) &server_name) != FAILURE) {
			char *hostname = Z_STRVAL_PP(server_name);
			struct hostent* host = gethostbyname(hostname);

			if(!host) {
				php_error_docref(NULL TSRMLS_CC, E_WARNING, "Failed to get server FQDN - Lookup failure");
			}

			nametmp.length = strlen(host->h_name) + 6;
			nametmp.value = emalloc(sizeof(char)*nametmp.length);
			snprintf(nametmp.value, nametmp.length, "HTTP@%s",host->h_name);

			status = gss_import_name(&minor_status, &nametmp,
							GSS_C_NT_HOSTBASED_SERVICE, &object->servname);

			if(GSS_ERROR(status)) {
				php_krb5_gssapi_handle_error(status, minor_status TSRMLS_CC);
				php_error_docref(NULL TSRMLS_CC, E_ERROR, "Could not parse server name");
			}

			efree(nametmp.value);
		} else {
			php_error_docref(NULL TSRMLS_CC, E_WARNING, "Failed to get server FQDN");
		}
	}

	INIT_STD_OBJECT(object->std, ce);

#if PHP_VERSION_ID < 50399
    zend_hash_copy(object->std.properties, &ce->default_properties,
	        		(copy_ctor_func_t) zval_add_ref, NULL,
					sizeof(zval*));
#else
	object_properties_init(&(object->std), ce);
#endif

	retval.handle = zend_objects_store_put(object, php_krb5_negotiate_auth_object_dtor, NULL, NULL TSRMLS_CC);

	retval.handlers = &krb5_negotiate_auth_handlers;
	return retval;
} /* }}} */

/* {{{ */
int php_krb5_negotiate_auth_register_classes(TSRMLS_D) {
	zend_class_entry negotiate_auth;

	INIT_CLASS_ENTRY(negotiate_auth, "KRB5NegotiateAuth", krb5_negotiate_auth_functions);
	krb5_ce_negotiate_auth = zend_register_internal_class(&negotiate_auth TSRMLS_CC);
	krb5_ce_negotiate_auth->create_object = php_krb5_negotiate_auth_object_new;
	memcpy(&krb5_negotiate_auth_handlers, zend_get_std_object_handlers(), sizeof(zend_object_handlers));

	return SUCCESS;
} /* }}} */


/** KRB5NegotiateAuth Methods **/
/* {{{ proto bool KRB5NegotiateAuth::__construct( string $keytab )
   Initialize KRB5NegotitateAuth object with a keytab to use  */
PHP_METHOD(KRB5NegotiateAuth, __construct)
{
	char *keytab;
	int keytab_len;

	if(zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, ARG_PATH, &keytab, &keytab_len) == FAILURE) {
		RETURN_FALSE;
	}

	if(krb5_gss_register_acceptor_identity(keytab) != GSS_S_COMPLETE) {
		zend_throw_exception(NULL, "Failed to use credential cache", 0 TSRMLS_CC);
		return;
	}
} /* }}} */

/* {{{ proto bool KRB5NegotiateAuth::doAuthentication(  )
   Performs Negotiate/GSSAPI authentication  */
PHP_METHOD(KRB5NegotiateAuth, doAuthentication)
{
	char *token = NULL;
	int token_len = 0;
	krb5_negotiate_auth_object *object;

	OM_uint32 status = 0;
	OM_uint32 minor_status = 0;
	OM_uint32 flags;
	gss_ctx_id_t gss_context = GSS_C_NO_CONTEXT;
	gss_buffer_t input_token = GSS_C_NO_BUFFER;
	gss_buffer_desc output_token;
	gss_cred_id_t server_creds = GSS_C_NO_CREDENTIAL;

	if (zend_parse_parameters_none() == FAILURE) {
		RETURN_FALSE;
	}

	object = (krb5_negotiate_auth_object*) zend_object_store_get_object(getThis() TSRMLS_CC);

	if(!object) {
		RETURN_FALSE;
	}


	/* get authentication data */
#if 1
	zval **auth_header = NULL;
 
 
	if(PG(http_globals)[TRACK_VARS_SERVER] && zend_hash_find(PG(http_globals)[TRACK_VARS_SERVER]->value.ht, "HTTP_AUTHORIZATION", sizeof("HTTP_AUTHORIZATION"), (void **) &auth_header) != FAILURE) {
 
		if(!strncasecmp(Z_STRVAL_PP(auth_header), "negotiate", 9) == 0) {
 			// user agent did not provide negotiate authentication data
 			RETURN_FALSE;
 		}
 
		if(Z_STRLEN_PP(auth_header) < 11) {
 			// user agent gave negotiate header but no data
 			zend_throw_exception(NULL, "Invalid negotiate authentication data given", 0 TSRMLS_CC);
 			return;
 		}
 
 #if (PHP_MAJOR_VERSION == 5 && PHP_MINOR_VERSION > 1) || (PHP_MAJOR_VERSION > 5)
		token = (char*) php_base64_decode_ex((unsigned char*) Z_STRVAL_PP(auth_header)+10, Z_STRLEN_PP(auth_header) - 10, &token_len, 1);
 #else
		token = (char*) php_base64_decode((unsigned char*) Z_STRVAL_PP(auth_header)+10, Z_STRLEN_PP(auth_header) - 10, &token_len);
 #endif
#else
	char *auth_header = NULL;
	int auth_header_len  = 0;

	zend_llist* header_list = &SG(sapi_headers).headers;

	zend_llist_position iter = header_list->head;

	sapi_header_struct *cur_header = zend_llist_get_first_ex(header_list, &iter);

	do {
		if(strncasecmp(cur_header->header, "Authorization:", 14) == 0) {
			php_printf("Found auth header: %s", cur_header->header);	
			break;
		}

		php_printf("header: %s", cur_header->header);
		cur_header = zend_llist_get_next_ex(header_list,&iter);
	} while(cur_header);


	if(auth_header) {
		if(!strncasecmp(auth_header, "negotiate", 9) == 0) {
			// user agent did not provide negotiate authentication data
			RETURN_FALSE;
		}

		if(auth_header_len < 11) {
			// user agent gave negotiate header but no data
			zend_throw_exception(NULL, "Invalid negotiate authentication data given", 0 TSRMLS_CC);
			return;
		}

#if (PHP_MAJOR_VERSION == 5 && PHP_MINOR_VERSION > 1) || (PHP_MAJOR_VERSION > 5)
		token = (char*) php_base64_decode_ex((unsigned char*) auth_header+10, auth_header_len - 10, &token_len, 1);
#else
		token = (char*) php_base64_decode((unsigned char*) auth_header+10, auth_header_len - 10, &token_len);
#endif
#endif
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

	status = gss_acquire_cred(&minor_status,
			object->servname,
			0,
			GSS_C_NO_OID_SET,
			GSS_C_ACCEPT,
			&server_creds,
			NULL,
			NULL);

	if(GSS_ERROR(status)) {
		efree(token);
		php_krb5_gssapi_handle_error(status, minor_status TSRMLS_CC);
		zend_throw_exception(NULL, "Error while obtaining server credentials", status TSRMLS_CC);
		RETURN_FALSE;
	}
	minor_status = 0;

	input_token = emalloc(sizeof(gss_buffer_desc));
	input_token->length = token_len;
	input_token->value = token;

	status = gss_accept_sec_context(   &minor_status,
                                       &gss_context,
                                       server_creds,
                                       input_token,
                                       GSS_C_NO_CHANNEL_BINDINGS,
                                       &object->authed_user,
                                       NULL,
                                       &output_token,
                                       &flags,
                                       NULL,
                                       &object->delegated);


	if(!(flags & GSS_C_DELEG_FLAG)) {
		object->delegated = GSS_C_NO_CREDENTIAL;
	}

	efree(input_token->value);
	efree(input_token);

	if(GSS_ERROR(status)) {
		php_krb5_gssapi_handle_error(status, minor_status TSRMLS_CC);
		zend_throw_exception(NULL, "Error while accepting security context", status TSRMLS_CC);
		RETURN_FALSE;
	}

	if(gss_context != GSS_C_NO_CONTEXT) {
		gss_delete_sec_context(&minor_status, &gss_context, GSS_C_NO_BUFFER);
	}

	if(output_token.length > 0) {

		int encoded_len = 0;
		char *encoded = (char*) php_base64_encode(output_token.value, output_token.length, &encoded_len);

		sapi_header_line ctr = {0};

		ctr.line = emalloc(sizeof("WWW-Authenticate: ")+encoded_len);
		strcpy(ctr.line, "WWW-Authenticate: ");
		strcpy(ctr.line + strlen("WWW-Authenticate: "), (char*) encoded);
		ctr.response_code = 200;
		sapi_header_op(SAPI_HEADER_ADD, &ctr TSRMLS_CC);

		efree(ctr.line);
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
	object = (krb5_negotiate_auth_object*) zend_object_store_get_object(getThis() TSRMLS_CC);

	if(!object || !object->authed_user || object->authed_user == GSS_C_NO_NAME) {
		RETURN_FALSE;
	}

	gss_buffer_desc username_tmp;
	status = gss_display_name(&minor_status, object->authed_user, &username_tmp, NULL);

	if(GSS_ERROR(status)) {
		php_krb5_gssapi_handle_error(status, minor_status TSRMLS_CC);
		RETURN_FALSE;
	}

	ZVAL_STRINGL(return_value, username_tmp.value, username_tmp.length, 1);
	gss_release_buffer(&minor_status, &username_tmp);
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

	object = (krb5_negotiate_auth_object*) zend_object_store_get_object(getThis() TSRMLS_CC);

	if(object->delegated == GSS_C_NO_CREDENTIAL) {
		zend_throw_exception(NULL, "No delegated credentials available", 0 TSRMLS_CC);
		return;
	}

	if(zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "O", &zticket, krb5_ce_ccache) == FAILURE) {
		return;
	}

	ticket = (krb5_ccache_object*) zend_object_store_get_object(zticket TSRMLS_CC);
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

