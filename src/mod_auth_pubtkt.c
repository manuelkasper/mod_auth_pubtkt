/*
	mod_auth_pubtkt
	
	based on mod_auth_tkt by Open Fusion
	(http://www.openfusion.com.au/labs/mod_auth_tkt/)
	
	Copyright 2008-2009 Manuel Kasper <mk@neon1.net>.
	
	See the LICENSE file included in the distribution for the license terms.
*/
#include "mod_auth_pubtkt.h"

/* ----------------------------------------------------------------------- */
/* Global variables */
auth_pubtkt_cache	*cache = NULL;
#if APR_HAS_THREADS
apr_thread_mutex_t	*cache_lock;
#endif

/* ----------------------------------------------------------------------- */
/* Initializers */
#ifdef APACHE13

void auth_pubtkt_init(server_rec *s, pool *p) {
	ap_add_version_component("mod_auth_pubtkt/" PUBTKT_AUTH_VERSION);
	ap_log_error(APLOG_MARK, APLOG_INFO, APR_SUCCESS, s, 
		"mod_auth_pubtkt: version %s", PUBTKT_AUTH_VERSION);
}

void auth_pubtkt_child_init(server_rec *s, pool *p) {
	CRYPTO_malloc_init();
	ERR_load_crypto_strings();
	OpenSSL_add_all_algorithms();
	
	cache_init(p, s);
}

#else
static int auth_pubtkt_init(apr_pool_t *p, 
	apr_pool_t *plog, apr_pool_t *ptemp, server_rec *s) {
	
	ap_add_version_component(p, "mod_auth_pubtkt/" PUBTKT_AUTH_VERSION);
	ap_log_error(APLOG_MARK, APLOG_INFO, APR_SUCCESS, s, 
		"mod_auth_pubtkt: version %s", PUBTKT_AUTH_VERSION);
	return DECLINED;
}

static void auth_pubtkt_child_init(apr_pool_t *p, server_rec *s) {
	CRYPTO_malloc_init();
	ERR_load_crypto_strings();
	OpenSSL_add_all_algorithms();
	
	cache_init(p, s);
}
#endif

/* Create per-dir config structures */
static void* create_auth_pubtkt_config(apr_pool_t *p, char* path) {
	auth_pubtkt_dir_conf *conf = apr_palloc(p, sizeof(*conf));
	
	conf->directory = path;
	conf->login_url = NULL;
	conf->timeout_url = NULL;
	conf->post_timeout_url = NULL;
	conf->unauth_url = NULL;
	conf->auth_token = apr_array_make(p, 0, sizeof (char *));
	conf->auth_cookie_name = NULL;
	conf->back_arg_name = NULL;
	conf->refresh_url = NULL;
	conf->require_ssl = -1;
	conf->debug = -1;
	conf->fake_basic_auth = -1;
	return conf;
}

/* Merge per-dir config structures */
static void* merge_auth_pubtkt_config(apr_pool_t *p, void* parent_dirv, void* subdirv) {

	auth_pubtkt_dir_conf *parent = (auth_pubtkt_dir_conf *) parent_dirv;
	auth_pubtkt_dir_conf *subdir = (auth_pubtkt_dir_conf *) subdirv;
	auth_pubtkt_dir_conf *conf = apr_palloc(p, sizeof(*conf));
	
	conf->directory = (subdir->directory) ? subdir->directory : parent->directory;
	conf->login_url = (subdir->login_url) ? subdir->login_url : parent->login_url;
	conf->timeout_url = (subdir->timeout_url) ? subdir->timeout_url : parent->timeout_url;
	conf->post_timeout_url = (subdir->post_timeout_url) ? subdir->post_timeout_url : parent->post_timeout_url;
	conf->unauth_url = (subdir->unauth_url) ? subdir->unauth_url : parent->unauth_url;
	conf->auth_token = (subdir->auth_token->nelts > 0) ? subdir->auth_token : parent->auth_token;
	conf->auth_cookie_name = (subdir->auth_cookie_name) ? subdir->auth_cookie_name : parent->auth_cookie_name;
	conf->back_arg_name = (subdir->back_arg_name) ? subdir->back_arg_name : parent->back_arg_name;
	conf->refresh_url = (subdir->refresh_url) ? subdir->refresh_url : parent->refresh_url;
	conf->require_ssl = (subdir->require_ssl >= 0) ? subdir->require_ssl : parent->require_ssl;
	conf->debug = (subdir->debug >= 0) ? subdir->debug : parent->debug;
	conf->fake_basic_auth = (subdir->fake_basic_auth >= 0) ? subdir->fake_basic_auth : parent->fake_basic_auth;
	
	return conf;
}

/* Create per-server config structures */
static void *create_auth_pubtkt_serv_config(apr_pool_t *p, server_rec* s) {
	auth_pubtkt_serv_conf *conf = apr_palloc(p, sizeof(*conf));
	conf->pubkey = NULL;
	
	return conf;
} 

/* Merge per-server config structures */
static void *merge_auth_pubtkt_serv_config(apr_pool_t *p, void* parent_dirv, void* subdirv) {
	auth_pubtkt_serv_conf *parent = (auth_pubtkt_serv_conf*)parent_dirv;
	auth_pubtkt_serv_conf *subdir = (auth_pubtkt_serv_conf*)subdirv;
	auth_pubtkt_serv_conf *conf = apr_palloc(p, sizeof(*conf));
	
	conf->pubkey = (subdir->pubkey) ? subdir->pubkey : parent->pubkey;
	return conf;
}

/* ----------------------------------------------------------------------- */
/* Caching */

static void cache_init(apr_pool_t *p, server_rec* s) {
	int i;
	
	cache = (auth_pubtkt_cache*)apr_palloc(p, sizeof(auth_pubtkt_cache));
	if (cache == NULL) {
		ap_log_error(APLOG_MARK, APLOG_ERR, APR_SUCCESS, s, 
			"TKT: cache init failed!");
		return;
	}
	
	cache->nextslot = 0;
	
	for (i = 0; i < CACHE_SIZE; i++)
		cache->slots[i].hash = 0;
	
#if APR_HAS_THREADS
	apr_thread_mutex_create(&(cache_lock), APR_THREAD_MUTEX_DEFAULT, p);
#endif
}

static int cache_get(const char *ticket, auth_pubtkt *tkt) {
	int i, found = 0;
	unsigned int hash;

	if (cache == NULL)
		return 0;
	
#if APR_HAS_THREADS
    apr_thread_mutex_lock(cache_lock);
#endif

	hash = cache_hash(ticket);

	for (i = 0; i < CACHE_SIZE; i++) {
		if (hash == cache->slots[i].hash) {
			if (strcmp(ticket, cache->slots[i].ticket) == 0) {
				/* found it */
				memcpy(tkt, &cache->slots[i].tkt, sizeof(*tkt));
				found = 1;
				break;
			}
		}
	}

#if APR_HAS_THREADS
    apr_thread_mutex_unlock(cache_lock);
#endif
	
	return found;
}

/* Put a new ticket into the cache. */
static void cache_put(const char *ticket, auth_pubtkt *tkt) {
	if (cache == NULL)
		return;

#if APR_HAS_THREADS
    apr_thread_mutex_lock(cache_lock);
#endif
	
	cache->slots[cache->nextslot].hash = cache_hash(ticket);
	
	strncpy(cache->slots[cache->nextslot].ticket, ticket, MAX_TICKET_SIZE);
	cache->slots[cache->nextslot].ticket[MAX_TICKET_SIZE] = 0;
	memcpy(&cache->slots[cache->nextslot].tkt, tkt, sizeof(*tkt));
	
	cache->nextslot++;
	if (cache->nextslot >= CACHE_SIZE)
		cache->nextslot = 0;

#if APR_HAS_THREADS
    apr_thread_mutex_unlock(cache_lock);
#endif
}

static unsigned int cache_hash(const char *ticket) {
	char *p;
	unsigned int hash = 0;

	for (p = (char*)ticket; *p; p++)
		hash = hash * 33 + *p;
	
	if (hash == 0)
		hash = 1;	/* unlikely case */
	
	return hash;
}

/* ----------------------------------------------------------------------- */
/* Command-specific functions */

module AP_MODULE_DECLARE_DATA auth_pubtkt_module;

static const char *set_auth_pubtkt_token(cmd_parms *cmd, void *cfg, const char *param) {
	char **new;
	auth_pubtkt_dir_conf *conf = (auth_pubtkt_dir_conf*)cfg;
	
	new = (char**)apr_array_push(conf->auth_token);
	*new = apr_pstrdup(cmd->pool, param);
	return NULL;
}

static const char *setup_pubkey(cmd_parms *cmd, void *cfg, const char *param) {
	FILE *fkey;
	const char *pubkeypath;
	auth_pubtkt_serv_conf *sconf = ap_get_module_config(cmd->server->module_config, &auth_pubtkt_module);

	/* read public key file */
	pubkeypath = ap_server_root_relative(cmd->pool, (char*)param);
	
	if (!pubkeypath)
		return apr_pstrcat(cmd->pool, cmd->cmd->name, ": Invalid file path ", param, NULL);
	
	fkey = fopen(pubkeypath, "r");
	if (fkey == NULL)
		return apr_psprintf(cmd->pool, "unable to open public key file '%s'", pubkeypath);
	
	sconf->pubkey = PEM_read_PUBKEY(fkey, NULL, NULL, NULL);
	fclose(fkey);
	
	if (sconf->pubkey == NULL)
		return apr_psprintf(cmd->pool, "unable to read public key file '%s': %s",
			pubkeypath, ERR_reason_error_string(ERR_get_error()));
	
	/* check key type */
	if (!(sconf->pubkey->type == EVP_PKEY_RSA || sconf->pubkey->type == EVP_PKEY_RSA2 ||
		  sconf->pubkey->type == EVP_PKEY_DSA || sconf->pubkey->type == EVP_PKEY_DSA1 || sconf->pubkey->type == EVP_PKEY_DSA2 ||
		  sconf->pubkey->type == EVP_PKEY_DSA3 || sconf->pubkey->type == EVP_PKEY_DSA4))
		return apr_psprintf(cmd->pool, "unsupported key type %d", sconf->pubkey->type);
	
	return NULL;
}

static const char *set_auth_pubtkt_debug(cmd_parms *cmd, void *cfg, const char *param) {
	auth_pubtkt_dir_conf *conf = (auth_pubtkt_dir_conf*)cfg;
	
	int debug = atoi(param);
	
	if (debug < 0)        return ("Debug level must be positive");
	if (debug == INT_MAX) return ("Integer overflow or invalid number");
	
	conf->debug = debug;
	
	return NULL;
}

/* Command table */
static const command_rec auth_pubtkt_cmds[] =
{
	AP_INIT_TAKE1("TKTAuthLoginURL", ap_set_string_slot, 
		(void *)APR_OFFSETOF(auth_pubtkt_dir_conf, login_url),
		OR_AUTHCFG, "URL to redirect to if authentication fails"),
	AP_INIT_TAKE1("TKTAuthTimeoutURL", ap_set_string_slot, 
		(void *)APR_OFFSETOF(auth_pubtkt_dir_conf, timeout_url),
		OR_AUTHCFG, "URL to redirect to if cookie times-out"),
	AP_INIT_TAKE1("TKTAuthPostTimeoutURL", ap_set_string_slot, 
		(void *)APR_OFFSETOF(auth_pubtkt_dir_conf, post_timeout_url),
		OR_AUTHCFG, "URL to redirect to if cookie times-out doing a POST"),
	AP_INIT_TAKE1("TKTAuthUnauthURL", ap_set_string_slot, 
		(void *)APR_OFFSETOF(auth_pubtkt_dir_conf, unauth_url),
		OR_AUTHCFG, "URL to redirect to if valid user without required token"),
	AP_INIT_TAKE1("TKTAuthCookieName", ap_set_string_slot, 
		(void *)APR_OFFSETOF(auth_pubtkt_dir_conf, auth_cookie_name),
		OR_AUTHCFG, "name to use for ticket cookie"),
	AP_INIT_TAKE1("TKTAuthBackArgName", ap_set_string_slot, 
		(void *)APR_OFFSETOF(auth_pubtkt_dir_conf, back_arg_name),
		OR_AUTHCFG, "name to use for back url argument (NULL for none)"),
	AP_INIT_TAKE1("TKTAuthRefreshURL", ap_set_string_slot, 
		(void *)APR_OFFSETOF(auth_pubtkt_dir_conf, refresh_url),
		OR_AUTHCFG, "URL to redirect to if cookie reach grace period"),
	AP_INIT_FLAG("TKTAuthRequireSSL", ap_set_flag_slot, 
		(void *)APR_OFFSETOF(auth_pubtkt_dir_conf, require_ssl),
		OR_AUTHCFG, "whether to refuse non-HTTPS requests"),
	AP_INIT_FLAG("TKTAuthFakeBasicAuth", ap_set_flag_slot, 
		(void *)APR_OFFSETOF(auth_pubtkt_dir_conf, fake_basic_auth),
		OR_AUTHCFG, "whether to refuse non-HTTPS requests"),
	AP_INIT_ITERATE("TKTAuthToken", set_auth_pubtkt_token, 
		(void *)APR_OFFSETOF(auth_pubtkt_dir_conf, auth_token),
		OR_AUTHCFG, "token required to access this area (NULL for none)"),
	AP_INIT_TAKE1("TKTAuthPublicKey", setup_pubkey, 
		NULL, RSRC_CONF, "public key file to use in MD5 digest"),
	AP_INIT_ITERATE("TKTAuthDebug", set_auth_pubtkt_debug, 
		(void *)APR_OFFSETOF(auth_pubtkt_dir_conf, debug),
		OR_AUTHCFG, "debug level (1-3, higher for more debug output)"),
	{NULL},
};

/* ----------------------------------------------------------------------- */
/* Support functions */

/* Parse ticket (assuming it has already been validated).
   Returns 1 on success or 0 on error. */
static int parse_ticket(request_rec *r, char *ticket, auth_pubtkt *tkt) {

	auth_pubtkt_dir_conf *conf = ap_get_module_config(r->per_dir_config, &auth_pubtkt_module);
	char *tok, *last;
	
	for (tok = apr_strtok(ticket, ";", &last); tok; tok = apr_strtok(NULL, ";", &last)) {
		/* split key/value pair */
		char *key, *value;
		char *eqptr = strchr(tok, '=');
		if (eqptr == NULL) {
			ap_log_rerror(APLOG_MARK, APLOG_WARNING, APR_SUCCESS, r, 
				"TKT parse_ticket: bad key/value pair: '%s'", tok);
			continue;
		}
		
		*eqptr = 0;
		key = tok;
		value = (eqptr + 1);
		
		if (strcmp(key, "uid") == 0)
			strncpy(tkt->uid, value, sizeof(tkt->uid)-1);
		else if (strcmp(key, "cip") == 0)
			strncpy(tkt->clientip, value, sizeof(tkt->clientip)-1);
		else if (strcmp(key, "validuntil") == 0)
			tkt->valid_until = atoi(value);
		else if (strcmp(key, "graceperiod") == 0)
			tkt->grace_period = atoi(value);
		else if (strcmp(key, "tokens") == 0)
			strncpy(tkt->tokens, value, sizeof(tkt->tokens)-1);
		else if (strcmp(key, "udata") == 0)
			strncpy(tkt->user_data, value, sizeof(tkt->user_data)-1);
	}
	
	if (!tkt->uid[0] || tkt->valid_until == 0) {
		ap_log_rerror(APLOG_MARK, APLOG_WARNING, APR_SUCCESS, r, 
			"TKT parse_ticket missing keys in ticket '%s'", ticket);
		return 0;
	}

	if (conf->debug >= 1) {
		ap_log_rerror(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, r, 
			"TKT parse_ticket decoded ticket: uid %s, cip %s, validuntil %u, graceperiod %u, tokens %s, udata %s",
			tkt->uid, tkt->clientip, tkt->valid_until, tkt->grace_period, tkt->tokens, tkt->user_data);
	}
  	
	return 1;
}

/* Search cookie headers for our ticket */
static int cookie_match(void *result, const char *key, const char *cookie) {
	cookie_res *cr = (cookie_res*)result;
	auth_pubtkt_dir_conf *conf = ap_get_module_config(cr->r->per_dir_config, &auth_pubtkt_module);
	
	if (cookie != NULL) {
		char *cookie_name, *value;
		int cknamelen = strlen(cr->cookie_name);
		
		cookie_name = apr_palloc(cr->r->pool, cknamelen + 2);
		strncpy(cookie_name, cr->cookie_name, cknamelen);
		cookie_name[cknamelen] = '=';
		cookie_name[cknamelen + 1] = '\0';
		
		value = (char*)cookie;
		while ((value = strstr(value, cookie_name))) {
			/* Cookie includes our cookie_name - copy (first) value into cookiebuf */
			char *cookiebuf, *end;
			int len;
			
			value += (cknamelen + 1);
			cookiebuf = apr_pstrdup(cr->r->pool, value);
			end = ap_strchr(cookiebuf, ';');
			if (end)
				*end = '\0';      /* Ignore anything after the next ; */
			
			/* Skip empty cookies (such as with misconfigured logoffs) */
			len = strlen(cookiebuf);
			if (len > 0) {
				int i;
				
				/* UAs may quote cookie values */
				if (cookiebuf[len-1] == '"')
					cookiebuf[len-1] = 0;
				if (cookiebuf[0] == '"')
					cookiebuf++;
				
				/* Replace '+' by ' ' (not handled by ap_unescape_url_keep2f) */
				for (i = 0; cookiebuf[i]; i++) {
					if (cookiebuf[i] == '+')
						cookiebuf[i] = ' ';
				}
				
				/* URL-unescape cookie */
				if (ap_unescape_url_keep2f(cookiebuf) != 0) {
					ap_log_rerror(APLOG_MARK, APLOG_WARNING, APR_SUCCESS, cr->r, 
						"TKT cookie_match: error while URL-unescaping cookie");
					continue;
				}
				cr->cookie = cookiebuf;
				if (conf->debug >= 1) {
					ap_log_rerror(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, cr->r, 
						"TKT cookie_match: found '%s'", cookiebuf);
				}
				return 0;
			}
		}
	}
	if (conf->debug >= 2) {
		ap_log_rerror(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, cr->r, 
			"TKT cookie_match: NOT found");
	}
	return 1;
}

/* Look for a cookie ticket */
static char *get_cookie_ticket(request_rec *r) {
	auth_pubtkt_dir_conf *conf = ap_get_module_config(r->per_dir_config, &auth_pubtkt_module);
	
	/* Walk cookie headers looking for matching ticket */
	cookie_res *cr = apr_palloc(r->pool, sizeof(*cr));
	cr->r = r;
	cr->cookie = NULL;
	cr->cookie_name = (conf->auth_cookie_name) ? conf->auth_cookie_name : AUTH_COOKIE_NAME;
	apr_table_do(cookie_match, (void*)cr, r->headers_in, "Cookie", NULL);
	
	/* Give up if cookie not found or too short */
	if (!cr->cookie || strlen(cr->cookie) < MIN_AUTH_COOKIE_SIZE)
		return NULL;
	
	return cr->cookie;
}

/* Validate the signature on this ticket, and if it is good, parse the ticket
 * Returns the parsed ticket if valid, or NULL otherwise */
static auth_pubtkt* validate_parse_ticket(request_rec *r, char *ticket) {

	auth_pubtkt_dir_conf *conf = ap_get_module_config(r->per_dir_config, &auth_pubtkt_module);
	auth_pubtkt_serv_conf *sconf = ap_get_module_config(r->server->module_config, &auth_pubtkt_module);
	char *sigptr, *sig_buf;
	char *tktval_buf;
	int sig_len;
	auth_pubtkt *tkt;
	EVP_MD_CTX ctx;
	const EVP_MD *impl;
	
	if (strlen(ticket) > MAX_TICKET_SIZE) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, APR_SUCCESS, r, 
			"TKT validate_parse_ticket: ticket too long");
		return NULL;
	}
	
	tkt = (auth_pubtkt*)apr_pcalloc(r->pool, sizeof(*tkt));
	if (tkt == NULL) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, APR_SUCCESS, r, 
			"TKT validate_parse_ticket: cannot allocate memory for ticket");
		return NULL;
	}
	
	/* first check the cache for an entry for this ticket */
	if (cache_get(ticket, tkt)) {
		if (conf->debug >= 1) {
			ap_log_rerror(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, r,
				"TKT validate_parse_ticket: found ticket in cache: '%s'",
				ticket);
		}
		return tkt;
	}
	
	/* Before we attempt to do any more sophisticated parsing, verify that
	   the signature on the ticket is valid */
	
	/* find the signature */
	sigptr = strstr(ticket, ";sig=");
	
	if (sigptr == NULL) {
		ap_log_rerror(APLOG_MARK, APLOG_WARNING, APR_SUCCESS, r, 
			"TKT validate_parse_ticket: no signature found in ticket");
		return NULL;
	}
	
	/* split ticket value and signature */
	tktval_buf = apr_pstrndup(r->pool, ticket, (sigptr - ticket));
	sigptr += 5;
	sig_buf = (char*)apr_palloc(r->pool, strlen(sigptr) + 1);  
	sig_len = apr_base64_decode(sig_buf, sigptr);
	
	if (sig_len <= 0) {
		ap_log_rerror(APLOG_MARK, APLOG_WARNING, APR_SUCCESS, r, 
			"TKT validate_parse_ticket: empty or bad signature found in ticket");
		return NULL;
	}
	
	if (conf->debug >= 1) {
		ap_log_rerror(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, r,
			"TKT validate_parse_ticket: tktval '%s', sig '%s'",
			tktval_buf, sigptr);
	}
	
	if (sconf->pubkey->type == EVP_PKEY_RSA || sconf->pubkey->type == EVP_PKEY_RSA2)
		impl = EVP_sha1();
	else if (sconf->pubkey->type == EVP_PKEY_DSA || sconf->pubkey->type == EVP_PKEY_DSA1 ||
			 sconf->pubkey->type == EVP_PKEY_DSA2 || sconf->pubkey->type == EVP_PKEY_DSA3 ||
			 sconf->pubkey->type == EVP_PKEY_DSA4)
		impl = EVP_dss1();
	else {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, APR_SUCCESS, r,
			"TKT validate_parse_ticket: invalid algorithm!");
		return NULL;
	}
	
	ERR_clear_error();
	
	if (!EVP_VerifyInit(&ctx, impl)) {
		ap_log_rerror(APLOG_MARK, APLOG_WARNING, APR_SUCCESS, r, 
			"TKT validate_parse_ticket: EVP_VerifyInit failed");
		return NULL;
	}
	
	if (!EVP_VerifyUpdate(&ctx, tktval_buf, strlen(tktval_buf))) {
		ap_log_rerror(APLOG_MARK, APLOG_WARNING, APR_SUCCESS, r, 
			"TKT validate_parse_ticket: EVP_VerifyUpdate failed");
		return NULL;
	}
	
	if (EVP_VerifyFinal(&ctx, (unsigned char*)sig_buf, sig_len, sconf->pubkey) != 1) {
		unsigned long lasterr;
		char *errbuf = apr_palloc(r->pool, 120);
	
		ap_log_rerror(APLOG_MARK, APLOG_WARNING, APR_SUCCESS, r, 
			"TKT validate_parse_ticket: invalid signature!");
		
		while ((lasterr = ERR_get_error()) != 0) {
			ERR_error_string_n(lasterr, errbuf, 120);
			ap_log_rerror(APLOG_MARK, APLOG_WARNING, APR_SUCCESS, r, 
				"TKT validate_parse_ticket: OpenSSL error: %s", errbuf);
		}
		
		return NULL;
	}
	
	/* good signature - parse ticket */
	if (!parse_ticket(r, tktval_buf, tkt))
		return NULL;
	
	/* put the parsed ticket into the cache */
	cache_put(ticket, tkt);
	
	return tkt;
}

/* Check for required auth tokens 
 * Returns 1 on success, 0 on failure */
static int check_tokens(request_rec *r, auth_pubtkt *tkt) {

	auth_pubtkt_dir_conf *conf = ap_get_module_config(r->per_dir_config, &auth_pubtkt_module);
	char *next_parsed_token;
	const char *t = NULL;
	int match = 0;

	/* Success if no tokens required */
	if (conf->auth_token->nelts == 0 || strcmp(((char**)conf->auth_token->elts)[0], "NULL") == 0)
		return 1;
	
	/* Failure if no user tokens found */
	if (!tkt->tokens[0])
		return 0;

	t = apr_pstrdup(r->pool, tkt->tokens); 
  
	while (*t && (next_parsed_token = ap_getword(r->pool, &t, ','))) {
		char** auth_tokens = (char **)conf->auth_token->elts;
		int i;
		
		for (i = 0; i < conf->auth_token->nelts; i++) {
			int token_len = strlen(auth_tokens[i]);
			if (strncmp(auth_tokens[i], next_parsed_token, token_len) == 0 &&
				next_parsed_token[token_len] == 0) {
				match = 1;
				break;
			}
		}
		if (match)
			break;
	}
	
	if (conf->debug >= 1 && !match) {
		ap_log_rerror(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, r, 
			"TKT: no matching tokens! (user tokens '%s')", tkt->tokens);
	}
	
	return match;
}

/* Check client IP address against the one found in the ticket (if any)
   Returns 1 on success, 0 on failure */
static int check_clientip(request_rec *r, auth_pubtkt *tkt) {
	if (!tkt->clientip[0])
		return 1;		/* no clientip in ticket */
	
	return (strcmp(tkt->clientip, r->connection->remote_ip) == 0);
}
  
/* Check whether the given ticket has timed out 
 * Returns 1 if okay, 0 if timed out */
static int check_timeout(request_rec *r, auth_pubtkt *tkt) {
	time_t now = time(NULL);
	
	return (now <= tkt->valid_until);
}

/* Check whether the given ticket will time out and enter into grace period
 * Returns 1 if okay, 0 if timed out */
static int check_grace_period(request_rec *r, auth_pubtkt *tkt) {
	time_t now = time(NULL);

	return ((tkt->grace_period == 0 ) || (now <= tkt->grace_period));
}

/* Hex conversion, from httpd util.c */
static const char c2x_table[] = "0123456789abcdef";
static APR_INLINE unsigned char *c2x(unsigned what, unsigned char *where) {
#if APR_CHARSET_EBCDIC
	what = apr_xlate_conv_byte(ap_hdrs_to_ascii, (unsigned char)what);
#endif /*APR_CHARSET_EBCDIC*/
	*where++ = '%';
	*where++ = c2x_table[what >> 4];
	*where++ = c2x_table[what & 0xf];
	return where;
}

/* Extra escaping - variant of httpd util.c ap_escape_path_segment */
static char *escape_extras(apr_pool_t *p, const char *segment) {
	char *copy = apr_palloc(p, 3 * strlen(segment) + 1);
	const unsigned char *s = (const unsigned char *)segment;
	unsigned char *d = (unsigned char *)copy;
	unsigned c;
	
	while ((c = *s)) {
		if (c == '=' || c == '&' || c == ':')
			d = c2x(c, d);
		else
			*d++ = c;
		++s;
	}
	*d = '\0';
	return copy;
}

/* External redirect to the given url, setting 'back' argument */
static int redirect(request_rec *r, char *location) {
	auth_pubtkt_dir_conf *conf = ap_get_module_config(r->per_dir_config, &auth_pubtkt_module);
	
	char *back_arg_name = (conf->back_arg_name) ? conf->back_arg_name : BACK_ARG_NAME;
	char *query;
	char *url, *back;
	const char *hostinfo = 0;
	int port;
	char sep;
	
	/* Get the scheme we use (http or https) */
	const char *scheme = (char*)ap_http_method(r);
	
	/* Use main request args if subrequest */
	request_rec *r_main = r->main == NULL ? r : r->main;
	if (r_main->args == NULL) 
		query = "";
	else
		query = apr_psprintf(r->pool, "?%s", r_main->args); 
	
	/* Build back URL */
	/* Use X-Forward-Host header for host:port info if available */
	/* Failing that, use Host header */
	hostinfo = apr_table_get(r->headers_in, "X-Forwarded-Host");
	/*if (!hostinfo) 	XXX Host header doesn't include port??
		hostinfo = apr_table_get(r->headers_in, "Host");*/
	if (!hostinfo) {
		/* Fallback to using r->hostname and the server port. This usually
		   works, but behind a reverse proxy the port may well be wrong. 
		   On the other hand, it's really the proxy's problem, not ours.
		*/
		port = ap_get_server_port(r);
		hostinfo = port == apr_uri_default_port_for_scheme(scheme) ?
			apr_psprintf(r->pool, "%s", r->hostname) :
			apr_psprintf(r->pool, "%s:%d", r->hostname, port);
	}
	back = apr_psprintf(r->pool, "%s://%s%s%s", scheme, hostinfo, r->uri, query);
	
	if (conf->debug >= 1) {
		ap_log_rerror(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, r, 
			"TKT: back url '%s'", back);
	}
	
	/* Escape testing */
	back = ap_escape_path_segment(r->pool, back);
	back = escape_extras(r->pool, back);
	
	/* Add a back url argument to url */
	sep = ap_strchr(location, '?') ? '&' : '?';
	url = apr_psprintf(r->pool, "%s%c%s=%s", location, sep, back_arg_name, back);
	
	if (conf->debug >= 2) {
		ap_log_rerror(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, r, 
			"TKT: redirect '%s'", url);
	}
	apr_table_setn(r->headers_out, "Location", url);
	
	return (r->proto_num  >= HTTP_VERSION(1,1)) ? HTTP_TEMPORARY_REDIRECT : HTTP_MOVED_TEMPORARILY;
}

/* ----------------------------------------------------------------------- */
/* Debug routines */
void dump_config(request_rec *r) {
	auth_pubtkt_dir_conf *conf = ap_get_module_config(r->per_dir_config, &auth_pubtkt_module);
	
	if (conf->debug >= 3) {		
		/* Dump config settings */
		fprintf(stderr,"[ mod_auth_pubtkt config ]\n");
		fprintf(stderr,"URI: %s\n", r->uri);
		fprintf(stderr,"Filename: %s\n",                    r->filename);
		fprintf(stderr,"directory: %s\n", 		        conf->directory);
		fprintf(stderr,"TKTAuthLoginURL: %s\n", 	        conf->login_url);
		fprintf(stderr,"TKTAuthTimeoutURL: %s\n", 	        conf->timeout_url);
		fprintf(stderr,"TKTAuthPostTimeoutURL: %s\n",	conf->post_timeout_url);
		fprintf(stderr,"TKTAuthUnauthURL: %s\n", 	        conf->unauth_url);
		fprintf(stderr,"TKTAuthCookieName: %s\n", 	        conf->auth_cookie_name);
		fprintf(stderr,"TKTAuthBackArgName: %s\n",	        conf->back_arg_name);
		fprintf(stderr,"TKTAuthRefreshURL: %s\n",	        conf->refresh_url);
		fprintf(stderr,"TKTAuthRequireSSL: %d\n", 	        conf->require_ssl);
		if (conf->auth_token->nelts > 0) {
			char ** auth_token = (char **) conf->auth_token->elts;
			int i;
			for (i = 0; i < conf->auth_token->nelts; i++) {
				fprintf(stderr, "TKTAuthToken: %s\n", auth_token[i]);
			}
		}
		fprintf(stderr,"TKTAuthDebug: %d\n",                conf->debug);
		fprintf(stderr,"TKTAuthFakeBasicAuth: %d\n", 	    conf->fake_basic_auth);
		fflush(stderr);
	}
}

/* ----------------------------------------------------------------------- */
/* Main ticket authentication */
static int auth_pubtkt_check(request_rec *r) {
	char *ticket;
	auth_pubtkt *parsed;
	auth_pubtkt_dir_conf *conf = ap_get_module_config(r->per_dir_config,
									&auth_pubtkt_module);
	auth_pubtkt_serv_conf *sconf = ap_get_module_config(r->server->module_config,
									&auth_pubtkt_module);
	const char *scheme = (char*)ap_http_method(r);
	const char *current_auth = (char*)ap_auth_type(r);
	char *url = NULL;

	dump_config(r);

	if (!current_auth || strcasecmp(current_auth, MOD_AUTH_PUBTKT_AUTH_TYPE)) {
		return DECLINED;
	}

	/* Module misconfigured unless login_url is set */
	if (!conf->login_url) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, APR_SUCCESS, r,
		    "TKT: TKTAuthLoginURL missing");
		return HTTP_INTERNAL_SERVER_ERROR;
	}
	
	/* Module misconfigured unless public key set */
	if (!sconf->pubkey) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, APR_SUCCESS, r, 
			"TKT: TKTAuthPublicKey missing");
		return HTTP_INTERNAL_SERVER_ERROR;
	}
	
	/* Redirect/login if scheme not "https" and require_ssl is set */
	if (conf->require_ssl > 0 && strcmp(scheme, "https") != 0) {
		ap_log_rerror(APLOG_MARK, APLOG_WARNING, APR_SUCCESS, r, 
			"TKT: redirect/login - unsecured request, TKTAuthRequireSSL is on");
		return redirect(r, conf->login_url);
	}

	/* Check for ticket cookie */
	ticket = get_cookie_ticket(r);
	if (ticket == NULL) {
		ap_log_rerror(APLOG_MARK, APLOG_INFO, APR_SUCCESS, r, 
			"TKT: no ticket found - redirecting to login URL");
		return redirect(r, conf->login_url);
	}
	
	/* Validate and parse ticket (or get it from cache) */
	parsed = validate_parse_ticket(r, ticket);
	
	if (parsed == NULL) {
		ap_log_rerror(APLOG_MARK, APLOG_INFO, APR_SUCCESS, r, 
			"TKT: invalid ticket found - redirecting to login URL");
		return redirect(r, conf->login_url);
	}
	
	/* Check client IP address (if present in ticket) */
	if (!check_clientip(r, parsed)) {
		ap_log_rerror(APLOG_MARK, APLOG_INFO, APR_SUCCESS, r,
			"TKT: client IP mismatch (ticket: %s, request: %s) - redirecting to login URL",
			parsed->clientip, r->connection->remote_ip);
		
		return redirect(r, conf->login_url);
	}

	/* Valid ticket, check timeout - redirect/timed-out if so */
	if (!check_timeout(r, parsed)) {
		ap_log_rerror(APLOG_MARK, APLOG_INFO, APR_SUCCESS, r,
			"TKT: ticket expired - redirecting to timeout URL");
		
		/* Special timeout URL can be defined for POST requests */
		if (strcmp(r->method, "POST") == 0 && conf->post_timeout_url)
			url = conf->post_timeout_url;
		else
			url = conf->timeout_url ? conf->timeout_url : conf->login_url;
		
		return redirect(r, url);
	}
	
	/* Attempt to refresh cookie if it will expires - redirect on get if so */
	if ( !check_grace_period(r, parsed) && strcmp(r->method, "GET") == 0 ) {
		ap_log_rerror(APLOG_MARK, APLOG_INFO, APR_SUCCESS, r,
			"TKT: ticket grace period - redirecting to refresh URL");
		return redirect(r, (conf->refresh_url ? conf->refresh_url : conf->login_url));
	}

	/* Check tokens - redirect/unauthorised if so */
	if (!check_tokens(r, parsed))
		return redirect(r, conf->unauth_url ? conf->unauth_url : conf->login_url);

	/* Setup apache user, auth_type, and environment variables */
#ifdef APACHE13
	r->connection->user = parsed->uid;
	r->connection->ap_auth_type = MOD_AUTH_PUBTKT_AUTH_TYPE;
#else
	r->user = parsed->uid;
	r->ap_auth_type = MOD_AUTH_PUBTKT_AUTH_TYPE;
#endif
	apr_table_set(r->subprocess_env, REMOTE_USER_ENV,        parsed->uid);
	apr_table_set(r->subprocess_env, REMOTE_USER_DATA_ENV,   parsed->user_data);
	apr_table_set(r->subprocess_env, REMOTE_USER_TOKENS_ENV, parsed->tokens);

	if( !apr_table_get(r->headers_in, "Authorization") && conf->fake_basic_auth>0 ) {
		ap_log_rerror(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, r,
			"TKT: Adding faking basic auth");

		apr_table_set(r->headers_in, "Authorization", 
			apr_pstrcat(r->pool, "Basic ",
				ap_pbase64encode(r->pool,
					apr_pstrcat(r->pool, parsed->uid, ":password", NULL)), NULL));

	}

	return OK;
}

/* ----------------------------------------------------------------------- */
/* Setup main module data structure */

#ifdef APACHE13
/* Apache 1.3 style */

module MODULE_VAR_EXPORT auth_pubtkt_module = {
	STANDARD_MODULE_STUFF, 
	auth_pubtkt_init,					/* initializer */
	create_auth_pubtkt_config,			/* create per-dir    config structures */
	merge_auth_pubtkt_config,			/* merge  per-dir    config structures */
	create_auth_pubtkt_serv_config,		/* create per-server config structures */
	merge_auth_pubtkt_serv_config,		/* merge  per-server config structures */
	auth_pubtkt_cmds,					/* table of config file commands       */
	NULL,								/* handlers */
	NULL,								/* filename translation */
	auth_pubtkt_check,					/* check user_id */
	NULL,								/* check auth */
	NULL,								/* check access */
	NULL,								/* type_checker */
	NULL,								/* fixups */
	NULL,								/* logger */
	NULL,								/* header parser */
	auth_pubtkt_child_init,				/* child_init */
	NULL,								/* child_exit */
	NULL 								/* post read-request */
};

#else
/* Apache 2.0 style */

/* Register hooks */
static void auth_pubtkt_register_hooks (apr_pool_t *p) {
	ap_hook_post_config(auth_pubtkt_init, NULL, NULL, APR_HOOK_MIDDLE);
	ap_hook_check_user_id(auth_pubtkt_check, NULL, NULL, APR_HOOK_MIDDLE);
	ap_hook_child_init(auth_pubtkt_child_init, NULL, NULL, APR_HOOK_FIRST);
}

/* Declare and populate the main module data structure */
module AP_MODULE_DECLARE_DATA auth_pubtkt_module = {
  STANDARD20_MODULE_STUFF, 
  create_auth_pubtkt_config,		/* create per-dir    config structures */
  merge_auth_pubtkt_config,			/* merge  per-dir    config structures */
  create_auth_pubtkt_serv_config,	/* create per-server config structures */
  merge_auth_pubtkt_serv_config,	/* merge  per-server config structures */
  auth_pubtkt_cmds,					/* table of config file commands       */
  auth_pubtkt_register_hooks		/* register hooks                      */
};

#endif
