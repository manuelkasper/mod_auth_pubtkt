#ifndef MOD_AUTH_PUBTKT_H
#define MOD_AUTH_PUBTKT_H 1

#ifndef _WIN32
#include <netinet/in.h>
#include <arpa/inet.h>
#endif
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/x509.h>
#include <openssl/err.h>
#include <openssl/pem.h>

#include "httpd.h"
#include "http_config.h"
#include "http_log.h"
#include "http_core.h"
#include "http_protocol.h"
#include "http_request.h"
#include "ap_mmn.h"

#if MODULE_MAGIC_NUMBER < 20010224
#include "ap_compat.h"
#else
#include "apr_lib.h"
#include "apr_strings.h"
#include "apr_uuid.h"
#include "apr_base64.h"
#include "apu_version.h"
#endif
#if MODULE_MAGIC_NUMBER >= 20050101
#define ap_http_method ap_http_scheme
#endif
#if APU_MAJOR_VERSION > 0
#define apr_uri_default_port_for_scheme apr_uri_port_of_scheme
#endif

#define MOD_AUTH_PUBTKT_AUTH_TYPE "mod_auth_pubtkt"
#define AUTH_COOKIE_NAME "auth_pubtkt"
#define BACK_ARG_NAME "back"
#define REMOTE_USER_ENV "REMOTE_USER"
#define REMOTE_USER_DATA_ENV "REMOTE_USER_DATA"
#define REMOTE_USER_TOKENS_ENV "REMOTE_USER_TOKENS"
#define MIN_AUTH_COOKIE_SIZE 64	/* the Base64-encoded signature alone is >= 64 bytes */
#define CACHE_SIZE 200			/* number of entries in ticket cache */
#define MAX_TICKET_SIZE 1024	/* maximum length of raw ticket */

#define PUBTKT_AUTH_VERSION "0.6"

/* ----------------------------------------------------------------------- */
/* Per-directory configuration */
typedef struct  {
	char				*directory;
	char				*login_url;
	char				*timeout_url;
	char				*post_timeout_url;
	char				*unauth_url;
	char				*auth_cookie_name;
	char				*back_arg_name;
	char				*refresh_url;
	apr_array_header_t	*auth_token;
	int					require_ssl;
	int					debug;
	int					fake_basic_auth;
	int					grace_period;
} auth_pubtkt_dir_conf;

/* Per-server configuration */
typedef struct {
	EVP_PKEY	*pubkey;	/* public key for signature verification */
} auth_pubtkt_serv_conf;

/* Ticket structure */
typedef struct {
	char			uid[33];
	char			clientip[40];
	unsigned int	valid_until;
	unsigned int	grace_period;
	char			tokens[256];
	char			user_data[256];
} auth_pubtkt;

typedef struct {
	request_rec *r;
	char *cookie;
	char *cookie_name;
} cookie_res;

/* An entry in the ticket cache.
   Note that while each entry has a hash (over the ticket string), this is
   not a hash table; managing a real hash table without fiddling with pointers
   (which could become a problem if the cache was ever converted to use
   shared memory) is rather difficult, and before we start optimizing the
   scan over ~200 integer hash values, getting rid of some strlen()s would
   probably make a bigger difference.
*/
typedef struct {
	unsigned int	hash;						/* hash over the unparsed ticket value (0 = slot available) */
	char			ticket[MAX_TICKET_SIZE+1];	/* the unparsed ticket value */
	auth_pubtkt		tkt;
} auth_pubtkt_cache_ent;

typedef struct {
	auth_pubtkt_cache_ent	slots[CACHE_SIZE];
	int						nextslot;
} auth_pubtkt_cache;

#ifdef APACHE13
void auth_pubtkt_init(server_rec *s, pool *p);
void auth_pubtkt_child_init(server_rec *s, pool *p);
#else
static int auth_pubtkt_init(apr_pool_t *p, apr_pool_t *plog, apr_pool_t *ptemp, server_rec *s);
static void auth_pubtkt_child_init(apr_pool_t *p, server_rec *s);
#endif

static void* create_auth_pubtkt_config(apr_pool_t *p, char* path);
static void* merge_auth_pubtkt_config(apr_pool_t *p, void* parent_dirv, void* subdirv);
static void *create_auth_pubtkt_serv_config(apr_pool_t *p, server_rec* s);
static void *merge_auth_pubtkt_serv_config(apr_pool_t *p, void* parent_dirv, void* subdirv);

static void cache_init(apr_pool_t *p, server_rec* s);
static int cache_get(const char* ticket, auth_pubtkt *tkt);
static void cache_put(const char *ticket, auth_pubtkt *tkt);
static unsigned int cache_hash(const char *ticket);

static const char *set_auth_pubtkt_token(cmd_parms *cmd, void *cfg, const char *param);
static const char *setup_pubkey(cmd_parms *cmd, void *cfg, const char *param);
static const char *set_auth_pubtkt_debug(cmd_parms *cmd, void *cfg, const char *param);

static int parse_ticket(request_rec *r, char *ticket, auth_pubtkt *tkt);
static int cookie_match(void *result, const char *key, const char *cookie);
static char *get_cookie_ticket(request_rec *r);
static auth_pubtkt* validate_parse_ticket(request_rec *r, char *ticket);
static int check_tokens(request_rec *r, auth_pubtkt *tkt);
static int check_clientip(request_rec *r, auth_pubtkt *tkt);
static int check_timeout(request_rec *r, auth_pubtkt *tkt);
static int check_grace_period(request_rec *r, auth_pubtkt *tkt);

static APR_INLINE unsigned char *c2x(unsigned what, unsigned char *where);
static char *escape_extras(apr_pool_t *p, const char *segment);

static int redirect(request_rec *r, char *location);

void dump_config(request_rec *r);

static int auth_pubtkt_check(request_rec *r);

#endif
