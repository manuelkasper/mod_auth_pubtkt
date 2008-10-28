/* Compatibility mappings from apache 2.0 api calls to apache 2.2 */

#ifndef AP22_COMPAT_H
#define AP22_COMPAT_H

#define ap_http_method ap_http_scheme
#define apr_uri_default_port_for_scheme apr_uri_port_of_scheme

#endif /* AP22_COMPAT_H */

