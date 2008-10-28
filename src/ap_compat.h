/* Compatibility mappings from apache 2.0 api calls back to apache 1.3.x */
/* Derived from apr_compat.h and apu_compat.h */

#ifndef AP_COMPAT_H
#define AP_COMPAT_H

#define APR_INLINE ap_inline 
#define AP_MODULE_DECLARE_DATA MODULE_VAR_EXPORT
#define APR_OFFSETOF XtOffsetOf
#define APR_EGENERAL 0
#define APR_INADDR_NONE INADDR_NONE

/* Omit Apache2 status from ap_log_rerror, adding APLOG_NOERRNO instead */
#define ap_log_error(mark, level, status, ...) ap_log_error(mark, level | APLOG_NOERRNO, __VA_ARGS__)
#define ap_log_rerror(mark, level, status, ...) ap_log_rerror(mark, level | APLOG_NOERRNO, __VA_ARGS__)

#define apr_uri_default_port_for_scheme ap_default_port_for_scheme
#define apr_pool_t pool
#define apr_md5_ctx_t ap_md5_ctx_t 
#define apr_md5_encode ap_MD5Encode 
#define apr_md5_final ap_MD5Final 
#define apr_md5_init ap_MD5Init 
#define apr_md5_update ap_MD5Update 
#define apr_array_append ap_append_arrays 
#define apr_array_cat ap_array_cat 
#define apr_array_header_t array_header
#define apr_array_pstrcat ap_array_pstrcat 
#define apr_pool_free_blocks_num_bytes ap_bytes_in_free_blocks  
#define apr_pool_num_bytes ap_bytes_in_pool 
#define apr_check_file_time ap_check_file_time 
#define apr_filetype_e ap_filetype_e 
#define apr_pool_cleanup_for_exec ap_cleanup_for_exec 
#define apr_pool_clear ap_clear_pool 
#define apr_table_clear ap_clear_table 
#define apr_array_copy ap_copy_array 
#define apr_array_copy_hdr ap_copy_array_hdr 
#define apr_table_copy ap_copy_table 
#define apr_cpystrn ap_cpystrn 
#define apr_day_snames ap_day_snames 
#define apr_pool_destroy ap_destroy_pool 
#define apr_time_exp_t ap_exploded_time_t 
#define apr_fnmatch ap_fnmatch 
#define apr_getopt ap_getopt 
#define apr_inet_addr ap_inet_addr 
#define apr_pool_alloc_init ap_init_alloc 
#define apr_is_empty_table ap_is_empty_table 
#define apr_fnmatch_test ap_is_fnmatch 
#define apr_pool_cleanup_kill ap_kill_cleanup 
#define apr_array_make ap_make_array 
#define apr_pool_sub_make ap_make_sub_pool 
#define apr_table_make ap_make_table 
#define apr_month_snames ap_month_snames 
#define apr_pool_note_subprocess ap_note_subprocess 
#define apr_pool_cleanup_null ap_null_cleanup 
#define apr_filepath_merge ap_os_canonical_filename 
/* #define apr_filepath_merge ap_os_case_canonical_filename  */
#define apr_dso_load ap_os_dso_load 
#define apr_dso_unload ap_os_dso_unload 
#define apr_dso_sym ap_os_dso_sym 
#define apr_dso_error ap_os_dso_error 
/** @deprecated @see apr_filepath_merge
 *  @warning apr_filepath_merge rejects invalid filenames */
/* #define ap_os_is_filename_valid apr_filepath_merge */
#define apr_proc_kill ap_os_kill 
/* #define ap_os_systemcase_canonical_filename apr_filepath_merge */
#define apr_table_overlap ap_overlap_tables 
#define apr_table_overlay ap_overlay_tables 
#define apr_palloc ap_palloc 
#define apr_pcalloc ap_pcalloc 
#define apr_pool_join ap_pool_join 
#define apr_psprintf ap_psprintf 
#define apr_pstrcat ap_pstrcat 
#define apr_pstrdup ap_pstrdup 
#define apr_pstrndup ap_pstrndup 
#define apr_array_push ap_push_array 
#define apr_pvsprintf ap_pvsprintf 
#define apr_pool_cleanup_register ap_register_cleanup 
#define apr_proc_other_child_register ap_register_other_child 
#define apr_pool_cleanup_run ap_run_cleanup 
#define apr_signal ap_signal 
#define apr_snprintf ap_snprintf 
#define apr_table_add ap_table_add 
#define apr_table_addn ap_table_addn 
#define apr_table_do ap_table_do 
#define apr_table_elts ap_table_elts 
#define apr_table_get ap_table_get 
#define apr_table_merge ap_table_merge 
#define apr_table_mergen ap_table_mergen 
#define apr_table_set ap_table_set 
#define apr_table_setn ap_table_setn 
#define apr_table_unset ap_table_unset 
#define apr_proc_other_child_unregister ap_unregister_other_child 
#define apr_password_validate ap_validate_password 
#define apr_vformatter ap_vformatter 
#define apr_vsnprintf ap_vsnprintf 
#define apr_wait_t ap_wait_t 

#define apr_isalnum ap_isalnum 
#define apr_isalpha ap_isalpha 
#define apr_iscntrl ap_iscntrl 
#define apr_isdigit ap_isdigit 
#define apr_isgraph ap_isgraph 
#define apr_islower ap_islower 
#define apr_isascii ap_isascii 
#define apr_isprint ap_isprint 
#define apr_ispunct ap_ispunct 
#define apr_isspace ap_isspace 
#define apr_isupper ap_isupper 
#define apr_isxdigit ap_isxdigit 
#define apr_tolower ap_tolower 
#define apr_toupper ap_toupper 

#define APR_USEC_PER_SEC AP_USEC_PER_SEC 
#define APR_RFC822_DATE_LEN AP_RFC822_DATE_LEN 
#define APR_OVERLAP_TABLES_MERGE AP_OVERLAP_TABLES_MERGE 
#define APR_OVERLAP_TABLES_SET AP_OVERLAP_TABLES_SET 

#define apr_base64_decode ap_base64decode 
#define apr_base64_decode_binary ap_base64decode_binary 
#define apr_base64_decode_len ap_base64decode_len 
#define apr_base64_encode ap_base64encode 
#define apr_base64_encode_binary ap_base64encode_binary 
#define apr_base64_encode_len ap_base64encode_len 
#define apr_hook_deregister_all ap_hook_deregister_all 
#define apr_hook_sort_register ap_hook_sort_register 
#define apr_hook_debug_show ap_show_hook 

/* --------------------------------------------------------------------
 * the following symbols were moved from httpd-2.0/.../util_date.[ch]
 */
#define apr_date_parse_http ap_parseHTTPdate 
#define apr_date_checkmask ap_checkmask 

/* --------------------------------------------------------------------
 * the following symbols were moved from httpd-2.0/.../util_xml.[ch]
 */
#define ap_text apr_text
#define ap_text_header apr_text_header
#define ap_text_append apr_text_append

#define AP_XML_NS_DAV_ID APR_XML_NS_DAV_ID
#define AP_XML_NS_NONE APR_XML_NS_NONE
#define AP_XML_NS_ERROR_BASE APR_XML_NS_ERROR_BASE
#define AP_XML_NS_IS_ERROR(e) APR_XML_NS_IS_ERROR(e)
#define AP_XML_ELEM_IS_EMPTY(e) APR_XML_ELEM_IS_EMPTY(e)

#define ap_xml_attr apr_xml_attr
#define ap_xml_elem apr_xml_elem
#define ap_xml_doc apr_xml_doc

#define ap_xml_to_text apr_xml_to_text
#define AP_XML_X2T_FULL APR_XML_X2T_FULL
#define AP_XML_X2T_INNER APR_XML_X2T_INNER
#define AP_XML_X2T_LANG_INNER APR_XML_X2T_LANG_INNER
#define AP_XML_X2T_FULL_NS_LANG APR_XML_X2T_FULL_NS_LANG

#define ap_xml_empty_elem apr_xml_empty_elem
#define ap_xml_quote_string apr_xml_quote_string
#define ap_xml_quote_elem apr_xml_quote_elem
#define ap_xml_insert_uri apr_xml_insert_uri
#define AP_XML_GET_URI_ITEM(a,i) APR_XML_GET_URI_ITEM(a,i)

/* From Apache2 httpd.h */
# define ap_strchr(s, c)        strchr(s, c)

/* From Apache2 http_config.h */
# define AP_INIT_NO_ARGS(directive, func, mconfig, where, help) \
    { directive, func, mconfig, where, RAW_ARGS, help }
# define AP_INIT_RAW_ARGS(directive, func, mconfig, where, help) \
    { directive, func, mconfig, where, RAW_ARGS, help }
# define AP_INIT_TAKE1(directive, func, mconfig, where, help) \
    { directive, func, mconfig, where, TAKE1, help }
# define AP_INIT_ITERATE(directive, func, mconfig, where, help) \
    { directive, func, mconfig, where, ITERATE, help }
# define AP_INIT_TAKE2(directive, func, mconfig, where, help) \
    { directive, func, mconfig, where, TAKE2, help }
# define AP_INIT_TAKE12(directive, func, mconfig, where, help) \
    { directive, func, mconfig, where, TAKE12, help }
# define AP_INIT_ITERATE2(directive, func, mconfig, where, help) \
    { directive, func, mconfig, where, ITERATE2, help }
# define AP_INIT_TAKE13(directive, func, mconfig, where, help) \
    { directive, func, mconfig, where, TAKE13, help }
# define AP_INIT_TAKE23(directive, func, mconfig, where, help) \
    { directive, func, mconfig, where, TAKE23, help }
# define AP_INIT_TAKE123(directive, func, mconfig, where, help) \
    { directive, func, mconfig, where, TAKE123, help }
# define AP_INIT_TAKE3(directive, func, mconfig, where, help) \
    { directive, func, mconfig, where, TAKE3, help }
# define AP_INIT_FLAG(directive, func, mconfig, where, help) \
    { directive, func, mconfig, where, FLAG, help }

/* use strtok_r instead of apr_strtok */
#define apr_strtok strtok_r

/* Apache 1.3 doesn't have ap_unescape_url_keep2f */
static char x2c(const char *what)
{
    register char digit;

    digit = ((what[0] >= 'A') ? ((what[0] & 0xdf) - 'A') + 10 : (what[0] - '0'));
    digit *= 16;
    digit += (what[1] >= 'A' ? ((what[1] & 0xdf) - 'A') + 10 : (what[1] - '0'));
    return (digit);
}

static int ap_unescape_url_keep2f(char *url)
{
    register int badesc, badpath;
    char *x, *y;

    badesc = 0;
    badpath = 0;
    /* Initial scan for first '%'. Don't bother writing values before
     * seeing a '%' */
    y = strchr(url, '%');
    if (y == NULL) {
        return OK;
    }
    for (x = y; *y; ++x, ++y) {
        if (*y != '%') {
            *x = *y;
        }
        else {
            if (!apr_isxdigit(*(y + 1)) || !apr_isxdigit(*(y + 2))) {
                badesc = 1;
                *x = '%';
            }
            else {
                char decoded;
                decoded = x2c(y + 1);
                if (decoded == '\0') {
                    badpath = 1;
                }
                else {
                    *x = decoded;
                    y += 2;
                }
            }
        }
    }
    *x = '\0';
    if (badesc) {
        return HTTP_BAD_REQUEST;
    }
    else if (badpath) {
        return HTTP_NOT_FOUND;
    }
    else {
        return OK;
    }
}

#endif /* AP_COMPAT_H */
