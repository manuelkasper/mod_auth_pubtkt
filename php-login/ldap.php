<?php
function ldap_auth($user, $password) {
	global $default_timeout, $default_graceperiod, $default_token;

	$out['success'] = false;
	if(empty($user) || empty($password)) return $out;

	// your ldap server 
	$ldap_host = "ldap.{DOMAIN}.{TLD}"

	// (base location of ldap search) - Zimbra, (Generic OpenLDAP ?)
	$ldap_dn = "ou=people,dc={DOMAIN},dc={TLD}";

	// connect to LDAP host
	$ldap = ldap_connect($ldap_host);
	
	// Don't do things over plain text.
	ldap_start_tls($ldap);

	// configure ldap params
	ldap_set_option($ldap,LDAP_OPT_PROTOCOL_VERSION,3);
	ldap_set_option($ldap,LDAP_OPT_REFERRALS,0);

	// Doing authentication base on the success of the BIND to LDAP.
	// A vaild, but doesn't feel like the best way
	if ( $ldap ) {
		// UID is what Zimbra uses for the username.  You may need to change this.
		$bind = ldap_bind($ldap, "uid=$user,$ldap_dn", $password);
		if ($bind) {
			$out['success'] = TRUE;
			$out['tokens']  = array ( $default_token ) ;
			$out['timeout'] = $default_timeout;
			$out['graceperiod'] = $default_graceperiod;
		}
	}
	// some debug information that would to the apache error log.
	// error_log ( " ==> user_out_info:  " . json_encode($out) );

	return $out;
}
?>
