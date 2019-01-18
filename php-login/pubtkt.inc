<?php
/*
	Generate tickets for use with mod_auth_pubtkt
	(https://neon1.net/mod_auth_pubtkt)
	
	written by Manuel Kasper <mk@neon1.net>
*/

/* Set this to the path to your OpenSSL binary.
   This is usually something like /usr/bin/openssl on Unix-like systems.
   On Windows, you must manually get openssl.exe *and* the necessary libraries
   (usually libeay32.dll and ssleay32.dll) and put them together in a
   directory where they're accessible to PHP.
*/
define("OPENSSL_PATH", "/usr/bin/openssl");

/* Generate a ticket.
	
	Parameters:
		privkeyfile		path to private key file (PEM format)
		privkeytype		type of private key ("RSA" or "DSA")
		digest			digest algorithm ("default" is sha1 or dss1)
						also valid:  sha224, sha256, sha384, and sha512
		uid				user ID/username
		clientip		client IP address (optional; can be empty or null)
		validuntil		expiration timestamp (e.g. time() + 86400)
		tokens			comma-separated list of tokens (optional)
		udata			user data (optional)
		bauth			basic auth username:password (for passthru, optional;
						can optionally use pubtkt_encrypt_bauth() to encrypt it)
		multifactor             boolean (optional). Notes if multifactor authentication is present
	
	Returns:
		ticket string, or FALSE on failure
*/
function pubtkt_generate($privkeyfile, $privkeytype, $digest, $uid, $clientip, $validuntil, $graceperiod, $tokens, $udata, $bauth = null, $multifactor = false) {
	
	/* format ticket string */
	$tkt = "uid=$uid;";
	if ($clientip)
		$tkt .= "cip=$clientip;";
	$tkt .= "validuntil=$validuntil;";
	if ( isset($graceperiod) && is_numeric($graceperiod) && $graceperiod > 0 ) {
		$tkt .= "graceperiod=".($validuntil-$graceperiod).";";
	}
	if (!empty($bauth))
		$tkt .= "bauth=" . base64_encode($bauth) . ";";

        if ($multifactor) {
                $multifactor_int = 1;
        } else {
                $multifactor_int = 0;
        }
        $tkt .= "tokens=$tokens;udata=$udata;multifactor=$multifactor_int";
	
	if ($privkeytype == "DSA")
		$algoparam = "-dss1";
	else
		$algoparam = "-sha1";

	if ($digest != "default")
		$algoparam = "-" . $digest;
	
	$fd = @proc_open(OPENSSL_PATH . " dgst $algoparam -binary -sign " . escapeshellarg($privkeyfile),
		array(0 => array("pipe", "r"), 1 => array("pipe", "w")), $pipes);
	
	if (!is_resource($fd)) {
		echo "Cannot start openssl";
		return false;
	}
	
	fwrite($pipes[0], $tkt);
	fclose($pipes[0]);
	
	$sig = '';
	while (!feof($pipes[1]))
		$sig .= fread($pipes[1], 8192);
	fclose($pipes[1]);
	
	$res = proc_close($fd);
	
	if ($res != 0) {
		echo "openssl returned exit status $res";
		return false;
	}
	
	return $tkt . ";sig=" . base64_encode($sig);
}

/* Generate a ticket using php-only functions (only for RSA signature type)

    Parameters:
        privkey         private key as string (PEM format)
        uid             user ID/username
        clientip        client IP address (optional; can be empty or null)
        validuntil      expiration timestamp (e.g. time() + 86400)
        tokens          comma-separated list of tokens (optional)
        udata           user data (optional)
        bauth           basic auth username:password (for passthru, optional;
                        can optionally use pubtkt_encrypt_bauth() to encrypt it)

    Returns:
        ticket string, or FALSE on failure
*/
function pubtkt_generate_php($privkey, $uid, $clientip, $validuntil, $graceperiod, $tokens, $udata, $bauth = null) {
    /* format ticket string */
    $tkt = "uid=$uid;";
    if ($clientip)
        $tkt .= "cip=$clientip;";
    $tkt .= "validuntil=$validuntil;";
    if ( isset($graceperiod) && is_numeric($graceperiod) && $graceperiod > 0 ) {
        $tkt .= "graceperiod=".($validuntil-$graceperiod).";";
    }
    if (!empty($bauth))
        $tkt .= "bauth=" . base64_encode($bauth) . ";";
    $tkt .= "tokens=$tokens;udata=$udata";

    $pkeyid = openssl_get_privatekey($privkey);
    if($pkeyid === false)
        return false;
    $res = openssl_sign($tkt, $sig, $pkeyid);
    openssl_free_key($pkeyid);

    if(!$res)
        return false;

    return $tkt . ";sig=" . base64_encode($sig);
}

/*	Validate a ticket.
	
	Parameters:
		pubkeyfile		path to public key file (PEM format)
		pubkeytype		type of public key ("RSA" or "DSA")
		digest			digest algorithm ("default" is sha1 or dss1)
						also valid:  sha224, sha256, sha384, and sha512
		ticket			ticket string (including signature)
	
	Returns:
		ticket valid true/false
*/
function pubtkt_verify($pubkeyfile, $pubkeytype, $digest, $ticket) {
	/* strip off signature */
	$sigpos = strpos($ticket, ";sig=");
	if ($sigpos === false)
		return false;	/* no signature found */
	
	$ticketdata = substr($ticket, 0, $sigpos);
	$sigdata = base64_decode(substr($ticket, $sigpos + 5));
	
	if (!$sigdata)
		return false;
	
	/* write binary signature to temporary file */
	$tmpfn = tempnam("/tmp", "tktsig");
	$tmpfd = fopen($tmpfn, "wb");
	fwrite($tmpfd, $sigdata);
	fclose($tmpfd);
	
	if ($pubkeytype == "DSA")
		$algoparam = "-dss1";
	else
		$algoparam = "-sha1";

	if ($digest != "default")
		$algoparam = "-" . $digest;
	
	/* check DSA signature */
	$fd = proc_open(OPENSSL_PATH . " dgst $algoparam -verify " . escapeshellarg($pubkeyfile) . 
		" -signature " . escapeshellarg($tmpfn),
		array(0 => array("pipe", "r"), 1 => array("pipe", "w")), $pipes);
	
	fwrite($pipes[0], $ticketdata);
	fclose($pipes[0]);
	
	$res = trim(fgets($pipes[1]));
	fclose($pipes[1]);
	
	proc_close($fd);
	unlink($tmpfn);
	
	return ($res === "Verified OK");
}

/*  Validate a ticket using PHP only (only for RSA signature type)

    Parameters:
        pubkey          public key as string (PEM format)
        ticket          ticket string (including signature)

    Returns:
        ticket valid true/false
*/
function pubtkt_verify_php($pubkey, $ticket) {
    /* strip off signature */
    $sigpos = strpos($ticket, ";sig=");
    if ($sigpos === false)
        return false;   /* no signature found */

    $ticketdata = substr($ticket, 0, $sigpos);
    $sigdata = base64_decode(substr($ticket, $sigpos + 5));

    if (!$sigdata)
        return false;

    $ret = openssl_verify($ticketdata, $sigdata, $pubkey);

    if($ret === 1)
        return true;

    return false;
}

/*	Parse a ticket into its key/value pairs and return them as an
	associative array for easier use.
*/
function pubtkt_parse($ticket) {
	$tkt = array();
	$kvpairs = explode(";", $ticket);
	
	foreach ($kvpairs as $kvpair) {
		list($key,$val) = explode("=", $kvpair, 2);
		$tkt[$key] = $val;
	}
	
	return $tkt;
}

/*	Encrypt a "bauth" passthru basic authentication value
	(username:password) with the given key (must be exactly 16
	characters and match the key configured on the server). The
	result is in binary, but can be passed to pubtkt_generate()
	directly, as it will be Base64-encoded.
	Requires Mcrypt! */
function pubtkt_encrypt_bauth($bauth, $key) {
	if (strlen($key) != 16)
		return null;
	
	$td = mcrypt_module_open(MCRYPT_RIJNDAEL_128, '', MCRYPT_MODE_CBC, '');
	$iv = mcrypt_create_iv(mcrypt_enc_get_iv_size($td), MCRYPT_DEV_URANDOM);
	mcrypt_generic_init($td, $key, $iv);
	$encrypted = mcrypt_generic($td, $bauth);
	mcrypt_generic_deinit($td);
	mcrypt_module_close($td);

	return $iv . $encrypted;
}

/*  Decrypt a "bauth" passthru basic authentication value
 *  and return only the password with the given key (must be exactly 16
 *  characters). The input $bauth string should be binary,
 *  so it has to be decoded using base64_decode beforehand.
 *  Requires mcrypt!
 */
function pubtkt_decrypt_bauth($bauth, $key) {
    if (strlen($key) != 16)
        return null;

    $td = mcrypt_module_open(MCRYPT_RIJNDAEL_128, '', MCRYPT_MODE_CBC, '');
    $iv_s = mcrypt_enc_get_iv_size($td);
    $iv = substr($bauth, 0, $iv_s);
    $c_t = substr($bauth, $iv_s);

    mcrypt_generic_init($td, $key, $iv);
    $decrypted = mdecrypt_generic($td, $c_t);
    mcrypt_generic_deinit($td);
    mcrypt_module_close($td);

    $decrypted = trim($decrypted);
    $pass = substr($decrypted, strpos($decrypted, ':') + 1);
    return $pass;
}

?>
