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
		uid				user ID/username
		clientip		client IP address (optional; can be empty or null)
		validuntil		expiration timestamp (e.g. time() + 86400)
		tokens			comma-separated list of tokens (optional)
		udata			user data (optional)
	
	Returns:
		ticket string, or FALSE on failure
*/
function pubtkt_generate($privkeyfile, $privkeytype, $uid, $clientip, $validuntil, $graceperiod, $tokens, $udata) {
	
	/* format ticket string */
	$tkt = "uid=$uid;";
	if ($clientip)
		$tkt .= "cip=$clientip;";
	$tkt .= "validuntil=$validuntil;";
	if ( isset($graceperiod) && is_numeric($graceperiod) && $graceperiod > 0 ) {
		$tkt .= "graceperiod=".($validuntil-$graceperiod).";";
	}
	$tkt .= "tokens=$tokens;udata=$udata";
	
	if ($privkeytype == "DSA")
		$algoparam = "-dss1";
	else
		$algoparam = "-sha1";
	
	$fd = @proc_open(OPENSSL_PATH . " dgst $algoparam -binary -sign " . escapeshellarg($privkeyfile),
		array(0 => array("pipe", "r"), 1 => array("pipe", "w")), $pipes);
	
	if (!is_resource($fd)) {
		echo "Cannot start openssl";
		return false;
	}
	
	fwrite($pipes[0], $tkt);
	fclose($pipes[0]);
	
	$sig = fread($pipes[1], 8192);
	fclose($pipes[1]);
	
	$res = proc_close($fd);
	
	if ($res != 0) {
		echo "openssl returned exit status $res";
		return false;
	}
	
	return $tkt . ";sig=" . base64_encode($sig);
}

/*	Validate a ticket.
	
	Parameters:
		pubkeyfile		path to public key file (PEM format)
		pubkeytype		type of public key ("RSA" or "DSA")
		ticket			ticket string (including signature)
	
	Returns:
		ticket valid true/false
*/
function pubtkt_verify($pubkeyfile, $pubkeytype, $ticket) {
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

?>
