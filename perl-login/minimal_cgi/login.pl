#!/usr/bin/env perl
use strict;
use warnings;
use FindBin;
use lib "$FindBin::Bin/../";
use mod_auth_pubtkt;
use CGI qw(:standard  :cgi-lib);
use CGI::Carp qw/fatalsToBrowser/;
use URI::Escape;
use Data::Dump qw/dump/;
$CGI::POST_MAX=1024 * 10;  # max 10K posts
$CGI::DISABLE_UPLOADS = 1;  # no uploads

sub show_login_page;
sub show_post_page;
sub post_successful_login;
sub validate_login;

##
## Configuration parameters.
## These must match the corresponding "mod_auth_pubtkt" settings on every apache handler server.
##
my $mod_auth_pubtkt_cookie = "auth_pubtkt"; # mod_auth_pubtkt's TKTAuthCookieName setting.
my $mod_auth_cookie_domain = ".cshl.edu"; # the domain for which this cookie is valid.
my $tokens = ""; # mod_auth_pubtkt's TKTAuthToken setting. This default implementation doesn't send any tokens.
my $user_data = "" ; # This default implementation doesn't send any user-data.
my $valid_until_delta = 86400 ; # Valid for one day
my $grace_period = 3600 ; # Grace period of one hour
my $use_client_ip = 1 ; # should the ticket/cookie contain the client's IP address?

## TODO: DO NOT USE THESE keys in a production settings.
##       These are just for debugging/testing.
my $key_type = "rsa";
my $public_key = "$FindBin::Bin/../key.pub.pem";
my $private_key = "$FindBin::Bin/../key.priv.pem";


=head1 Technical note

=head2 This login script can be invoked in one of several ways:

=over 2

=item C<GET> request, with possibly a C<back>, C<timeout>, C<unauth> CGI parameters.

foo bar

=item C<GET> request, with a C<auth_pubtkt> cookie, (and possibly C<back>, C<unauth>, C<timeout> CGI parameters) 

foo bar

=item C<POST> request, with a possible C<back> CGI GET paramter, and C<username> and C<password> POST CGI parameters.

foo bar

=back

=cut

###########################################################
## CGI Script Starts here
###########################################################
if (request_method() eq "GET") {
	show_login_page();
}
elsif (request_method() eq "POST") {
	## User tried to login, verify username/password, and issue a ticket.
	if (validate_login()) {
		post_successful_login();
	} else {
		show_login_page("Login failed. Please try again");
	}
} else {
	## We don't susport anything else other than GET/POST. no HEAD, PUT, DELETE, etc.
	die "What's going on? unknown request method: " . request_method() ;
}
###########################################################
## CGI Script End
###########################################################


sub show_login_page
{
	my $message = shift || "";

	my $back = url_param('back') || "";
	if ($back) {
		$back = "back=" .uri_escape($back);
	}

	print header(); # HTTP header, back to apache
	#The simplest login HTML <form> page
	print <<HTML;
<html>
<head>
</head>
<body>
<form action="?$back" method="post">
<center>
<table>
	<tr>
		<td colspan="2"><h1>Login</h1></td>
	</tr>
	<tr>
		<td colspan="2"><h2>$message</h2></td>
	</tr>
	<tr>
		<td><b>Name:</b></td>
		<td><input type="text" name="username" value=""/></td>
	</tr>
	<tr>
		<td><b>Password:</b></td>
		<td><input type="password" name="password" value=""/></td>
	</tr>
	<tr>
		<td colspan="2"><input type="submit" name="login" value="login"/></td>
	</tr>
</table>
</center>
</form>
</body>
</html>
HTML
}

=pod
  Get the username/password from the POST parameters, try to authenticate the user.

  return FALSE on any failure, or TRUE if login was successful.

  TODO:
    Implement it in which every way you want (DB, LDAP, PAM, Text file, etc.)
=cut
sub validate_login
{
	my $username = param("username") || "";
	my $password = param("password") || "";

	# This seems pretty much bullet-proof secure :)
	return ( $username eq "gordon" && $password eq "12345" );
}

=pod
  Generate the cookie, with the signed ticket,
  and all other parameters.	
=cut
sub generate_pubtkt_cookie
{
	my ($user_id) = shift or croak "Error: missing user_id parameter.";

	my $ticket = pubtkt_generate(
			privatekey => $private_key,
			keytype    => $key_type,
			clientip   => ($use_client_ip) ? remote_addr() : undef,
			userid     => $user_id,
			validuntil => time() + $valid_until_delta,
			graceperiod=> $grace_period,
			tokens     => $tokens,
			userdata   => $user_data);

	my $cookie = cookie(-name  => $mod_auth_pubtkt_cookie,
			    -value => $ticket,
			    -domain=> $mod_auth_cookie_domain,
			    -path  => "/");

	return $cookie;
}

=pod
 What to do after the user successfully logged on?
 (either by entering username/password, or by renewing a grace-period)

 1. Set a new mod_auth_pubtkt cookie
 2. If there's a "back" CGI parameter, redirect the user there.
 3. If there's no "back", show something else.
=cut
sub post_successful_login
{
	my $cookie = generate_pubtkt_cookie(param("username"));

	my $back = url_param('back') || "" ;
	if ($back) {
		## Send the user back were he/she came from, this time with a cookie
		print redirect( -url => $back, -cookie => $cookie );
		exit(0);
	}

	##
	## Don't knwo where the user came from, show some generic message (and set the cookie).
	## possibly show "portal" - a list of other services using this ticket authentication system.
	##
	print header(-cookie => $cookie); # HTTP header, back to apache
	print <<HTML;
<html>
<head>
</head>
<body>
<center>
<h1>Good, now go away</h1>
</center>
</body>
</html>
HTML
}
