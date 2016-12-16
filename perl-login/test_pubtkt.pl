#!/usr/bin/env perl
=pod
 Perl implementation of mod_auth_pubtkt  ticket generateion.

 see https://neon1.net/mod_auth_pubtkt/ for more details.

 Copyright (C) 2012 A. Gordon ( gordon at cshl dot edu )

 LICENSE: Apacle License (see LICENSE file)

 See README.perl.md file for more details.
=cut
use strict;
use warnings;
use mod_auth_pubtkt;

##
## Generate a ticket
##
my $ticket = pubtkt_generate(
		privatekey => "key.priv.pem",
		keytype    => "rsa",
		digest     => undef,
		clientip   => undef,
		userid     => "102",
		validuntil => time() + 86400,
		graceperiod=> 3600,
		tokens     => undef,
		userdata   => undef);

print $ticket,"\n";
##
## Verify the same ticket
##
my $ok = pubtkt_verify (
		publickey => "key.pub.pem",
		keytype   => "rsa",
		digest    => undef,
		ticket    => $ticket
	);
die "Ticket verification failed.\n" if not $ok;

##
## Change something in the ticket, then verify again (which should fail)
##
$ticket =~ s/uid=102/uid=103/;

$ok = pubtkt_verify (
		publickey => "key.pub.pem",
		keytype   => "rsa",
		digest    => undef,
		ticket    => $ticket
	);

die "Error: forged ticket verified successfully, something is terribly wrong." if $ok;

print "all ok\n";
