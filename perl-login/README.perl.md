Perl wrapper for mod_auth_pubtkt
================================

Prerequisites
-------------

1. Perl's IPC::Run3" module. Running:
     $ sudo cpan IPC::Run3
   should "just work".

2. Generate a pair of private+public keys, as explained here:
   https://neon1.net/mod_auth_pubtkt/install.html

   Running the following commands should work:
     # Genereate a private RSA key
     $ openssl genrsa -out key.priv.pem 1024
     # Geenrate a public RSA key
     $ openssl rsa -in key.priv.pem -out key.pub.pem -pubout


Module Usage Example
--------------------

See the 'test_pubtkt.pl' script for a complete generate ticket + verify ticket example.

run `perldoc mod_auth_pubtkt.pm` for more details.
