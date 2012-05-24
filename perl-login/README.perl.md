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



Login Page Example
------------------

See ./perl-login/minimal-cgi/login.pl for a bare-bones CGI login script.
use "gordon" and password "12345" to test the login mechanism.

A reasonable Apache configuration for the login server would be:
    ```
    <VirtualHost *:443>
        ServerName sso.mydomain.com

        DocumentRoot /path/to/mod_auth_pubtkt/perl-login/minimal_cgi
        <Directory /path/to/mod_auth_pubtkt/perl-login/minimal_cgi>
            Order Allow,Deny
            Allow from all
            Options +ExecCGI
            DirectoryIndex login.pl
            AddHandler cgi-script .pl
        </Directory>
    </VirtualHost>
    ```


And a corresponding Handler's apache configuration would be:

    ```
    <VirtualHost *:80>
        ServerName myserver.mydomain.com
        DocumentRoot /path/to/my/htdocs
        
        TKTAuthPublicKey /path/to/mod_auth/pubtkt/perl-login/key.pub.pem
        
        <Directory /path/to/my/htdocs>
        Order Allow,Deny
        Allow from all
        
        AuthType mod_auth_pubtkt
        TKTAuthLoginURL https://sso.mydomain.com/login.pl
        TKTAuthTimeoutURL https://sso.mydomain.com/login.pl?timeout=1
        TKTAuthUnauthURL https://sso.mydomain.com/login.pl?unauth=1
        require valid-user
        </Directory>
    </VirtualHost>
    ```

To try out this minimal CGI, you'll need to update the configuration paramters (e.g. domain name) in `login.pl`.
