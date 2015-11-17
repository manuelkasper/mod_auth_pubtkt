Summary: Ticket-based authorization module for the Apache HTTP Server
Name: mod_auth_pubtkt
Version: 0.9
Release: 0
License: Apache
Group: Applications/System
Source0: https://neon1.net/mod_auth_pubtkt/mod_auth_pubtkt-0.9.tar.gz
Source1: mod_auth_pubtkt.conf
URL: https://neon1.net/mod_auth_pubtkt/
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-buildroot
BuildRequires: httpd-devel, openssl-devel
Requires: httpd-mmn = %(cat %{_includedir}/httpd/.mmn || echo httpd-devel missing)
Requires: openssl

%description
Single sign-on module for Apache, based on mod_auth_tkt.

%prep
%setup -q

%build
./configure
make

%install
rm -rf %{buildroot}

mkdir -p %{buildroot}/%{_libdir}/httpd/modules
mkdir -p %{buildroot}/%{_sysconfdir}/httpd/conf.d

install -m 755 src/.libs/mod_auth_pubtkt.so %{buildroot}/%{_libdir}/httpd/modules
install -m 644 %{_sourcedir}/auth_pubtkt.conf %{buildroot}/%{_sysconfdir}/httpd/conf.d/

rm -f %{buildroot}/%{_libdir}/httpd/modules/{*.la,*.so.*}

%clean
rm -rf %{buildroot}

%files
%defattr(-,root,root,-)
%{_libdir}/httpd/modules/*.so
%config %{_sysconfdir}/httpd/conf.d/auth_pubtkt.conf

%changelog
* Wed Sep 09 2015 Manuel Kasper <mk@neon1.net> 0.9-0
- Updated to latest version of mod_auth_pubtkt [0.9]

* Tue Mar 26 2013 John Wittkoski <jwittkoski@gmail.com> 0.8-0
- Updated to latest version of mod_auth_pubtkt [0.8]

* Mon Jun 04 2012 Manuel Kasper <mk@neon1.net> 0.7-0
- Updated to latest version of mod_auth_pubtkt [0.7]

* Sat Sep 19 2009 Omachonu Ogali <oogali@currenex.com> 0.6-0
- Updated to latest version of mod_auth_pubtkt [0.6]

* Tue Sep 08 2009 Omachonu Ogali <oogali@currenex.com> 0.5-0
- Initial package creation
