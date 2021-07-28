#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([mod_auth_pubtkt],[0.14],[https://github.com/manuelkasper/mod_auth_pubtkt]) 
AC_CONFIG_AUX_DIR([.])
AM_INIT_AUTOMAKE([-Wall -Werror foreign])

AC_CONFIG_SRCDIR([src/ap_compat.h])
AC_CONFIG_HEADERS([src/config.h])

# Checks for programs.
AC_PROG_CC

# Checks for libraries.
if test -z "${APXS}"; then
    AC_PATH_PROGS(APXS, apxs2 apxs, no, [$PATH:/usr/sbin:/usr/local/apache2/bin])
fi
if test "$APXS" = no; then
    AC_MSG_ERROR([apxs not found: install it or provide the path --with-apxs])
fi
AC_SUBST(APXS)

if test x$CRYPTO = x; then
    AC_CHECK_LIB([crypto], [EVP_md5], [CRYPTO="crypto"])
fi

if test x$CRYPTO != x; then
    AC_DEFINE(HAVE_LIBCRYPTO, 1,
        [Define to 1 if you have the OpenSSL library (-lcrypto or -leay32).])
    LIBCRYPTO="-l${CRYPTO}"

    AC_CHECK_LIB(${CRYPTO}, EVP_MD_CTX_create,
        AC_DEFINE([HAVE_EVP_MD_CTX_CREATE], [],
            [Define to 1 if you have the 'EVP_MD_CTX_create' function.])
        AC_DEFINE([HAVE_EVP_MD_CTX_DESTROY], [],
            [Define to 1 if you have the 'EVP_MD_CTX_destroy' function.]))
    AC_CHECK_LIB(${CRYPTO}, EVP_MD_CTX_new,
        AC_DEFINE([HAVE_EVP_MD_CTX_NEW], [],
            [Define to 1 if you have the 'EVP_MD_CTX_new' function.])
        AC_DEFINE([HAVE_EVP_MD_CTX_FREE], [],
            [Define to 1 if you have the 'EVP_MD_CTX_free' function.]))

fi

# Checks for header files.
AC_CHECK_HEADERS([arpa/inet.h limits.h netinet/in.h string.h httpd.h ap_release.h])

dnl Update CFLAGS to add httpd includes
AP_INCLUDES="-I`${APXS} -q INCLUDEDIR`"
CFLAGS="$CFLAGS $AP_INCLUDES"

dnl Check the signature of ap_unescape_url_keep2f()
AC_LINK_IFELSE([AC_LANG_PROGRAM([[#include <httpd.h>
            ]], [[int (f) (char *url, int decode_slashes) = ap_unescape_url_keep2f;]])],[AC_DEFINE(APACHE_UNESCAPE_HAS_LONG_ARGS, 1,
                       Define to 1 if ap_unescape_url_keep2f() takes 2 arguments)],[])

AC_MSG_CHECKING([Apache version])
AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
    #include <ap_release.h>
]], [[
    char *version = AP_SERVER_BASEREVISION;
]])],[
    APACHE_VER=2.0
],[
    APACHE_VER=1.3
])

if test "$APACHE_VER" = "1.3" ; then
    APACHE_VER=1.3
else
    AC_MSG_CHECKING([whether we are on Apache 2.2.x])
    AC_RUN_IFELSE([AC_LANG_PROGRAM([[#include <ap_release.h>]], [[
        int main ()
        {
            return (AP_SERVER_MAJORVERSION_NUMBER == 2 && AP_SERVER_MINORVERSION_NUMBER == 2) ? 0 : 1;
        }
        ]])]
        ,[
            AC_MSG_RESULT([yes])
            APACHE_VER=2.2
        ],[
            AC_MSG_RESULT([no])
        ]
    )

    AC_MSG_CHECKING([whether we are on Apache 2.4.x])
    AC_RUN_IFELSE([AC_LANG_PROGRAM([[#include <ap_release.h>]], [[
        int main ()
        {
            return (AP_SERVER_MAJORVERSION_NUMBER == 2 && AP_SERVER_MINORVERSION_NUMBER == 4) ? 0 : 1;
        }
        ]])]
        ,[
            AC_MSG_RESULT([yes])
            APACHE_VER=2.4
        ],[
            AC_MSG_RESULT([no])
        ]
    )
fi

if test ! "$APACHE_VER" = "1.3" -a ! "$APACHE_VER" = "retry" ; then
    AC_MSG_RESULT(${APACHE_VER})
fi

if test "$APACHE_VER" = "1.3"; then
    AC_DEFINE(APACHE13, [],
        [Compiling for Apache 1.3])
fi

AC_DEFINE([APACHE2],[],[Compiling for Apache >= 2.0 ])

if test "$APACHE_VER" = "2.2" ; then
    CFLAGS="${CFLAGS} -DAPACHE22"
    AC_DEFINE(APACHE22, [],
        [Compiling for Apache >= 2.2 ])
fi
if test "$APACHE_VER" = "2.4" ; then
    CFLAGS="${CFLAGS} -DAPACHE24"
    AC_DEFINE([APACHE24], [1],
        [Compiling for Apache >= 2.4 ])
fi

AC_MSG_NOTICE([Got Apache version $APACHE_VER])

dnl End trying to figure out Apache version

dnl Very helpful. Nicked from:
dnl https://github.com/maxmind/mod_maxminddb/blob/master/configure.ac
AC_DEFUN([AX_CHECK_CFLAGS],
[
    AC_MSG_CHECKING([whether compiler accepts "$1"])
    cat > conftest.c << EOF
    int main(){
        return 0;
    }
EOF
    if $CC $CFLAGS -o conftest.o conftest.c [$1] > /dev/null 2>&1
    then
        AC_MSG_RESULT([yes])
        CFLAGS="${CFLAGS} [$1]"
        [$2]
    else
        AC_MSG_RESULT([no])
        [$3]
    fi
])dnl AX_CHECK_CFLAGS

AX_CHECK_CFLAGS([-std=c99 -fms-extensions])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_SIZE_T

# Checks for library functions.
AC_CHECK_FUNCS([strcasecmp strchr strstr])

AC_CONFIG_FILES([Makefile
                 src/Makefile])
AC_OUTPUT
