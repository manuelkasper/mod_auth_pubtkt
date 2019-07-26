#!/bin/bash

set -e
set +x

MOD=mod_auth_pubtkt
VERSION=0.13

# nuke rubbish we don't want
find . -type f -name Makefile -delete
rm -f configure

autoreconf -vfi
./configure
make

if [[ $1 =~ "rpm" ]] ; then
    if [[ -e "$MOD.spec" ]] ; then
        mydir=`dirname $0`
        tmpdir=`mktemp -d`
        
        # sanity check
        if [ -z "$tmpdir" ] ; then
            echo "Error creating tmpdir"
            exit 1
        fi

        set +x

        cp -r "${mydir}" "${tmpdir}/${MOD}-${VERSION}"
        tar -czf "${tmpdir}/${MOD}-${VERSION}.tar.gz" --exclude=".git" -C "${tmpdir}" "${MOD}-${VERSION}"
        rpmbuild -ta "${tmpdir}/${MOD}-${VERSION}.tar.gz"
        rm -rf "${tmpdir}"
    else
        echo "Missing RPM spec file"
        exit 1
    fi
fi
