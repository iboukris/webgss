#!/bin/bash
set -e

trap 'end $?' EXIT
end() {
    if [ "$KDCPROC" != "0" ]; then
        kill $KDCPROC
    fi
    if [ "$SRVPROC" != "0" ]; then
        kill $SRVPROC
    fi
    exit $1
}

trap 'err $? $LINENO' ERR
err() {
    echo "Error $1 occurred at line $2"
    exit $1
}

TESTDIR=`realpath testdir_wgss`
KRB5_CONFIG=${TESTDIR}/krb5.conf
KRB5_KTNAME=${TESTDIR}/server.kt
KRB5_TRACE=${TESTDIR}/krb5_trace
KDCPROXY_CONFIG=${TESTDIR}/kproxy.conf

export KRB5_CONFIG KRB5_KTNAME KRB5_TRACE

KDCPROC=0
SRVPROC=0
HTTPDPORT=9999
KDCPORT=8888
KRB5REALM=WGSS.TEST
HOSTNAME=localhost
KSERVICE=HTTP/$HOSTNAME
KUSER=kuser
KUPWD=kuserpwd

rm -rf $TESTDIR && mkdir $TESTDIR

sed -e "s/_TEST_REALM_/$KRB5REALM/g" \
    -e "s/_TEST_HOSTNAME_/$HOSTNAME/g" \
    -e "s/_TEST_KDC_PORT_/$KDCPORT/g" \
    -e "s|_TEST_DIR_|$TESTDIR|g" \
    t_krb5.conf > $KRB5_CONFIG

kdb5_util create -W -r $KRB5REALM -s -P kdcpwd

kadmin.local -q "addprinc -randkey $KSERVICE"

kadmin.local -q "ktadd -k $KRB5_KTNAME $KSERVICE"

kadmin.local -q "addprinc -pw $KUPWD $KUSER"


krb5kdc -n > ${TESTDIR}/kdc_out 2>&1 &
KDCPROC=$!

printf "[global]\nconfigs = mit" > $KDCPROXY_CONFIG

export KUSER KUPWD KRB5REALM HOSTNAME HTTPDPORT KDCPROXY_CONFIG

python3 ./wsgi-server.py $HOSTNAME $HTTPDPORT &
SRVPROC=$!

sleep 1

node --trace-uncaught --trace-warnings node_test.js > ${TESTDIR}/out

grep "Hello $KUSER@$KRB5REALM" ${TESTDIR}/out

echo "TEST OK"
