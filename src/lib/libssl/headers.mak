#
# License CC0 PUBLIC DOMAIN
#
# To the extent possible under law, Mark J. Olesen has waived all copyright 
# and related or neighboring rights to headers.mak file. This work is published 
# from: United States.
#

DESTDIR=../../../
INSTALL=install
BINOWN=0644
BINGRP=0644

HDRS=\
	dtls1.h \
	srtp.h \
	ssl.h \
	ssl2.h \
	ssl23.h \
	ssl3.h \
	tls1.h

includes:
	@test -d ${DESTDIR}/usr/include/openssl || \
	    mkdir ${DESTDIR}/usr/include/openssl
	@for i in $(HDRS); do \
	    j="cmp -s $$i ${DESTDIR}/usr/include/openssl/`basename $$i` || \
	    ${INSTALL} -m 444 $$i ${DESTDIR}/usr/include/openssl"; \
	    echo $$j; \
	    eval "$$j"; \
	done;
