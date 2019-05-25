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
	tls.h

includes:
	@test -d ${DESTDIR}/usr/include/ || \
	    mkdir ${DESTDIR}/usr/include/
	@for i in $(HDRS); do \
	    j="cmp -s $$i ${DESTDIR}/usr/include/`basename $$i` || \
	    ${INSTALL} -m 444 $$i ${DESTDIR}/usr/include/"; \
	    echo $$j; \
	    eval "$$j"; \
	done;
