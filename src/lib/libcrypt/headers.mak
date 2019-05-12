#
# License CC0 PUBLIC DOMAIN
#
# To the extent possible under law, Mark J. Olesen has waived all copyright 
# and related or neighboring rights to headers.mak file. This work is published 
# from: United States.
#

DESTDIR=../../../
LCRYPTO_SRC=.
INSTALL=install
BINOWN=0644
BINGRP=0644

HDRS=\
	${LCRYPTO_SRC}/aes/aes.h \
	${LCRYPTO_SRC}/asn1/asn1.h \
	${LCRYPTO_SRC}/asn1/asn1t.h \
	${LCRYPTO_SRC}/bf/blowfish.h \
	${LCRYPTO_SRC}/bio/bio.h \
	${LCRYPTO_SRC}/bn/bn.h \
	${LCRYPTO_SRC}/buffer/buffer.h \
	${LCRYPTO_SRC}/camellia/camellia.h \
	${LCRYPTO_SRC}/cast/cast.h \
	${LCRYPTO_SRC}/chacha/chacha.h \
	${LCRYPTO_SRC}/cmac/cmac.h \
	${LCRYPTO_SRC}/comp/comp.h \
	${LCRYPTO_SRC}/conf/conf.h \
	${LCRYPTO_SRC}/conf/conf_api.h \
	${LCRYPTO_SRC}/crypto.h \
	${LCRYPTO_SRC}/crv25519/crv25519.h \
	${LCRYPTO_SRC}/des/des.h \
	${LCRYPTO_SRC}/dh/dh.h \
	${LCRYPTO_SRC}/dsa/dsa.h \
	${LCRYPTO_SRC}/dso/dso.h \
	${LCRYPTO_SRC}/ec/ec.h \
	${LCRYPTO_SRC}/ecdh/ecdh.h \
	${LCRYPTO_SRC}/ecdsa/ecdsa.h \
	${LCRYPTO_SRC}/engine/engine.h \
	${LCRYPTO_SRC}/err/err.h \
	${LCRYPTO_SRC}/evp/evp.h \
	${LCRYPTO_SRC}/gost/gost.h \
	${LCRYPTO_SRC}/hkdf/hkdf.h \
	${LCRYPTO_SRC}/hmac/hmac.h \
	${LCRYPTO_SRC}/idea/idea.h \
	${LCRYPTO_SRC}/lhash/lhash.h \
	${LCRYPTO_SRC}/md4/md4.h \
	${LCRYPTO_SRC}/md5/md5.h \
	${LCRYPTO_SRC}/modes/modes.h \
	${LCRYPTO_SRC}/objects/objects.h \
	${LCRYPTO_SRC}/ocsp/ocsp.h \
	${LCRYPTO_SRC}/opnsslft.h \
	${LCRYPTO_SRC}/opensslv.h \
	${LCRYPTO_SRC}/ossl_typ.h \
	${LCRYPTO_SRC}/pem/pem.h \
	${LCRYPTO_SRC}/pem/pem2.h \
	${LCRYPTO_SRC}/pkcs12/pkcs12.h \
	${LCRYPTO_SRC}/pkcs7/pkcs7.h \
	${LCRYPTO_SRC}/poly1305/poly1305.h \
	${LCRYPTO_SRC}/rand/rand.h \
	${LCRYPTO_SRC}/rc2/rc2.h \
	${LCRYPTO_SRC}/rc4/rc4.h \
	${LCRYPTO_SRC}/ripemd/ripemd.h \
	${LCRYPTO_SRC}/rsa/rsa.h \
	${LCRYPTO_SRC}/sha/sha.h \
	${LCRYPTO_SRC}/sm3/sm3.h \
	${LCRYPTO_SRC}/sm4/sm4.h \
	${LCRYPTO_SRC}/stack/safestk.h \
	${LCRYPTO_SRC}/stack/stack.h \
	${LCRYPTO_SRC}/ts/ts.h \
	${LCRYPTO_SRC}/txt_db/txt_db.h \
	${LCRYPTO_SRC}/ui/ui.h \
	${LCRYPTO_SRC}/ui/uicompat.h \
	${LCRYPTO_SRC}/whrlpool/whrlpool.h \
	${LCRYPTO_SRC}/x509/x509.h \
	${LCRYPTO_SRC}/x509/x509_vfy.h \
	${LCRYPTO_SRC}/x509v3/x509v3.h

HDRS_GEN=\
	./arch/i386/sslcfg.h \
	./objects/obj_mac.h

includes:
	@test -d ${DESTDIR}/usr/include/openssl || \
	    mkdir ${DESTDIR}/usr/include/openssl
	@for i in $(HDRS); do \
	    j="cmp -s $$i ${DESTDIR}/usr/include/openssl/`basename $$i` || \
	    ${INSTALL} -m 444 $$i ${DESTDIR}/usr/include/openssl"; \
	    echo $$j; \
	    eval "$$j"; \
	done; \
	for i in $(HDRS_GEN); do \
	    j="cmp -s $$i ${DESTDIR}/usr/include/openssl/`basename $$i` || \
	    ${INSTALL} -m 444 $$i ${DESTDIR}/usr/include/openssl"; \
	    echo $$j; \
	    eval "$$j"; \
	done;
