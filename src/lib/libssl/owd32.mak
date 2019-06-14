#
# License CC0 PUBLIC DOMAIN
#
# To the extent possible under law, Mark J. Olesen has waived all copyright 
# and related or neighboring rights to owd32.mak file. This work is published 
# from: United States.
#

ROOT=..\..\..\

OBJ=obj
LIB=$(ROOT)\usr\lib

DEFINES= -DLIBRESSL_INTERNAL -DOPENSSL_NO_DEPRECATED
INCLUDES= -i$(ROOT)\usr\include 

CC=wcc386
CFLAGS=-3r -mf -bt=DOS $(DEFINES) $(INCLUDES)

LIBSSL_OBJS=&
	$(OBJ)\bio_ssl.obj &
	$(OBJ)\bs_ber.obj &
	$(OBJ)\bs_cbb.obj &
	$(OBJ)\bs_cbs.obj &
	$(OBJ)\d1_both.obj &
	$(OBJ)\d1_clnt.obj &
	$(OBJ)\d1_enc.obj &
	$(OBJ)\d1_lib.obj &
	$(OBJ)\d1_pkt.obj &
	$(OBJ)\d1_srtp.obj &
	$(OBJ)\d1_srvr.obj &
	$(OBJ)\pqueue.obj &
	$(OBJ)\s3_cbc.obj &
	$(OBJ)\s3_lib.obj &
	$(OBJ)\ssl_algs.obj &
	$(OBJ)\ssl_asn1.obj &
	$(OBJ)\ssl_both.obj &
	$(OBJ)\ssl_cert.obj &
	$(OBJ)\ssl_ciph.obj &
	$(OBJ)\sslciphr.obj &
	$(OBJ)\ssl_clnt.obj &
	$(OBJ)\ssl_err.obj &
	$(OBJ)\ssl_init.obj &
	$(OBJ)\ssl_lib.obj &
	$(OBJ)\sslmeth.obj &
	$(OBJ)\ssl_pkt.obj &
	$(OBJ)\sslpkt.obj &
	$(OBJ)\ssl_rsa.obj &
	$(OBJ)\ssl_sess.obj &
	$(OBJ)\sslsigal.obj &
	$(OBJ)\ssl_srvr.obj &
	$(OBJ)\ssl_stat.obj &
	$(OBJ)\ssltlsex.obj &
	$(OBJ)\ssltrans.obj &
	$(OBJ)\ssl_txt.obj &
	$(OBJ)\sslver.obj &
	$(OBJ)\t1_enc.obj &
	$(OBJ)\t1_lib.obj &
	$(OBJ)\tlsbuff.obj &
	$(OBJ)\tlscli.obj &
	$(OBJ)\tlshand.obj &
	$(OBJ)\tlskey.obj &
	$(OBJ)\tlslayer.obj &
	$(OBJ)\tlslib.obj &
	$(OBJ)\tlsmsg.obj &
	$(OBJ)\tlsrec.obj

all : $(LIB)\ssl.lib
	
$(LIB)\ssl.lib : $(LIBSSL_OBJS)
	wlib -n $^@ @owd32.lbc
	
.c{$(OBJ)}.obj :
	*$(CC) $(CFLAGS) -fo=$@ $[@

