#
# License CC0 PUBLIC DOMAIN
#
# To the extent possible under law, Mark J. Olesen has waived all copyright 
# and related or neighboring rights to owd32.mak file. This work is published 
# from: United States.
#

OBJ=obj
LIB=lib

DEFINES= -DLIBRESSL_INTERNAL -DOPENSSL_NO_DEPRECATED
INCLUDES= -i..\..\..\usr\include 
INCLUDES+= -i\source\wattcp32\inc

CC=wcc386
CFLAGS=-3r -mf -bt=DOS -d3 $(DEFINES) $(INCLUDES)

LIBTLS_OBJS=&
	$(OBJ)\bio_cb.obj &
	$(OBJ)\client.obj &
	$(OBJ)\config.obj &
	$(OBJ)\conninfo.obj &
	$(OBJ)\keypair.obj &
	$(OBJ)\ocsp.obj &
	$(OBJ)\peer.obj &
	$(OBJ)\server.obj &
	$(OBJ)\tls.obj &
	$(OBJ)\util.obj &
	$(OBJ)\verify.obj

all : $(LIB)\tls.lib
	
$(LIB)\tls.lib : $(LIBTLS_OBJS)
	wlib -n $^@ @owd32.lbc
	
.c{$(OBJ)}.obj :
	*$(CC) $(CFLAGS) -fo=$@ $[@

