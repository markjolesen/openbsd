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

DEFINES=
INCLUDES=

CC=wcc386
CFLAGS=-3r -mf -bt=DOS $(DEFINES) $(INCLUDES)

LIBBSD_OBJS=&
	$(OBJ)\arc4rand.obj &
	$(OBJ)\asprintf.obj &
	$(OBJ)\bzero.obj &
	$(OBJ)\entropy.obj &
	$(OBJ)\freezero.obj &
	$(OBJ)\ftrunc.obj &
	$(OBJ)\gmtime_r.obj &
	$(OBJ)\htonl.obj &
	$(OBJ)\htons.obj &
	$(OBJ)\localtm.obj &
	$(OBJ)\memalign.obj &
	$(OBJ)\ntohs.obj &
	$(OBJ)\pread.obj &
	$(OBJ)\progname.obj &
	$(OBJ)\pwrite.obj &
	$(OBJ)\realloca.obj &
	$(OBJ)\recalloc.obj &
	$(OBJ)\safebcmp.obj &
	$(OBJ)\safemcmp.obj &
	$(OBJ)\strndup.obj &
	$(OBJ)\strnlen.obj &
	$(OBJ)\strsep.obj

all : $(LIB)\bsd.lib
	
$(LIB)\bsd.lib : $(LIBBSD_OBJS)
	wlib -n $^@ @owd32.lbc
	
.c{$(OBJ)}.obj :
	*$(CC) $(CFLAGS) -fo=$@ $[@

