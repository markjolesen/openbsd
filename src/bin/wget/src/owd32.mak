ROOT=..\..\..\..

WGET_BIN=$(ROOT)\usr\bin\wget.exe

VERSION = 1.20.3 (Watcom/DOS)

INCLUDES= -I. -I..\lib -I$(ROOT)\usr\include

CFLAGS= -mf -3r -bt=DOS  

DEFINES= -DHAVE_CONFIG_H -DSIZEOF_INT=4 -DUSE_WATT32 -DMSDOS
DEFINES+= -DWATT32_NO_NAMESPACE -DHAVE_SSL -DENABLE_DEBUG

COMPILE = *wcc386 $(CFLAGS) $(INCLUDES) $(DEFINES)

LINK = *wlink option quiet, map, verbose, eliminate, caseexact, stack=100k system causeway

.c : ..\lib

OBJ = obj

LIB_OBJS = &
	$(OBJ)\c-ctype.obj &
	$(OBJ)\casecmp.obj &
	$(OBJ)\casencmp.obj &
	$(OBJ)\casestr.obj &
	$(OBJ)\dirname.obj &
	$(OBJ)\dirnamel.obj &
	$(OBJ)\error.obj &
	$(OBJ)\exitfail.obj &
	$(OBJ)\getopt.obj &
	$(OBJ)\getopt1.obj &
	$(OBJ)\getpass.obj &
	$(OBJ)\lcharset.obj &
	$(OBJ)\mbchar.obj &
	$(OBJ)\mbiter.obj &
	$(OBJ)\md5.obj &
	$(OBJ)\quotearg.obj &
	$(OBJ)\regex.obj &
	$(OBJ)\xalloc.obj &
	$(OBJ)\xmalloc.obj &
	$(OBJ)\xmemdup0.obj &
	$(OBJ)\xstrndup.obj &
	$(OBJ)\tmpdir.obj &
	$(OBJ)\sha1.obj &
	$(OBJ)\base32.obj &
	$(OBJ)\basename.obj &
	$(OBJ)\basenam2.obj &
	$(OBJ)\getline.obj &
	$(OBJ)\sha256.obj &
	$(OBJ)\getdelim.obj &
	$(OBJ)\strptime.obj &
	$(OBJ)\memrchr.obj &
	$(OBJ)\utils.obj

WGET_OBJS = &
	$(OBJ)\build_in.obj &
	$(OBJ)\connect.obj &
	$(OBJ)\convert.obj &
	$(OBJ)\cookies.obj &
	$(OBJ)\css.obj &
	$(OBJ)\css-url.obj &
	$(OBJ)\exits.obj &
	$(OBJ)\ftp-basi.obj &
	$(OBJ)\ftp.obj &
	$(OBJ)\ftp-ls.obj &
	$(OBJ)\ftp-opie.obj &
	$(OBJ)\hash.obj &
	$(OBJ)\host.obj &
	$(OBJ)\html-par.obj &
	$(OBJ)\html-url.obj &
	$(OBJ)\http.obj &
	$(OBJ)\init.obj &
	$(OBJ)\log.obj &
	$(OBJ)\main.obj &
	$(OBJ)\netrc.obj &
	$(OBJ)\openssl.obj &
	$(OBJ)\progress.obj &
	$(OBJ)\ptimer.obj &
	$(OBJ)\recur.obj &
	$(OBJ)\res.obj &
	$(OBJ)\retr.obj &
	$(OBJ)\spider.obj &
	$(OBJ)\wgetbio.obj &
	$(OBJ)\version.obj &
	$(OBJ)\url.obj &
	$(OBJ)\warc.obj &
	$(OBJ)\xattr.obj

OBJECTS = $(LIB_OBJS) $(WGET_OBJS)

all : $(OBJ) $(WGET_BIN) .SYMBOLIC
	@echo 'Welcome to Wget / Watcom'

$(OBJ) :
	- mkdir $^@

.ERASE
.c{$(OBJ)}.obj : .AUTODEPEND
	*$(COMPILE) -fo=$@ $[@

css.c : css.l
	flex -8 -o$@ $[@

$(WGET_BIN) : $(OBJECTS)
	$(LINK) name $@ file { $(OBJECTS) } library ..\..\..\..\usr\lib\wattcpwf.lib, ..\..\..\..\usr\lib\bsd.lib, ..\..\..\..\usr\lib\tls.lib, ..\..\..\..\usr\lib\ssl.lib, ..\..\..\..\usr\lib\crypt.lib

version.c : owd32.mak
	@echo char *version_string = "$(VERSION)"; > $@
	@echo char *compilation_string = "$(CFLAGS)"; >> $@
#	@echo char *link_string = "$(LINK) name wget.exe file { $$(OBJECTS) }"; >> $@
	@echo char *link_string = "name wget.exe"; >> $@

clean : .SYMBOLIC
	- rm $(OBJ)\*.obj $(WGET_BIN) wget.map version.c css.c
	- rmdir $(OBJ)

