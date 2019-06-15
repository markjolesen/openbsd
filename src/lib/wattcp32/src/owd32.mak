#
# Makefile for the Watt-32 TCP/IP stack.
#

W32_BIN2C=..\util\bin2c.exe

ASM_SOURCE = asmpkt.asm chksum0.asm cpumodel.asm

CORE_SOURCE = bsdname.c  btree.c    chksum.c   country.c  crc.c      dynip.c    &
              echo.c     fortify.c  getopt.c   gettod.c   highc.c    idna.c     &
              ip4_frag.c ip4_in.c   ip4_out.c  ip6_in.c   ip6_out.c  language.c &
              lookup.c   loopback.c misc.c     netback.c  oldstuff.c packet32.c &
              pc_cbrk.c  pcarp.c    pcbootp.c  pcbuf.c    pcconfig.c pcdbug.c   &
              pcdhcp.c   pcdns.c    pcicmp.c   pcicmp6.c  pcigmp.c   pcintr.c   &
              pcping.c   pcpkt.c    pcpkt32.c  pcqueue.c  pcrarp.c   pcrecv.c   &
              pcsed.c    pcstat.c   pctcp.c    ports.c    powerpak.c ppp.c      &
              pppoe.c    profile.c  punycode.c qmsg.c     rs232.c    run.c      &
              settod.c   sock_dbu.c sock_in.c  sock_ini.c sock_io.c  sock_prn.c &
              sock_scn.c sock_sel.c split.c    strings.c  swsvpkt.c  tcp_fsm.c  &
              tcp_md5.c  tftp.c     timer.c    udp_rev.c  version.c  wdpmi.c    &
              win_dll.c  winadinf.c winmisc.c  winpkt.c   x32vm.c

BSD_SOURCE =  accept.c   bind.c     bsddbug.c  close.c    connect.c  fcntl.c    &
              fsext.c    get_ai.c   get_ip.c   get_ni.c   get_xbyr.c geteth.c   &
              gethost.c  gethost6.c getname.c  getnet.c   getprot.c  getput.c   &
              getserv.c  ioctl.c    linkaddr.c listen.c   netaddr.c  neterr.c   &
              nettime.c  nsapaddr.c poll.c     presaddr.c printk.c   receive.c  &
              select.c   shutdown.c signal.c   socket.c   sockopt.c  stream.c   &
              syslog.c   syslog2.c  transmit.c

BIND_SOURCE = res_comp.c res_data.c res_debu.c res_init.c res_loc.c res_mkqu.c &
              res_quer.c res_send.c

ZLIB_SOURCE = zadler32.c  zcompres.c zcrc32.c   zgzio.c &
              zuncompr.c  zdeflate.c ztrees.c   zutil.c &
              zinflate.c  zinfback.c zinftree.c zinffast.c

C_SOURCE = $(CORE_SOURCE) $(BSD_SOURCE) $(BIND_SOURCE) $(ZLIB_SOURCE)

OBJS = &
       $(OBJDIR)\chksum0.obj  $(OBJDIR)\cpumodel.obj  &
       $(OBJDIR)\accept.obj   $(OBJDIR)\bind.obj      &
       $(OBJDIR)\bsddbug.obj  $(OBJDIR)\bsdname.obj   &
       $(OBJDIR)\btree.obj    $(OBJDIR)\chksum.obj    &
       $(OBJDIR)\close.obj    $(OBJDIR)\connect.obj   &
       $(OBJDIR)\country.obj  $(OBJDIR)\crc.obj       &
       $(OBJDIR)\dynip.obj    $(OBJDIR)\echo.obj      &
       $(OBJDIR)\fcntl.obj    $(OBJDIR)\fortify.obj   &
       $(OBJDIR)\fsext.obj    $(OBJDIR)\get_ai.obj    &
       $(OBJDIR)\get_ip.obj   $(OBJDIR)\get_ni.obj    &
       $(OBJDIR)\get_xbyr.obj $(OBJDIR)\geteth.obj    &
       $(OBJDIR)\gethost.obj  $(OBJDIR)\gethost6.obj  &
       $(OBJDIR)\getname.obj  $(OBJDIR)\getnet.obj    &
       $(OBJDIR)\getopt.obj   $(OBJDIR)\getprot.obj   &
       $(OBJDIR)\getput.obj   $(OBJDIR)\getserv.obj   &
       $(OBJDIR)\gettod.obj   $(OBJDIR)\idna.obj      &
       $(OBJDIR)\ioctl.obj    $(OBJDIR)\ip4_frag.obj  &
       $(OBJDIR)\ip4_in.obj   $(OBJDIR)\ip4_out.obj   &
       $(OBJDIR)\ip6_in.obj   $(OBJDIR)\ip6_out.obj   &
       $(OBJDIR)\language.obj $(OBJDIR)\linkaddr.obj  &
       $(OBJDIR)\listen.obj   $(OBJDIR)\lookup.obj    &
       $(OBJDIR)\loopback.obj $(OBJDIR)\misc.obj      &
       $(OBJDIR)\netaddr.obj  $(OBJDIR)\netback.obj   &
       $(OBJDIR)\neterr.obj   $(OBJDIR)\nettime.obj   &
       $(OBJDIR)\nsapaddr.obj $(OBJDIR)\oldstuff.obj  &
       $(OBJDIR)\packet32.obj $(OBJDIR)\pc_cbrk.obj   &
       $(OBJDIR)\pcarp.obj    $(OBJDIR)\pcbootp.obj   &
       $(OBJDIR)\pcbuf.obj    $(OBJDIR)\pcconfig.obj  &
       $(OBJDIR)\pcdbug.obj   $(OBJDIR)\pcdhcp.obj    &
       $(OBJDIR)\pcdns.obj    $(OBJDIR)\pcicmp.obj    &
       $(OBJDIR)\pcicmp6.obj  $(OBJDIR)\pcigmp.obj    &
       $(OBJDIR)\pcintr.obj   $(OBJDIR)\pcping.obj    &
       $(OBJDIR)\pcpkt.obj    $(OBJDIR)\pcpkt32.obj   &
       $(OBJDIR)\pcqueue.obj  $(OBJDIR)\pcrarp.obj    &
       $(OBJDIR)\pcrecv.obj   $(OBJDIR)\pcsed.obj     &
       $(OBJDIR)\pcstat.obj   $(OBJDIR)\pctcp.obj     &
       $(OBJDIR)\poll.obj     $(OBJDIR)\ports.obj     &
       $(OBJDIR)\powerpak.obj $(OBJDIR)\ppp.obj       &
       $(OBJDIR)\pppoe.obj    $(OBJDIR)\presaddr.obj  &
       $(OBJDIR)\printk.obj   $(OBJDIR)\profile.obj   &
       $(OBJDIR)\punycode.obj $(OBJDIR)\qmsg.obj      &
       $(OBJDIR)\receive.obj  $(OBJDIR)\res_comp.obj  &
       $(OBJDIR)\res_data.obj $(OBJDIR)\res_debu.obj  &
       $(OBJDIR)\res_init.obj $(OBJDIR)\res_loc.obj   &
       $(OBJDIR)\res_mkqu.obj $(OBJDIR)\res_quer.obj  &
       $(OBJDIR)\res_send.obj $(OBJDIR)\rs232.obj     &
       $(OBJDIR)\run.obj      $(OBJDIR)\select.obj    &
       $(OBJDIR)\settod.obj   $(OBJDIR)\shutdown.obj  &
       $(OBJDIR)\signal.obj   $(OBJDIR)\sock_dbu.obj  &
       $(OBJDIR)\sock_in.obj  $(OBJDIR)\sock_ini.obj  &
       $(OBJDIR)\sock_io.obj  $(OBJDIR)\sock_prn.obj  &
       $(OBJDIR)\sock_scn.obj $(OBJDIR)\sock_sel.obj  &
       $(OBJDIR)\socket.obj   $(OBJDIR)\sockopt.obj   &
       $(OBJDIR)\split.obj    $(OBJDIR)\stream.obj    &
       $(OBJDIR)\strings.obj  $(OBJDIR)\swsvpkt.obj   &
       $(OBJDIR)\syslog.obj   $(OBJDIR)\syslog2.obj   &
       $(OBJDIR)\tcp_fsm.obj  $(OBJDIR)\tcp_md5.obj   &
       $(OBJDIR)\tftp.obj     $(OBJDIR)\timer.obj     &
       $(OBJDIR)\transmit.obj $(OBJDIR)\udp_rev.obj   &
       $(OBJDIR)\version.obj  $(OBJDIR)\wdpmi.obj     &
       $(OBJDIR)\win_dll.obj  $(OBJDIR)\winadinf.obj  &
       $(OBJDIR)\winmisc.obj  $(OBJDIR)\winpkt.obj    &
       $(OBJDIR)\x32vm.obj    $(OBJDIR)\zadler32.obj  &
       $(OBJDIR)\zcompres.obj $(OBJDIR)\zcrc32.obj    &
       $(OBJDIR)\zdeflate.obj $(OBJDIR)\zgzio.obj     &
       $(OBJDIR)\zinfback.obj $(OBJDIR)\zinffast.obj  &
       $(OBJDIR)\zinflate.obj $(OBJDIR)\zinftree.obj  &
       $(OBJDIR)\ztrees.obj   $(OBJDIR)\zuncompr.obj  &
       $(OBJDIR)\zutil.obj

#
# This generated file is used for all 32-bit MSDOS targets
# (and when USE_FAST_PKT is defined). This enables a faster real-mode
# callback for the PKTDRVR receiver. Included as an array in pcpkt2.c.
#
PKT_STUB = pkt_stub.h

########################################################################


.EXTENSIONS: .l

CC      = wcc386
CFLAGS  = -mf -3r -bt=dos
AFLAGS  = -bt=dos -3r -dDOSX -dDOS4GW
TARGET  = ..\..\..\..\usr\lib\wattcpwf.lib
OBJDIR  = build\watcom\flat
MAKEFIL = owd32.mak


LIBARG  = $(OBJDIR)\wlib.arg
LINKARG = $(OBJDIR)\wlink.arg
C_ARGS  = $(OBJDIR)\$(CC).arg

# AFLAGS += -zq -fr=nul -w3 -d1
CFLAGS += -DWATT32_BUILD -I. -I..\inc

#
# WCC386-flags used:
#   -m{s,l,f} memory model; small, large or flat
#   -3s       optimise for 386, stack call convention
#   -3r       optimise for 386, register calls
#   -s        no stack checking
#   -zq       quiet compiling
#   -d3       generate full debug info
#   -fpi      inline math + emulation
#   -fr       write errors to file (and stdout)
#   -bt=dos   target system - DOS
#   -bt=nt    target system - Win-NT
#   -zm       place each function in separate segment
#   -oilrtfm  optimization flags
#     i:      expand intrinsics
#     l:      loop optimisations
#     r:      reorder instructions
#     t:      favor execution time
#     f:      always use stack frames
#     m:      generate inline code for math functions
#
#  This should make the smallest code on a 386
#    -oahkrs -s -em -zp1 -3r -fp3
#
#  WCC-flags for small/large model:
#    -zc      place const data into the code segment
#    -os      optimization flags
#      s:     favour code size over execution time
#

AS = wasm
AR = wlib -q -b -c

all: $(PKT_STUB) $(C_ARGS) $(OBJDIR)\cflags.h $(OBJDIR)\cflagsb.h $(TARGET)

#..\lib\wattcpwf.lib: $(OBJS) $(LIBARG)
$(TARGET) : $(OBJS) $(LIBARG)
	$(AR) $^@ @$(LIBARG)

-!include "build\watcom\watt32.dep"

$(OBJDIR)\asmpkt.obj:   asmpkt.asm
$(OBJDIR)\chksum0.obj:  chksum0.asm
$(OBJDIR)\cpumodel.obj: cpumodel.asm

.ERASE
.c{$(OBJDIR)}.obj:
	*$(CC) $[@ @$(C_ARGS) -fo=$@

.ERASE
.asm{$(OBJDIR)}.obj:
	*$(AS) $[@ $(AFLAGS) -fo=$@

$(C_ARGS): $(MAKEFIL)
	%create $^@
	%append $^@ $(CFLAGS)

clean: .SYMBOLIC
	- @del $(OBJDIR)\*.obj
	- @del $(TARGET)
	- @del $(C_ARGS)
	- @del $(LIBARG)
	- @del pkt_stub.h
	@echo Cleaning done

$(LIBARG): $(MAKEFIL)
	%create $^@
	for %f in ($(OBJS)) do %append $^@ +- %f


########################################################################


########################################################################

doxygen:
	doxygen doxyfile

lang.c: lang.l
	flex -8 -t lang.l > lang.c

#
# GNU-Make rules uses shell 'sh' commands:
#
$(OBJDIR)\cflags.h: $(MAKEFIL)
	echo const char *w32_cflags = "$(CFLAGS)";  > $(OBJDIR)\cflags.h
	echo const char *w32_cc     = "$(CC)";     >> $(OBJDIR)\cflags.h


$(OBJDIR)\pcpkt.obj: asmpkt.nas

$(PKT_STUB): asmpkt.nas
	$(%W32_NASM) -f bin -l asmpkt.lst -o asmpkt.bin asmpkt.nas
	$(%W32_BIN2C) asmpkt.bin > $@

#
# Rules for creating cflagsb.h. A file with a C-array of the CFLAGS used.
# Included in version.c.
#
# $(W32_BIN2C) should be set by .\configur.bat to point to either
# ..\util\bin2.exe or ..\util\win32\bin2c.exe.
#
build\watcom\flat\cflagsb.h: $(C_ARGS)
	$(W32_BIN2C) $(C_ARGS)                    > build\watcom\flat\cflagsb.h

