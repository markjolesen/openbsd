git mv ./poly1305/poly1305-donna.c ./poly1305/p_donna.c
git rm -f ./whrlpool/asm/wp-x86_64.pl
git mv ./des/ede_cbcm_enc.c ./des/edecbenc.c
git mv ./des/COPYRIGHT ./des/copyright
git rm -r -f ./sha/asm
git rm -r -f ./rc4/asm
git mv ./constant_time_locl.h  ./ctm_locl.h  
git mv ./curve25519/curve25519.c          ./curve25519/crv25519.c  
git mv ./curve25519/curve25519.h          ./curve25519/crv25519.h  
git mv ./curve25519/curve25519-generic.c  ./curve25519/25519gen.c  
git mv ./curve25519/curve25519_internal.h ./curve25519/25519int.h  
git mv ./modes/modes_lcl.h  ./modes/modeslcl.h  
git rm -r -f ./modes/asm
git mv ./crypto_lock.c  ./cryptolk.c  
git rm ./x86_64cpuid.pl 
git mv ./objects/objects.README  ./objects/readme  
git mv ./malloc-wrapper.c  ./malloc_w.c  
git mv ./crypto_init.c  ./cryptini.c  
git mv ./stack/safestack.h  ./stack/safestk.h  
git rm -r -f  ./bn/asm
git mv ./format-pem.pl  ./fmtpem.pl  
git rm -f ./sparccpuid.S
git mv ./aes/README  ./aes/readme  
git rm -r -f ./aes/asm
git mv ./aes/aes_x86core.c  ./aes/x86core.c  
git rm -f ./sparcv9cap.c  
git rm -f ./ppccap.c  
git rm -f ./arc4random/arc4random_aix.h  
git rm -f ./arc4random/arc4random_freebsd.h  
git rm -f ./arc4random/arc4random_hpux.h  
git rm -f ./arc4random/arc4random_netbsd.h  
git rm -f ./arc4random/arc4random_osx.h  
git rm -f ./arc4random/arc4random_solaris.h  
git rm -f ./arc4random/arc4random_win.h  
git rm -f ./arc4random/getentropy_aix.c  
git rm -f ./arc4random/getentropy_freebsd.c  
git rm -f ./arc4random/getentropy_hpux.c  
git rm -f ./arc4random/getentropy_netbsd.c  
git rm -f ./arc4random/getentropy_osx.c  
git rm -f ./arc4random/getentropy_solaris.c  
git rm -f ./arc4random/getentropy_win.c  
git rm -f ./arc4random/arc4random_linux.h  
git rm -f ./arc4random/getentropy_linux.c  
git mv ./ts/ts_req_print.c  ./ts/reqprint.c  
git mv ./ts/ts_req_utils.c  ./ts/requtils.c  
git mv ./ts/ts_rsp_verify.c ./ts/rspvfy.c  
git mv ./ts/ts_rsp_sign.c   ./ts/rspsign.c  
git mv ./ts/ts_rsp_print.c  ./ts/rspprint.c  
git mv ./ts/ts_rsp_utils.c  ./ts/rsputils.c  
git mv ./ts/ts_verify_ctx.c ./ts/vfy_ctx.c  
git mv ./gost/gost2814789.c        ./gost/g2814789.c  
git mv ./gost/gost_asn1.c          ./gost/gostasn1.c  
git mv ./gost/gost_locl.h          ./gost/gostlocl.h  
git mv ./gost/gost89imit_ameth.c   ./gost/g89ameth.c  
git mv ./gost/gostr341001_ameth.c  ./gost/g341001a.c  
git mv ./gost/gost_asn1.h          ./gost/gostasn1.h  
git mv ./gost/gostr341194.c        ./gost/g341194.c  
git mv ./gost/gostr341001.c        ./gost/g341001.c  
git mv ./gost/gostr341001_params.c ./gost/g341001p.c  
git mv ./gost/gost89_params.c      ./gost/g89param.c  
git mv ./gost/gost89_keywrap.c     ./gost/g89keywr.c  
git mv ./gost/gostr341001_key.c    ./gost/g341001k.c  
git mv ./gost/gost89imit_pmeth.c   ./gost/g89pmeth.c  
git mv ./gost/gostr341001_pmeth.c  ./gost/g341001m.c  
git rm -f ./alphacpuid.pl  
git mv ./camellia/cmll_locl.h  ./camellia/cmlllocl.h  
git mv ./camellia/cmll_misc.c  ./camellia/cmllmisc.c  
git rm -r -f ./camellia/asm  
git mv ./ui/ui_openssl.c  ./ui/uissl.c  
git mv ./md32_common.h  ./md32comm.h  
git mv ./rsa/rsa_ameth.c  ./rsa/rsaameth.c  
git mv ./rsa/rsa_pmeth.c  ./rsa/rsapmeth.c  
git mv ./ec/ecp_nistp224.c  ./ec/nistp224.c  
git mv ./ec/ecp_nistp256.c  ./ec/nistp256.c  
git mv ./ec/ecp_nistz256_table.h  ./ec/nistztab.h  
git mv ./ec/ecp_nistp521.c  ./ec/nistp521.c  
git mv ./ec/ecp_nistz256.c  ./ec/nistz256.c   
git rm -r -f ./ec/asm  
git mv ./ec/ecp_nistputil.c  ./ec/nistputi.c  
git mv ./shlib_version  ./shlibver  
git mv ./dso/dso_dlfcn.c  ./dso/dsodlfcn.c  
git mv ./dso/dso_openssl.c  ./dso/dsoopnssl.c  
git mv ./evp/m_streebog.c  ./evp/mstreebo.c  
git mv ./evp/m_md5_sha1.c  ./evp/mmd5sha1.c  
git mv ./evp/e_gost2814789.c  ./evp/e2814789.c  
git mv ./evp/e_camellia.c  ./evp/ecamelli.c  
git mv ./evp/m_gost2814789.c  ./evp/m2814789.c  
git mv ./evp/e_rc4_hmac_md5.c  ./evp/hmac_md5.c  
git mv ./evp/pmeth_lib.c  ./evp/pmethlib.c  
git mv ./evp/e_aes_cbc_hmac_sha1.c  ./evp/hmacsha1.c  
git mv ./evp/m_gostr341194.c  ./evp/m341194.c  
git mv ./evp/e_chacha20poly1305.c  ./evp/poly1305.c  
git mv ./opensslfeatures.h  ./opnsslft.h  
git mv ./bf/README  ./bf/readme  
git mv ./bf/VERSION  ./bf/version  
git rm -r -f ./bf/asm  
git mv ./bf/INSTALL  ./bf/install  
git mv ./bf/COPYRIGHT  ./bf/copyrigh  
git mv ./engine/README ./engine/readme    
git mv ./engine/eng_aesni.c   ./engine/engaesni.c  
git mv ./engine/eng_table.c   ./engine/engtable.c  
git mv ./engine/eng_openssl.c ./engine/enopnssl.c  
git mv ./engine/tb_pkmeth.c   ./engine/tbpkmeth.c  
git mv ./engine/tb_cipher.c   ./engine/tbcipher.c  
git mv ./engine/tb_digest.c   ./engine/tbdigest.c  
git mv ./engine/eng_padlock.ec ./engine/padlock.ec  
git mv ./engine/eng_padlock.c  ./engine/padlock.c  
git mv ./engine/tb_asnmth.c  ./engine/tbasnmth.c  
git mv ./Makefile  ./makefile  
git mv ./x509v3/pcy_cache.c  ./x509v3/pcycache.c  
git rm -r -f ./man  
git mv ./asn1/a_time_tm.c ./asn1/atime_tm.c   
git mv ./asn1/asn1_locl.h ./asn1/asn1locl.h   
git mv ./asn1/ameth_lib.c ./asn1/amethlib.c  
git rm -r -f ./cast/asm  
git mv ./chacha/chacha-merged.c  ./chacha/merged.c  
git rm -f ./arm_arch.h  
git rm -f ./ppccpuid.pl  
git mv ./generate_pkgconfig.sh  ./pkgcfg.sh  
git rm -r -f ./md5/asm  
git rm -r -f ./perlasm  
git mv ./Symbols.list  ./symbols.lst  
git rm -r -f ./arch/hppa  
git rm -r -f ./arch/alpha  
git rm -r -f ./arch/amd64  
git rm -r -f ./arch/m88k  
git rm -r -f ./arch/sparc  
git mv ./arch/i386/opensslconf.h  ./arch/i386/sslcfg.h  
git mv ./arch/i386/Makefile.inc  ./arch/i386/makefile.inc  
git rm -r -f ./arch/sparc64  
git rm -r -f ./arch/mips64  
git rm -r -f ./arch/powerpc  
git rm -r -f ./arch/sh  
git rm -r -f ./arch/arm  
git rm -r -f ./arch/aarch64  
git mv ./conf/README ./conf/readme   
git mv ./conf/conf_mall.c  ./conf/confmall.c  
git rm -f ./armv4cpuid.S  
