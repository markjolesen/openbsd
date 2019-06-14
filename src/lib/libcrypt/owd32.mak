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

DEFINES= -DLIBRESSL_INTERNAL -DOPENSSL_NO_ASM -DNO_SYSLOG -DOPENSSL_NO_DGRAM
DEFINES+= -DOPENSSL_NO_DEPRECATED

INCLUDES= -i$(ROOT)\usr\include 
INCLUDES+= -i. -i.\bn -i.\asn1 -i.\ec -i.\ecdsa -i.\evp -i.\modes

CC=wcc386
CFLAGS=-3r -mf -bt=DOS $(DEFINES) $(INCLUDES)

RIPEMD_OBJS=&
	$(OBJ)\rmd_one.obj &
	$(OBJ)\rmd_dgst.obj

POLY1305_OBJS=&
	$(OBJ)\poly1305.obj 

WHRLPOOL_OBJS=&
	$(OBJ)\wp_block.obj &
	$(OBJ)\wp_dgst.obj

CRV25519_OBJS=&
	$(OBJ)\25519gen.obj &
	$(OBJ)\crv25519.obj

OCSP_OBJS=&
	$(OBJ)\ocsp_cl.obj &
	$(OBJ)\ocsp_srv.obj &
	$(OBJ)\ocsp_prn.obj &
	$(OBJ)\ocsp_err.obj &
	$(OBJ)\ocsp_lib.obj &
	$(OBJ)\ocsp_asn.obj &
	$(OBJ)\ocsp_vfy.obj &
	$(OBJ)\ocsp_ext.obj &
	$(OBJ)\ocsp_ht.obj

DES_OBJS=&
	$(OBJ)\pcbc_enc.obj &
	$(OBJ)\cbc_enc.obj &
	$(OBJ)\ecb_enc.obj &
	$(OBJ)\qud_cksm.obj &
	$(OBJ)\cfb64ede.obj &
	$(OBJ)\rand_key.obj &
	$(OBJ)\fcrypt_b.obj &
	$(OBJ)\ofb64ede.obj &
	$(OBJ)\cfb_enc.obj &
	$(OBJ)\des_enc.obj &
	$(OBJ)\fcrypt.obj &
	$(OBJ)\enc_writ.obj &
	$(OBJ)\str2key.obj &
	$(OBJ)\edecbenc.obj &
	$(OBJ)\ofb64enc.obj &
	$(OBJ)\ofb_enc.obj &
	$(OBJ)\cbc_cksm.obj &
	$(OBJ)\set_key.obj &
	$(OBJ)\ncbc_enc.obj &
	$(OBJ)\xcbc_enc.obj &
	$(OBJ)\ecb3_enc.obj &
	$(OBJ)\enc_read.obj &
	$(OBJ)\cfb64enc.obj

SHA_OBJS=&
	$(OBJ)\sha1_one.obj &
	$(OBJ)\sha1dgst.obj &
	$(OBJ)\sha512.obj &
	$(OBJ)\sha256.obj

RC4_OBJS=&
	$(OBJ)\rc4_enc.obj &
	$(OBJ)\rc4_skey.obj

BUFFER_OBJS=&
	$(OBJ)\buf_err.obj &
	$(OBJ)\buf_str.obj &
	$(OBJ)\buffer.obj

PEM_OBJS=&
	$(OBJ)\pem_xaux.obj &
	$(OBJ)\pem_sign.obj &
	$(OBJ)\pem_pk8.obj &
	$(OBJ)\pem_x509.obj &
	$(OBJ)\pvkfmt.obj &
	$(OBJ)\pem_err.obj &
	$(OBJ)\pem_seal.obj &
	$(OBJ)\pem_all.obj &
	$(OBJ)\pem_info.obj &
	$(OBJ)\pem_pkey.obj &
	$(OBJ)\pem_lib.obj &
	$(OBJ)\pem_oth.obj

PKCS12_OBJS=&
	$(OBJ)\p12_p8d.obj &
	$(OBJ)\p12_mutl.obj &
	$(OBJ)\p12_crt.obj &
	$(OBJ)\p12_add.obj &
	$(OBJ)\p12_key.obj &
	$(OBJ)\p12_init.obj &
	$(OBJ)\p12_attr.obj &
	$(OBJ)\p12_crpt.obj &
	$(OBJ)\p12_asn.obj &
	$(OBJ)\pk12err.obj &
	$(OBJ)\p12_npas.obj &
	$(OBJ)\p12_utl.obj &
	$(OBJ)\p12_p8e.obj &
	$(OBJ)\p12_kiss.obj &
	$(OBJ)\p12_decr.obj

RAND_OBJS=&
	$(OBJ)\rand_err.obj &
	$(OBJ)\randfile.obj &
	$(OBJ)\rand_lib.obj

MODES_OBJS=&
	$(OBJ)\ccm128.obj &
	$(OBJ)\xts128.obj &
	$(OBJ)\ofb128.obj &
	$(OBJ)\cts128.obj &
	$(OBJ)\cbc128.obj &
	$(OBJ)\ctr128.obj &
	$(OBJ)\gcm128.obj &
	$(OBJ)\cfb128.obj

TXT_DB_OBJS=&
	$(OBJ)\txt_db.obj

OBJECTS_OBJS=&
	$(OBJ)\obj_dat.obj &
	$(OBJ)\obj_err.obj &
	$(OBJ)\o_names.obj &
	$(OBJ)\obj_xref.obj &
	$(OBJ)\obj_lib.obj

HKDF_OBJS=&
	$(OBJ)\hkdf.obj

BIO_OBJS=&
	$(OBJ)\bss_log.obj &
	$(OBJ)\bss_null.obj &
	$(OBJ)\b_posix.obj &
	$(OBJ)\bss_conn.obj &
	$(OBJ)\bss_mem.obj &
	$(OBJ)\bf_nbio.obj &
	$(OBJ)\bio_lib.obj &
	$(OBJ)\bio_err.obj &
	$(OBJ)\bss_file.obj &
	$(OBJ)\b_dump.obj &
	$(OBJ)\bf_lbuf.obj &
	$(OBJ)\b_sock.obj &
	$(OBJ)\bio_cb.obj &
	$(OBJ)\bf_buff.obj &
	$(OBJ)\bss_sock.obj &
	$(OBJ)\bf_null.obj &
	$(OBJ)\b_print.obj &
	$(OBJ)\bss_bio.obj &
	$(OBJ)\bss_fd.obj &
	$(OBJ)\bssdgram.obj &
	$(OBJ)\bio_meth.obj &
	$(OBJ)\bss_acpt.obj

ECDH_OBJS=&
	$(OBJ)\ech_err.obj &
	$(OBJ)\ech_lib.obj &
	$(OBJ)\ech_key.obj

STACK_OBJS=&
	$(OBJ)\stack.obj

BN_OBJS=&
	$(OBJ)\bn_asm.obj &
	$(OBJ)\bn_kron.obj &
	$(OBJ)\bn_print.obj &
	$(OBJ)\bn_mod.obj &
	$(OBJ)\bn_exp.obj &
	$(OBJ)\bn_mpi.obj &
	$(OBJ)\bn_shift.obj &
	$(OBJ)\bn_word.obj &
	$(OBJ)\bn_lib.obj &
	$(OBJ)\bn_blind.obj &
	$(OBJ)\bn_depr.obj &
	$(OBJ)\bn_sqrt.obj &
	$(OBJ)\bn_gcd.obj &
	$(OBJ)\bn_nist.obj &
	$(OBJ)\bn_const.obj &
	$(OBJ)\bn_sqr.obj &
	$(OBJ)\bn_mont.obj &
	$(OBJ)\bn_prime.obj &
	$(OBJ)\bn_recp.obj &
	$(OBJ)\bn_ctx.obj &
	$(OBJ)\bn_rand.obj &
	$(OBJ)\bn_exp2.obj &
	$(OBJ)\bn_add.obj &
	$(OBJ)\bn_err.obj &
	$(OBJ)\bn_gf2m.obj &
	$(OBJ)\bn_x931p.obj &
	$(OBJ)\bn_mul.obj &
	$(OBJ)\bn_div.obj

DH_OBJS=&
	$(OBJ)\dh_lib.obj &
	$(OBJ)\dh_key.obj &
	$(OBJ)\dh_depr.obj &
	$(OBJ)\dh_prn.obj &
	$(OBJ)\dh_err.obj &
	$(OBJ)\dh_pmeth.obj &
	$(OBJ)\dh_ameth.obj &
	$(OBJ)\dh_asn1.obj &
	$(OBJ)\dh_gen.obj &
	$(OBJ)\dh_check.obj

ECDSA_OBJS=&
	$(OBJ)\ecs_err.obj &
	$(OBJ)\ecs_asn1.obj &
	$(OBJ)\ecs_sign.obj &
	$(OBJ)\ecs_lib.obj &
	$(OBJ)\ecs_ossl.obj &
	$(OBJ)\ecs_vrf.obj

DSA_OBJS=&
	$(OBJ)\dsa_gen.obj &
	$(OBJ)\dsa_ossl.obj &
	$(OBJ)\dsa_sign.obj &
	$(OBJ)\dsameth.obj &
	$(OBJ)\dsa_lib.obj &
	$(OBJ)\dsaameth.obj &
	$(OBJ)\dsa_key.obj &
	$(OBJ)\dsa_depr.obj &
	$(OBJ)\dsa_err.obj &
	$(OBJ)\dsa_asn1.obj &
	$(OBJ)\dsa_vrf.obj &
	$(OBJ)\dsapmeth.obj &
	$(OBJ)\dsa_prn.obj

LHASH_OBJS=&
	$(OBJ)\lhash.obj &
	$(OBJ)\lh_stats.obj

SM3_OBJS=&
	$(OBJ)\sm3.obj

AES_OBJS=&
	$(OBJ)\aes_ctr.obj &
	$(OBJ)\aes_misc.obj &
	$(OBJ)\aes_cbc.obj &
	$(OBJ)\aes_ecb.obj &
	$(OBJ)\x86core.obj &
	$(OBJ)\aes_core.obj &
	$(OBJ)\aes_wrap.obj &
	$(OBJ)\aes_ofb.obj &
	$(OBJ)\aes_ige.obj &
	$(OBJ)\aes_cfb.obj

TS_OBJS=&
	$(OBJ)\ts_asn1.obj &
	$(OBJ)\rspprint.obj &
	$(OBJ)\ts_err.obj &
	$(OBJ)\rspsign.obj &
	$(OBJ)\requtils.obj &
	$(OBJ)\rspvfy.obj &
	$(OBJ)\ts_lib.obj &
	$(OBJ)\vfy_ctx.obj &
	$(OBJ)\ts_conf.obj &
	$(OBJ)\rsputils.obj &
	$(OBJ)\reqprint.obj

GOST_OBJS=&
	$(OBJ)\streebog.obj &
	$(OBJ)\g341194.obj &
	$(OBJ)\g89pmeth.obj &
	$(OBJ)\g341001k.obj &
	$(OBJ)\g89keywr.obj &
	$(OBJ)\g341001a.obj &
	$(OBJ)\g89ameth.obj &
	$(OBJ)\g341001p.obj &
	$(OBJ)\gostasn1.obj &
	$(OBJ)\g2814789.obj &
	$(OBJ)\g89param.obj &
	$(OBJ)\g341001.obj &
	$(OBJ)\g341001m.obj &
	$(OBJ)\gost_err.obj

SM4_OBJS=&
	$(OBJ)\sm4.obj

CAMELLIA_OBJS=&
	$(OBJ)\cmll_cfb.obj &
	$(OBJ)\cmll_ctr.obj &
	$(OBJ)\cmllmisc.obj &
	$(OBJ)\cmll_cbc.obj &
	$(OBJ)\cmll_ofb.obj &
	$(OBJ)\cmll_ecb.obj &
	$(OBJ)\camellia.obj

UI_OBJS=&
	$(OBJ)\ui_err.obj &
	$(OBJ)\ui_lib.obj &
	$(OBJ)\uissl.obj &
	$(OBJ)\ui_util.obj

RC2_OBJS=&
	$(OBJ)\rc2ofb64.obj &
	$(OBJ)\rc2cfb64.obj &
	$(OBJ)\rc2_ecb.obj &
	$(OBJ)\rc2_skey.obj &
	$(OBJ)\rc2_cbc.obj

RSA_OBJS=&
	$(OBJ)\rsa_pk1.obj &
	$(OBJ)\rsa_pss.obj &
	$(OBJ)\rsa_none.obj &
	$(OBJ)\rsa_x931.obj &
	$(OBJ)\rsa_err.obj &
	$(OBJ)\rsa_depr.obj &
	$(OBJ)\rsa_chk.obj &
	$(OBJ)\rsa_sign.obj &
	$(OBJ)\rsa_meth.obj &
	$(OBJ)\rsa_prn.obj &
	$(OBJ)\rsa_gen.obj &
	$(OBJ)\rsa_asn1.obj &
	$(OBJ)\rsaameth.obj &
	$(OBJ)\rsapmeth.obj &
	$(OBJ)\rsa_eay.obj &
	$(OBJ)\rsa_oaep.obj &
	$(OBJ)\rsa_crpt.obj &
	$(OBJ)\rsa_lib.obj &
	$(OBJ)\rsa_saos.obj

EC_OBJS=&
	$(OBJ)\ec2_mult.obj &
	$(OBJ)\ec2_smpl.obj &
	$(OBJ)\ec_key.obj &
	$(OBJ)\nistputi.obj &
	$(OBJ)\nistz256.obj &
	$(OBJ)\ecp_oct.obj &
	$(OBJ)\eck_prn.obj &
	$(OBJ)\ec_lib.obj &
	$(OBJ)\ec_cvt.obj &
	$(OBJ)\nistp521.obj &
	$(OBJ)\nistp256.obj &
	$(OBJ)\ecp_smpl.obj &
	$(OBJ)\ec_oct.obj &
	$(OBJ)\ec2_oct.obj &
	$(OBJ)\ec_pmeth.obj &
	$(OBJ)\ec_mult.obj &
	$(OBJ)\ec_ameth.obj &
	$(OBJ)\ecp_mont.obj &
	$(OBJ)\ec_check.obj &
	$(OBJ)\nistp224.obj &
	$(OBJ)\ec_err.obj &
	$(OBJ)\ecp_nist.obj &
	$(OBJ)\ec_kmeth.obj &
	$(OBJ)\ec_curve.obj &
	$(OBJ)\ec_print.obj &
	$(OBJ)\ec_asn1.obj

DSO_OBJS=&
	$(OBJ)\dso_err.obj &
	$(OBJ)\dsodlfcn.obj &
	$(OBJ)\dso_null.obj &
	$(OBJ)\dso_ssl.obj &
	$(OBJ)\dso_lib.obj

EVP_OBJS=&
	$(OBJ)\m_dss1.obj &
	$(OBJ)\e_poly.obj &
	$(OBJ)\evp_lib.obj &
	$(OBJ)\m_sigver.obj &
	$(OBJ)\pmeth_gn.obj &
	$(OBJ)\evp_pkey.obj &
	$(OBJ)\bio_enc.obj &
	$(OBJ)\p_sign.obj &
	$(OBJ)\p_open.obj &
	$(OBJ)\evp_pbe.obj &
	$(OBJ)\hmacsha1.obj &
	$(OBJ)\e_cast.obj &
	$(OBJ)\pmeth_fn.obj &
	$(OBJ)\evp_err.obj &
	$(OBJ)\e_old.obj &
	$(OBJ)\p_lib.obj &
	$(OBJ)\c_all.obj &
	$(OBJ)\bio_md.obj &
	$(OBJ)\e_rc4.obj &
	$(OBJ)\m_ecdsa.obj &
	$(OBJ)\bio_b64.obj &
	$(OBJ)\e_aes.obj &
	$(OBJ)\e_bf.obj &
	$(OBJ)\e_rc2.obj &
	$(OBJ)\e2814789.obj &
	$(OBJ)\ecamelli.obj &
	$(OBJ)\p_dec.obj &
	$(OBJ)\m2814789.obj &
	$(OBJ)\m_sha1.obj &
	$(OBJ)\m_md5.obj &
	$(OBJ)\evp_key.obj &
	$(OBJ)\e_des.obj &
	$(OBJ)\pmethlib.obj &
	$(OBJ)\m_null.obj &
	$(OBJ)\m_md4.obj &
	$(OBJ)\m_ripemd.obj &
	$(OBJ)\digest.obj &
	$(OBJ)\p_seal.obj &
	$(OBJ)\e_idea.obj &
	$(OBJ)\m_dss.obj &
	$(OBJ)\evp_enc.obj &
	$(OBJ)\encode.obj &
	$(OBJ)\p_verify.obj &
	$(OBJ)\p5_crpt2.obj &
	$(OBJ)\mmd5sha1.obj &
	$(OBJ)\e_sm4.obj &
	$(OBJ)\e_des3.obj &
	$(OBJ)\p_enc.obj &
	$(OBJ)\names.obj &
	$(OBJ)\m_sm3.obj &
	$(OBJ)\e_null.obj &
	$(OBJ)\mstreebo.obj &
	$(OBJ)\m341194.obj &
	$(OBJ)\m_wp.obj &
	$(OBJ)\hmac_md5.obj &
	$(OBJ)\e_xcbc_d.obj &
	$(OBJ)\evp_aead.obj &
	$(OBJ)\p5_crpt.obj &
	$(OBJ)\e_chacha.obj

BF_OBJS=&
	$(OBJ)\bf_cfb64.obj &
	$(OBJ)\bf_cbc.obj &
	$(OBJ)\bf_enc.obj &
	$(OBJ)\bf_ecb.obj &
	$(OBJ)\bf_skey.obj &
	$(OBJ)\bf_ofb64.obj

ENGINE_OBJS=&
	$(OBJ)\eng_cnf.obj &
	$(OBJ)\enopnssl.obj &
	$(OBJ)\eng_list.obj &
	$(OBJ)\eng_dyn.obj &
	$(OBJ)\eng_pkey.obj &
	$(OBJ)\tb_ecdh.obj &
	$(OBJ)\eng_err.obj &
	$(OBJ)\tb_ecdsa.obj &
	$(OBJ)\eng_lib.obj &
	$(OBJ)\eng_fat.obj &
	$(OBJ)\tb_rand.obj &
	$(OBJ)\tb_store.obj &
	$(OBJ)\eng_all.obj &
	$(OBJ)\tb_dh.obj &
	$(OBJ)\eng_init.obj &
	$(OBJ)\tb_eckey.obj &
	$(OBJ)\engaesni.obj &
	$(OBJ)\tbpkmeth.obj &
	$(OBJ)\tbdigest.obj &
	$(OBJ)\tb_dsa.obj &
	$(OBJ)\engtable.obj &
	$(OBJ)\tb_rsa.obj &
	$(OBJ)\tbcipher.obj &
	$(OBJ)\eng_ctrl.obj &
	$(OBJ)\padlock.obj &
	$(OBJ)\tbasnmth.obj

X509_OBJS=&
	$(OBJ)\x509name.obj &
	$(OBJ)\x509_att.obj &
	$(OBJ)\x509_err.obj &
	$(OBJ)\x509_vpm.obj &
	$(OBJ)\x509_txt.obj &
	$(OBJ)\x509_req.obj &
	$(OBJ)\x509_trs.obj &
	$(OBJ)\x_all.obj &
	$(OBJ)\x509spki.obj &
	$(OBJ)\x509_d2.obj &
	$(OBJ)\x509_ext.obj &
	$(OBJ)\x509rset.obj &
	$(OBJ)\x509_def.obj &
	$(OBJ)\by_dir.obj &
	$(OBJ)\x509_r2x.obj &
	$(OBJ)\x509_obj.obj &
	$(OBJ)\x509_v3.obj &
	$(OBJ)\by_file.obj &
	$(OBJ)\x509_vfy.obj &
	$(OBJ)\x509_lu.obj &
	$(OBJ)\x509type.obj &
	$(OBJ)\x509cset.obj &
	$(OBJ)\by_mem.obj &
	$(OBJ)\x509_cmp.obj &
	$(OBJ)\x509_set.obj

MD4_OBJS=&
	$(OBJ)\md4_one.obj &
	$(OBJ)\md4_dgst.obj

X509V3_OBJS=&
	$(OBJ)\v3_pku.obj &
	$(OBJ)\v3_pcia.obj &
	$(OBJ)\v3_ncons.obj &
	$(OBJ)\v3_genn.obj &
	$(OBJ)\v3_crld.obj &
	$(OBJ)\v3_ia5.obj &
	$(OBJ)\v3_int.obj &
	$(OBJ)\v3_alt.obj &
	$(OBJ)\v3_pci.obj &
	$(OBJ)\pcy_node.obj &
	$(OBJ)\v3_lib.obj &
	$(OBJ)\v3_bitst.obj &
	$(OBJ)\v3_cpols.obj &
	$(OBJ)\pcy_map.obj &
	$(OBJ)\v3_bcons.obj &
	$(OBJ)\v3_extku.obj &
	$(OBJ)\v3_enum.obj &
	$(OBJ)\v3_sxnet.obj &
	$(OBJ)\v3_info.obj &
	$(OBJ)\v3err.obj &
	$(OBJ)\v3_conf.obj &
	$(OBJ)\pcy_tree.obj &
	$(OBJ)\v3_prn.obj &
	$(OBJ)\v3_akey.obj &
	$(OBJ)\v3_utl.obj &
	$(OBJ)\pcy_data.obj &
	$(OBJ)\v3_skey.obj &
	$(OBJ)\v3_pmaps.obj &
	$(OBJ)\pcycache.obj &
	$(OBJ)\pcy_lib.obj &
	$(OBJ)\v3_akeya.obj &
	$(OBJ)\v3_purp.obj &
	$(OBJ)\v3_pcons.obj &
	$(OBJ)\v3_ocsp.obj

COMP_OBJS=&
	$(OBJ)\c_rle.obj &
	$(OBJ)\comp_lib.obj &
	$(OBJ)\c_zlib.obj &
	$(OBJ)\comp_err.obj

ASN1_OBJS=&
	$(OBJ)\asn1_gen.obj &
	$(OBJ)\p5_pbev2.obj &
	$(OBJ)\a_sign.obj &
	$(OBJ)\atime_tm.obj &
	$(OBJ)\x_pubkey.obj &
	$(OBJ)\a_digest.obj &
	$(OBJ)\t_bitst.obj &
	$(OBJ)\a_utf8.obj &
	$(OBJ)\tasn_typ.obj &
	$(OBJ)\a_mbstr.obj &
	$(OBJ)\x_name.obj &
	$(OBJ)\i2d_pu.obj &
	$(OBJ)\a_time.obj &
	$(OBJ)\asn1_par.obj &
	$(OBJ)\p8_pkey.obj &
	$(OBJ)\asn1_err.obj &
	$(OBJ)\x_info.obj &
	$(OBJ)\x_x509.obj &
	$(OBJ)\a_bool.obj &
	$(OBJ)\f_int.obj &
	$(OBJ)\a_print.obj &
	$(OBJ)\t_x509a.obj &
	$(OBJ)\a_bitstr.obj &
	$(OBJ)\a_octet.obj &
	$(OBJ)\x_nx509.obj &
	$(OBJ)\a_object.obj &
	$(OBJ)\x_long.obj &
	$(OBJ)\i2d_pr.obj &
	$(OBJ)\f_enum.obj &
	$(OBJ)\t_pkey.obj &
	$(OBJ)\asn_pack.obj &
	$(OBJ)\a_verify.obj &
	$(OBJ)\f_string.obj &
	$(OBJ)\evp_asn1.obj &
	$(OBJ)\a_d2i_fp.obj &
	$(OBJ)\p5_pbe.obj &
	$(OBJ)\a_strex.obj &
	$(OBJ)\t_x509.obj &
	$(OBJ)\asn1_lib.obj &
	$(OBJ)\bio_asn1.obj &
	$(OBJ)\a_enum.obj &
	$(OBJ)\x_algor.obj &
	$(OBJ)\d2i_pr.obj &
	$(OBJ)\tasn_prn.obj &
	$(OBJ)\a_type.obj &
	$(OBJ)\amethlib.obj &
	$(OBJ)\x_bignum.obj &
	$(OBJ)\tasn_utl.obj &
	$(OBJ)\tasn_new.obj &
	$(OBJ)\tasn_dec.obj &
	$(OBJ)\n_pkey.obj &
	$(OBJ)\bio_ndef.obj &
	$(OBJ)\tasn_enc.obj &
	$(OBJ)\x_exten.obj &
	$(OBJ)\t_crl.obj &
	$(OBJ)\x_sig.obj &
	$(OBJ)\t_spki.obj &
	$(OBJ)\a_strnid.obj &
	$(OBJ)\t_req.obj &
	$(OBJ)\x_x509a.obj &
	$(OBJ)\x_val.obj &
	$(OBJ)\tasn_fre.obj &
	$(OBJ)\nsseq.obj &
	$(OBJ)\x_attrib.obj &
	$(OBJ)\asn_moid.obj &
	$(OBJ)\a_int.obj &
	$(OBJ)\a_i2d_fp.obj &
	$(OBJ)\d2i_pu.obj &
	$(OBJ)\x_req.obj &
	$(OBJ)\x_pkey.obj &
	$(OBJ)\x_spki.obj &
	$(OBJ)\x_crl.obj &
	$(OBJ)\asn_mime.obj &
	$(OBJ)\a_dup.obj

CAST_OBJS=&
	$(OBJ)\c_ofb64.obj &
	$(OBJ)\c_skey.obj &
	$(OBJ)\c_ecb.obj &
	$(OBJ)\c_enc.obj &
	$(OBJ)\c_cfb64.obj

CHACHA_OBJS=&
	$(OBJ)\merged.obj &
	$(OBJ)\chacha.obj

HMAC_OBJS=&
	$(OBJ)\hm_ameth.obj &
	$(OBJ)\hmac.obj &
	$(OBJ)\hm_pmeth.obj

PKCS7_OBJS=&
	$(OBJ)\pk7_lib.obj &
	$(OBJ)\pk7_doit.obj &
	$(OBJ)\pk7_asn1.obj &
	$(OBJ)\pkcs7err.obj &
	$(OBJ)\pk7_attr.obj &
	$(OBJ)\pk7smime.obj &
	$(OBJ)\pk7_mime.obj &
	$(OBJ)\bio_pk7.obj

MD5_OBJS=&
	$(OBJ)\md5_one.obj &
	$(OBJ)\md5_dgst.obj

ERR_OBJS=&
	$(OBJ)\err_prn.obj &
	$(OBJ)\err_all.obj &
	$(OBJ)\err.obj

CONF_OBJS=&
	$(OBJ)\conf_api.obj &
	$(OBJ)\conf_def.obj &
	$(OBJ)\conf_err.obj &
	$(OBJ)\conf_mod.obj &
	$(OBJ)\conf_lib.obj &
	$(OBJ)\confmall.obj &
	$(OBJ)\conf_sap.obj

CMAC_OBJS=&
	$(OBJ)\cmac.obj &
	$(OBJ)\cm_ameth.obj &
	$(OBJ)\cm_pmeth.obj

IDEA_OBJS=&
	$(OBJ)\i_ofb64.obj &
	$(OBJ)\i_cbc.obj &
	$(OBJ)\i_ecb.obj &
	$(OBJ)\i_skey.obj &
	$(OBJ)\i_cfb64.obj

CRYPTO_OBJS=&
	$(OBJ)\malloc_w.obj &
	$(OBJ)\o_init.obj &
	$(OBJ)\o_time.obj &
	$(OBJ)\o_str.obj &
	$(OBJ)\cryptini.obj &
	$(OBJ)\ex_data.obj &
	$(OBJ)\cpt_err.obj &
	$(OBJ)\mem_clr.obj &
	$(OBJ)\mem_dbg.obj &
	$(OBJ)\cryptlib.obj &
	$(OBJ)\cryptolk.obj &
	$(OBJ)\cversion.obj

LIB_OBJS=&
	$(CRYPTO_OBJS) &
	$(RIPEMD_OBJS) &
	$(POLY1305_OBJS) &
	$(WHRLPOOL_OBJS) &
	$(CRV25519_OBJS) &
	$(OCSP_OBJS) &
	$(DES_OBJS) &
	$(SHA_OBJS) &
	$(RC4_OBJS) &
	$(BUFFER_OBJS) &
	$(PEM_OBJS) &
	$(PKCS12_OBJS) &
	$(RAND_OBJS) &
	$(MODES_OBJS) &
	$(TXT_DB_OBJS) &
	$(OBJECTS_OBJS) &
	$(HKDF_OBJS) &
	$(BIO_OBJS) &
	$(ECDH_OBJS) &
	$(STACK_OBJS) &
	$(BN_OBJS) &
	$(DH_OBJS) &
	$(ECDSA_OBJS) &
	$(DSA_OBJS) &
	$(LHASH_OBJS) &
	$(SM3_OBJS) &
	$(AES_OBJS) &
	$(TS_OBJS) &
	$(GOST_OBJS) &
	$(SM4_OBJS) &
	$(CAMELLIA_OBJS) &
	$(UI_OBJS) &
	$(RC2_OBJS) &
	$(RSA_OBJS) &
	$(EC_OBJS) &
	$(DSO_OBJS) &
	$(EVP_OBJS) &
	$(BF_OBJS) &
	$(ENGINE_OBJS) &
	$(X509_OBJS) &
	$(MD4_OBJS) &
	$(X509V3_OBJS) &
	$(COMP_OBJS) &
	$(ASN1_OBJS) &
	$(CAST_OBJS) &
	$(CHACHA_OBJS) &
	$(HMAC_OBJS) &
	$(PKCS7_OBJS) &
	$(MD5_OBJS) &
	$(ERR_OBJS) &
	$(CONF_OBJS) &
	$(CMAC_OBJS) &
	$(IDEA_OBJS)

all : $(LIB)\crypt.lib .SYMBOLIC

$(LIB)\crypt.lib : $(LIB_OBJS)
	wlib -n $^@ @owd32.lbc

$(OBJ) :
	mkdir $(OBJ)

$(LIB) :
	mkdir $(LIB)

$(OBJ)\rmd_one.obj: ripemd\rmd_one.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\rmd_dgst.obj: ripemd\rmd_dgst.c ripemd\rmd_locl.h md32comm.h &
 ripemd\rmdconst.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\poly1305.obj: poly1305\poly1305.c poly1305\p_donna.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\wp_block.obj: whrlpool\wp_block.c whrlpool\wp_locl.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\wp_dgst.obj: whrlpool\wp_dgst.c whrlpool\wp_locl.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\25519gen.obj: crv25519\25519gen.c crv25519\25519int.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\crv25519.obj: crv25519\crv25519.c crv25519\25519int.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\malloc_w.obj: malloc_w.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\ocsp_cl.obj: ocsp\ocsp_cl.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\ocsp_srv.obj: ocsp\ocsp_srv.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\ocsp_prn.obj: ocsp\ocsp_prn.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\ocsp_err.obj: ocsp\ocsp_err.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\ocsp_lib.obj: ocsp\ocsp_lib.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\ocsp_asn.obj: ocsp\ocsp_asn.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\ocsp_vfy.obj: ocsp\ocsp_vfy.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\ocsp_ext.obj: ocsp\ocsp_ext.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\ocsp_ht.obj: ocsp\ocsp_ht.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\pcbc_enc.obj: des\pcbc_enc.c des\des_locl.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\cbc_enc.obj: des\cbc_enc.c des\ncbc_enc.c des\des_locl.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\ecb_enc.obj: des\ecb_enc.c des\des_locl.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\qud_cksm.obj: des\qud_cksm.c des\des_locl.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\cfb64ede.obj: des\cfb64ede.c des\des_locl.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\rand_key.obj: des\rand_key.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\fcrypt_b.obj: des\fcrypt_b.c des\des_locl.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\ofb64ede.obj: des\ofb64ede.c des\des_locl.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\cfb_enc.obj: des\cfb_enc.c des\des_locl.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\des_enc.obj: des\des_enc.c des\des_locl.h des\spr.h des\ncbc_enc.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\fcrypt.obj: des\fcrypt.c des\des_locl.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\enc_writ.obj: des\enc_writ.c des\des_locl.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\str2key.obj: des\str2key.c des\des_locl.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\edecbenc.obj: des\edecbenc.c des\des_locl.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\ofb64enc.obj: des\ofb64enc.c des\des_locl.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\ofb_enc.obj: des\ofb_enc.c des\des_locl.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\cbc_cksm.obj: des\cbc_cksm.c des\des_locl.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\set_key.obj: des\set_key.c des\des_locl.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\ncbc_enc.obj: des\ncbc_enc.c des\des_locl.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\xcbc_enc.obj: des\xcbc_enc.c des\des_locl.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\ecb3_enc.obj: des\ecb3_enc.c des\des_locl.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\enc_read.obj: des\enc_read.c des\des_locl.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\cfb64enc.obj: des\cfb64enc.c des\des_locl.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\sha1_one.obj: sha\sha1_one.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\sha1dgst.obj: sha\sha1dgst.c sha\sha_locl.h md32comm.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\sha512.obj: sha\sha512.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\sha256.obj: sha\sha256.c md32comm.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\o_init.obj: o_init.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\rc4_enc.obj: rc4\rc4_enc.c rc4\rc4_locl.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\rc4_skey.obj: rc4\rc4_skey.c rc4\rc4_locl.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\buf_err.obj: buffer\buf_err.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\buf_str.obj: buffer\buf_str.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\buffer.obj: buffer\buffer.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\pem_xaux.obj: pem\pem_xaux.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\pem_sign.obj: pem\pem_sign.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\pem_pk8.obj: pem\pem_pk8.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\pem_x509.obj: pem\pem_x509.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\pvkfmt.obj: pem\pvkfmt.c bn\bn_lcl.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\pem_err.obj: pem\pem_err.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\pem_seal.obj: pem\pem_seal.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\pem_all.obj: pem\pem_all.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\pem_info.obj: pem\pem_info.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\pem_pkey.obj: pem\pem_pkey.c asn1\asn1locl.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\pem_lib.obj: pem\pem_lib.c asn1\asn1locl.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\pem_oth.obj: pem\pem_oth.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\p12_p8d.obj: pkcs12\p12_p8d.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\p12_mutl.obj: pkcs12\p12_mutl.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\p12_crt.obj: pkcs12\p12_crt.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\p12_add.obj: pkcs12\p12_add.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\p12_key.obj: pkcs12\p12_key.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\p12_init.obj: pkcs12\p12_init.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\p12_attr.obj: pkcs12\p12_attr.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\p12_crpt.obj: pkcs12\p12_crpt.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\p12_asn.obj: pkcs12\p12_asn.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\pk12err.obj: pkcs12\pk12err.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\p12_npas.obj: pkcs12\p12_npas.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\p12_utl.obj: pkcs12\p12_utl.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\p12_p8e.obj: pkcs12\p12_p8e.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\p12_kiss.obj: pkcs12\p12_kiss.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\p12_decr.obj: pkcs12\p12_decr.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\rand_err.obj: rand\rand_err.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\randfile.obj: rand\randfile.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\rand_lib.obj: rand\rand_lib.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\ccm128.obj: modes\ccm128.c modes\modeslcl.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\xts128.obj: modes\xts128.c modes\modeslcl.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\ofb128.obj: modes\ofb128.c modes\modeslcl.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\cts128.obj: modes\cts128.c modes\modeslcl.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\cbc128.obj: modes\cbc128.c modes\modeslcl.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\ctr128.obj: modes\ctr128.c modes\modeslcl.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\gcm128.obj: modes\gcm128.c modes\modeslcl.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\cfb128.obj: modes\cfb128.c modes\modeslcl.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\txt_db.obj: txt_db\txt_db.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\o_time.obj: o_time.c o_time.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\o_str.obj: o_str.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\cryptini.obj: cryptini.c cryptlib.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\obj_dat.obj: objects\obj_dat.c objects\obj_dat.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\obj_err.obj: objects\obj_err.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\o_names.obj: objects\o_names.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\obj_xref.obj: objects\obj_xref.c objects\obj_xref.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\obj_lib.obj: objects\obj_lib.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\ex_data.obj: ex_data.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\hkdf.obj: hkdf\hkdf.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\bss_log.obj: bio\bss_log.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\bss_null.obj: bio\bss_null.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\b_posix.obj: bio\b_posix.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\bss_conn.obj: bio\bss_conn.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\bss_mem.obj: bio\bss_mem.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\bf_nbio.obj: bio\bf_nbio.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\bio_lib.obj: bio\bio_lib.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\bio_err.obj: bio\bio_err.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\bss_file.obj: bio\bss_file.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\b_dump.obj: bio\b_dump.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\bf_lbuf.obj: bio\bf_lbuf.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\b_sock.obj: bio\b_sock.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\bio_cb.obj: bio\bio_cb.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\bf_buff.obj: bio\bf_buff.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\bss_sock.obj: bio\bss_sock.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\bf_null.obj: bio\bf_null.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\b_print.obj: bio\b_print.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\bss_bio.obj: bio\bss_bio.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\bss_fd.obj: bio\bss_fd.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\bssdgram.obj: bio\bssdgram.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\bio_meth.obj: bio\bio_meth.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\bss_acpt.obj: bio\bss_acpt.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\ech_err.obj: ecdh\ech_err.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\ech_lib.obj: ecdh\ech_lib.c ecdh\ech_locl.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\ech_key.obj: ecdh\ech_key.c ecdh\ech_locl.h ec\ec_lcl.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\stack.obj: stack\stack.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\bn_asm.obj: bn\bn_asm.c bn\bn_lcl.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\bn_kron.obj: bn\bn_kron.c bn\bn_lcl.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\bn_print.obj: bn\bn_print.c bn\bn_lcl.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\bn_mod.obj: bn\bn_mod.c bn\bn_lcl.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\bn_exp.obj: bn\bn_exp.c bn\bn_lcl.h ctm_locl.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\bn_mpi.obj: bn\bn_mpi.c bn\bn_lcl.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\bn_shift.obj: bn\bn_shift.c bn\bn_lcl.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\bn_word.obj: bn\bn_word.c bn\bn_lcl.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\bn_lib.obj: bn\bn_lib.c bn\bn_lcl.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\bn_blind.obj: bn\bn_blind.c bn\bn_lcl.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\bn_depr.obj: bn\bn_depr.c bn\bn_lcl.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\bn_sqrt.obj: bn\bn_sqrt.c bn\bn_lcl.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\bn_gcd.obj: bn\bn_gcd.c bn\bn_lcl.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\bn_nist.obj: bn\bn_nist.c bn\bn_lcl.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\bn_const.obj: bn\bn_const.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\bn_sqr.obj: bn\bn_sqr.c bn\bn_lcl.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\bn_mont.obj: bn\bn_mont.c bn\bn_lcl.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\bn_prime.obj: bn\bn_prime.c bn\bn_lcl.h bn\bn_prime.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\bn_recp.obj: bn\bn_recp.c bn\bn_lcl.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\bn_ctx.obj: bn\bn_ctx.c bn\bn_lcl.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\bn_rand.obj: bn\bn_rand.c bn\bn_lcl.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\bn_exp2.obj: bn\bn_exp2.c bn\bn_lcl.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\bn_add.obj: bn\bn_add.c bn\bn_lcl.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\bn_err.obj: bn\bn_err.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\bn_gf2m.obj: bn\bn_gf2m.c bn\bn_lcl.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\bn_x931p.obj: bn\bn_x931p.c bn\bn_lcl.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\bn_mul.obj: bn\bn_mul.c bn\bn_lcl.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\bn_div.obj: bn\bn_div.c bn\bn_lcl.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\dh_lib.obj: dh\dh_lib.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\dh_key.obj: dh\dh_key.c bn\bn_lcl.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\dh_depr.obj: dh\dh_depr.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\dh_prn.obj: dh\dh_prn.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\dh_err.obj: dh\dh_err.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\dh_pmeth.obj: dh\dh_pmeth.c evp\evp_locl.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\dh_ameth.obj: dh\dh_ameth.c asn1\asn1locl.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\dh_asn1.obj: dh\dh_asn1.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\dh_gen.obj: dh\dh_gen.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\dh_check.obj: dh\dh_check.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\ecs_err.obj: ecdsa\ecs_err.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\ecs_asn1.obj: ecdsa\ecs_asn1.c ecdsa\ecs_locl.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\ecs_sign.obj: ecdsa\ecs_sign.c ecdsa\ecs_locl.h ec\ec_lcl.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\ecs_lib.obj: ecdsa\ecs_lib.c ecdsa\ecs_locl.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\ecs_ossl.obj: ecdsa\ecs_ossl.c bn\bn_lcl.h ecdsa\ecs_locl.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\ecs_vrf.obj: ecdsa\ecs_vrf.c ecdsa\ecs_locl.h ec\ec_lcl.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\cpt_err.obj: cpt_err.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\dsa_gen.obj: dsa\dsa_gen.c bn\bn_lcl.h dsa\dsa_locl.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\dsa_ossl.obj: dsa\dsa_ossl.c bn\bn_lcl.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\dsa_sign.obj: dsa\dsa_sign.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\dsameth.obj: dsa\dsameth.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\dsa_lib.obj: dsa\dsa_lib.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\dsaameth.obj: dsa\dsaameth.c asn1\asn1locl.h bn\bn_lcl.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\dsa_key.obj: dsa\dsa_key.c bn\bn_lcl.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\dsa_depr.obj: dsa\dsa_depr.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\dsa_err.obj: dsa\dsa_err.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\dsa_asn1.obj: dsa\dsa_asn1.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\dsa_vrf.obj: dsa\dsa_vrf.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\dsapmeth.obj: dsa\dsapmeth.c dsa\dsa_locl.h evp\evp_locl.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\dsa_prn.obj: dsa\dsa_prn.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\lhash.obj: lhash\lhash.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\lh_stats.obj: lhash\lh_stats.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\mem_clr.obj: mem_clr.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\sm3.obj: sm3\sm3.c sm3\sm3_locl.h md32comm.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\aes_ctr.obj: aes\aes_ctr.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\aes_misc.obj: aes\aes_misc.c aes\aes_locl.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\aes_cbc.obj: aes\aes_cbc.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\aes_ecb.obj: aes\aes_ecb.c aes\aes_locl.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\x86core.obj: aes\x86core.c aes\aes_locl.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\aes_core.obj: aes\aes_core.c aes\aes_locl.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\aes_wrap.obj: aes\aes_wrap.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\aes_ofb.obj: aes\aes_ofb.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\aes_ige.obj: aes\aes_ige.c aes\aes_locl.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\aes_cfb.obj: aes\aes_cfb.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\ts_asn1.obj: ts\ts_asn1.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\rspprint.obj: ts\rspprint.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\ts_err.obj: ts\ts_err.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\rspsign.obj: ts\rspsign.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\requtils.obj: ts\requtils.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\rspvfy.obj: ts\rspvfy.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\ts_lib.obj: ts\ts_lib.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\vfy_ctx.obj: ts\vfy_ctx.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\ts_conf.obj: ts\ts_conf.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\rsputils.obj: ts\rsputils.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\reqprint.obj: ts\reqprint.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\mem_dbg.obj: mem_dbg.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\streebog.obj: gost\streebog.c gost\gostlocl.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\g341194.obj: gost\g341194.c gost\gostlocl.h md32comm.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\g89pmeth.obj: gost\g89pmeth.c evp\evp_locl.h gost\gostlocl.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\g341001k.obj: gost\g341001k.c gost\gostlocl.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\g89keywr.obj: gost\g89keywr.c gost\gostlocl.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\g341001a.obj: gost\g341001a.c asn1\asn1locl.h gost\gostlocl.h &
 gost\gostasn1.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\g89ameth.obj: gost\g89ameth.c asn1\asn1locl.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\g341001p.obj: gost\g341001p.c gost\gostlocl.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\gostasn1.obj: gost\gostasn1.c gost\gostlocl.h gost\gostasn1.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\g2814789.obj: gost\g2814789.c gost\gostlocl.h md32comm.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\g89param.obj: gost\g89param.c gost\gostlocl.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\g341001.obj: gost\g341001.c bn\bn_lcl.h gost\gostlocl.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\g341001m.obj: gost\g341001m.c evp\evp_locl.h gost\gostlocl.h &
 gost\gostasn1.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\gost_err.obj: gost\gost_err.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\sm4.obj: sm4\sm4.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\cmll_cfb.obj: camellia\cmll_cfb.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\cmll_ctr.obj: camellia\cmll_ctr.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\cmllmisc.obj: camellia\cmllmisc.c camellia\cmlllocl.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\cmll_cbc.obj: camellia\cmll_cbc.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\cmll_ofb.obj: camellia\cmll_ofb.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\cmll_ecb.obj: camellia\cmll_ecb.c camellia\cmlllocl.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\camellia.obj: camellia\camellia.c camellia\cmlllocl.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\ui_err.obj: ui\ui_err.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\ui_lib.obj: ui\ui_lib.c ui\ui_locl.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\uissl.obj: ui\uissl.c ui\ui_locl.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\ui_util.obj: ui\ui_util.c ui\ui_locl.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\rc2ofb64.obj: rc2\rc2ofb64.c rc2\rc2_locl.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\rc2cfb64.obj: rc2\rc2cfb64.c rc2\rc2_locl.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\rc2_ecb.obj: rc2\rc2_ecb.c rc2\rc2_locl.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\rc2_skey.obj: rc2\rc2_skey.c rc2\rc2_locl.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\rc2_cbc.obj: rc2\rc2_cbc.c rc2\rc2_locl.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\rsa_pk1.obj: rsa\rsa_pk1.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\rsa_pss.obj: rsa\rsa_pss.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\rsa_none.obj: rsa\rsa_none.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\rsa_x931.obj: rsa\rsa_x931.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\rsa_err.obj: rsa\rsa_err.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\rsa_depr.obj: rsa\rsa_depr.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\rsa_chk.obj: rsa\rsa_chk.c bn\bn_lcl.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\rsa_sign.obj: rsa\rsa_sign.c rsa\rsa_locl.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\rsa_meth.obj: rsa\rsa_meth.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\rsa_prn.obj: rsa\rsa_prn.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\rsa_gen.obj: rsa\rsa_gen.c bn\bn_lcl.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\rsa_asn1.obj: rsa\rsa_asn1.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\rsaameth.obj: rsa\rsaameth.c asn1\asn1locl.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\rsapmeth.obj: rsa\rsapmeth.c evp\evp_locl.h rsa\rsa_locl.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\rsa_eay.obj: rsa\rsa_eay.c bn\bn_lcl.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\rsa_oaep.obj: rsa\rsa_oaep.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\rsa_crpt.obj: rsa\rsa_crpt.c bn\bn_lcl.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\rsa_lib.obj: rsa\rsa_lib.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\rsa_saos.obj: rsa\rsa_saos.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\cryptlib.obj: cryptlib.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\ec2_mult.obj: ec\ec2_mult.c bn\bn_lcl.h ec\ec_lcl.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\ec2_smpl.obj: ec\ec2_smpl.c ec\ec_lcl.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\ec_key.obj: ec\ec_key.c bn\bn_lcl.h ec\ec_lcl.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\nistputi.obj: ec\nistputi.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\nistz256.obj: ec\nistz256.c ec\ec_lcl.h ec\nistztab.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\ecp_oct.obj: ec\ecp_oct.c ec\ec_lcl.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\eck_prn.obj: ec\eck_prn.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\ec_lib.obj: ec\ec_lib.c ec\ec_lcl.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\ec_cvt.obj: ec\ec_cvt.c ec\ec_lcl.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\nistp521.obj: ec\nistp521.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\nistp256.obj: ec\nistp256.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\ecp_smpl.obj: ec\ecp_smpl.c bn\bn_lcl.h ec\ec_lcl.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\ec_oct.obj: ec\ec_oct.c ec\ec_lcl.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\ec2_oct.obj: ec\ec2_oct.c ec\ec_lcl.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\ec_pmeth.obj: ec\ec_pmeth.c evp\evp_locl.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\ec_mult.obj: ec\ec_mult.c ec\ec_lcl.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\ec_ameth.obj: ec\ec_ameth.c asn1\asn1locl.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\ecp_mont.obj: ec\ecp_mont.c ec\ec_lcl.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\ec_check.obj: ec\ec_check.c ec\ec_lcl.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\nistp224.obj: ec\nistp224.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\ec_err.obj: ec\ec_err.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\ecp_nist.obj: ec\ecp_nist.c ec\ec_lcl.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\ec_kmeth.obj: ec\ec_kmeth.c ec\ec_lcl.h ecdsa\ecs_locl.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\ec_curve.obj: ec\ec_curve.c ec\ec_lcl.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\ec_print.obj: ec\ec_print.c ec\ec_lcl.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\ec_asn1.obj: ec\ec_asn1.c ec\ec_lcl.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\cryptolk.obj: cryptolk.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\dso_err.obj: dso\dso_err.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\dsodlfcn.obj: dso\dsodlfcn.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\dso_null.obj: dso\dso_null.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\dso_ssl.obj: dso\dso_ssl.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\dso_lib.obj: dso\dso_lib.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\m_dss1.obj: evp\m_dss1.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\e_poly.obj: evp\e_poly.c evp\evp_locl.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\evp_lib.obj: evp\evp_lib.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\m_sigver.obj: evp\m_sigver.c evp\evp_locl.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\pmeth_gn.obj: evp\pmeth_gn.c evp\evp_locl.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\evp_pkey.obj: evp\evp_pkey.c asn1\asn1locl.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\bio_enc.obj: evp\bio_enc.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\p_sign.obj: evp\p_sign.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\p_open.obj: evp\p_open.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\evp_pbe.obj: evp\evp_pbe.c evp\evp_locl.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\hmacsha1.obj: evp\hmacsha1.c evp\evp_locl.h ctm_locl.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\e_cast.obj: evp\e_cast.c evp\evp_locl.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\pmeth_fn.obj: evp\pmeth_fn.c evp\evp_locl.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\evp_err.obj: evp\evp_err.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\e_old.obj: evp\e_old.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\p_lib.obj: evp\p_lib.c asn1\asn1locl.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\c_all.obj: evp\c_all.c cryptlib.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\bio_md.obj: evp\bio_md.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\e_rc4.obj: evp\e_rc4.c evp\evp_locl.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\m_ecdsa.obj: evp\m_ecdsa.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\bio_b64.obj: evp\bio_b64.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\e_aes.obj: evp\e_aes.c evp\evp_locl.h modes\modeslcl.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\e_bf.obj: evp\e_bf.c evp\evp_locl.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\e_rc2.obj: evp\e_rc2.c evp\evp_locl.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\e2814789.obj: evp\e2814789.c evp\evp_locl.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\ecamelli.obj: evp\ecamelli.c evp\evp_locl.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\p_dec.obj: evp\p_dec.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\m2814789.obj: evp\m2814789.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\m_sha1.obj: evp\m_sha1.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\m_md5.obj: evp\m_md5.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\evp_key.obj: evp\evp_key.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\e_des.obj: evp\e_des.c evp\evp_locl.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\pmethlib.obj: evp\pmethlib.c asn1\asn1locl.h evp\evp_locl.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\m_null.obj: evp\m_null.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\m_md4.obj: evp\m_md4.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\m_ripemd.obj: evp\m_ripemd.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\digest.obj: evp\digest.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\p_seal.obj: evp\p_seal.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\e_idea.obj: evp\e_idea.c evp\evp_locl.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\m_dss.obj: evp\m_dss.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\evp_enc.obj: evp\evp_enc.c evp\evp_locl.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\encode.obj: evp\encode.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\p_verify.obj: evp\p_verify.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\p5_crpt2.obj: evp\p5_crpt2.c evp\evp_locl.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\mmd5sha1.obj: evp\mmd5sha1.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\e_sm4.obj: evp\e_sm4.c evp\evp_locl.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\e_des3.obj: evp\e_des3.c evp\evp_locl.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\p_enc.obj: evp\p_enc.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\names.obj: evp\names.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\m_sm3.obj: evp\m_sm3.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\e_null.obj: evp\e_null.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\mstreebo.obj: evp\mstreebo.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\m341194.obj: evp\m341194.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\m_wp.obj: evp\m_wp.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\hmac_md5.obj: evp\hmac_md5.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\e_xcbc_d.obj: evp\e_xcbc_d.c evp\evp_locl.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\evp_aead.obj: evp\evp_aead.c evp\evp_locl.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\p5_crpt.obj: evp\p5_crpt.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\e_chacha.obj: evp\e_chacha.c evp\evp_locl.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\bf_cfb64.obj: bf\bf_cfb64.c bf\bf_locl.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\bf_cbc.obj: bf\bf_cbc.c bf\bf_locl.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\bf_enc.obj: bf\bf_enc.c bf\bf_locl.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\bf_ecb.obj: bf\bf_ecb.c bf\bf_locl.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\bf_skey.obj: bf\bf_skey.c bf\bf_locl.h bf\bf_pi.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\bf_ofb64.obj: bf\bf_ofb64.c bf\bf_locl.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\eng_cnf.obj: engine\eng_cnf.c engine\eng_int.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\enopnssl.obj: engine\enopnssl.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\eng_list.obj: engine\eng_list.c cryptlib.h engine\eng_int.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\eng_dyn.obj: engine\eng_dyn.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\eng_pkey.obj: engine\eng_pkey.c engine\eng_int.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\tb_ecdh.obj: engine\tb_ecdh.c engine\eng_int.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\eng_err.obj: engine\eng_err.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\tb_ecdsa.obj: engine\tb_ecdsa.c engine\eng_int.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\eng_lib.obj: engine\eng_lib.c engine\eng_int.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\eng_fat.obj: engine\eng_fat.c engine\eng_int.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\tb_rand.obj: engine\tb_rand.c engine\eng_int.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\tb_store.obj: engine\tb_store.c engine\eng_int.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\eng_all.obj: engine\eng_all.c cryptlib.h engine\eng_int.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\tb_dh.obj: engine\tb_dh.c engine\eng_int.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\eng_init.obj: engine\eng_init.c engine\eng_int.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\tb_eckey.obj: engine\tb_eckey.c engine\eng_int.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\engaesni.obj: engine\engaesni.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\tbpkmeth.obj: engine\tbpkmeth.c engine\eng_int.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\tbdigest.obj: engine\tbdigest.c engine\eng_int.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\tb_dsa.obj: engine\tb_dsa.c engine\eng_int.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\engtable.obj: engine\engtable.c engine\eng_int.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\tb_rsa.obj: engine\tb_rsa.c engine\eng_int.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\tbcipher.obj: engine\tbcipher.c engine\eng_int.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\eng_ctrl.obj: engine\eng_ctrl.c engine\eng_int.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\padlock.obj: engine\padlock.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\tbasnmth.obj: engine\tbasnmth.c engine\eng_int.h asn1\asn1locl.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\x509name.obj: x509\x509name.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\x509_att.obj: x509\x509_att.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\x509_err.obj: x509\x509_err.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\x509_vpm.obj: x509\x509_vpm.c x509\vpm_int.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\x509_txt.obj: x509\x509_txt.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\x509_req.obj: x509\x509_req.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\x509_trs.obj: x509\x509_trs.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\x_all.obj: x509\x_all.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\x509spki.obj: x509\x509spki.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\x509_d2.obj: x509\x509_d2.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\x509_ext.obj: x509\x509_ext.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\x509rset.obj: x509\x509rset.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\x509_def.obj: x509\x509_def.c cryptlib.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\by_dir.obj: x509\by_dir.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\x509_r2x.obj: x509\x509_r2x.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\x509_obj.obj: x509\x509_obj.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\x509_v3.obj: x509\x509_v3.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\by_file.obj: x509\by_file.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\x509_vfy.obj: x509\x509_vfy.c asn1\asn1locl.h x509\vpm_int.h &
 x509\x509_lcl.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\x509_lu.obj: x509\x509_lu.c x509\x509_lcl.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\x509type.obj: x509\x509type.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\x509cset.obj: x509\x509cset.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\by_mem.obj: x509\by_mem.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\x509_cmp.obj: x509\x509_cmp.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\x509_set.obj: x509\x509_set.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\md4_one.obj: md4\md4_one.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\md4_dgst.obj: md4\md4_dgst.c md4\md4_locl.h md32comm.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\cversion.obj: cversion.c cryptlib.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\v3_pku.obj: x509v3\v3_pku.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\v3_pcia.obj: x509v3\v3_pcia.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\v3_ncons.obj: x509v3\v3_ncons.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\v3_genn.obj: x509v3\v3_genn.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\v3_crld.obj: x509v3\v3_crld.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\v3_ia5.obj: x509v3\v3_ia5.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\v3_int.obj: x509v3\v3_int.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\v3_alt.obj: x509v3\v3_alt.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\v3_pci.obj: x509v3\v3_pci.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\pcy_node.obj: x509v3\pcy_node.c x509v3\pcy_int.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\v3_lib.obj: x509v3\v3_lib.c x509v3\ext_dat.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\v3_bitst.obj: x509v3\v3_bitst.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\v3_cpols.obj: x509v3\v3_cpols.c x509v3\pcy_int.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\pcy_map.obj: x509v3\pcy_map.c x509v3\pcy_int.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\v3_bcons.obj: x509v3\v3_bcons.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\v3_extku.obj: x509v3\v3_extku.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\v3_enum.obj: x509v3\v3_enum.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\v3_sxnet.obj: x509v3\v3_sxnet.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\v3_info.obj: x509v3\v3_info.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\v3err.obj: x509v3\v3err.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\v3_conf.obj: x509v3\v3_conf.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\pcy_tree.obj: x509v3\pcy_tree.c x509v3\pcy_int.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\v3_prn.obj: x509v3\v3_prn.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\v3_akey.obj: x509v3\v3_akey.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\v3_utl.obj: x509v3\v3_utl.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\pcy_data.obj: x509v3\pcy_data.c x509v3\pcy_int.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\v3_skey.obj: x509v3\v3_skey.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\v3_pmaps.obj: x509v3\v3_pmaps.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\pcycache.obj: x509v3\pcycache.c x509v3\pcy_int.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\pcy_lib.obj: x509v3\pcy_lib.c x509v3\pcy_int.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\v3_akeya.obj: x509v3\v3_akeya.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\v3_purp.obj: x509v3\v3_purp.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\v3_pcons.obj: x509v3\v3_pcons.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\v3_ocsp.obj: x509v3\v3_ocsp.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\c_rle.obj: comp\c_rle.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\comp_lib.obj: comp\comp_lib.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\c_zlib.obj: comp\c_zlib.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\comp_err.obj: comp\comp_err.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\asn1_gen.obj: asn1\asn1_gen.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\p5_pbev2.obj: asn1\p5_pbev2.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\a_sign.obj: asn1\a_sign.c asn1\asn1locl.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\atime_tm.obj: asn1\atime_tm.c o_time.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\x_pubkey.obj: asn1\x_pubkey.c asn1\asn1locl.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\a_digest.obj: asn1\a_digest.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\t_bitst.obj: asn1\t_bitst.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\a_utf8.obj: asn1\a_utf8.c asn1\asn1locl.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\tasn_typ.obj: asn1\tasn_typ.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\a_mbstr.obj: asn1\a_mbstr.c asn1\asn1locl.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\x_name.obj: asn1\x_name.c asn1\asn1locl.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\i2d_pu.obj: asn1\i2d_pu.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\a_time.obj: asn1\a_time.c o_time.h asn1\asn1locl.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\asn1_par.obj: asn1\asn1_par.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\p8_pkey.obj: asn1\p8_pkey.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\asn1_err.obj: asn1\asn1_err.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\x_info.obj: asn1\x_info.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\x_x509.obj: asn1\x_x509.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\a_bool.obj: asn1\a_bool.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\f_int.obj: asn1\f_int.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\a_print.obj: asn1\a_print.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\t_x509a.obj: asn1\t_x509a.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\a_bitstr.obj: asn1\a_bitstr.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\a_octet.obj: asn1\a_octet.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\x_nx509.obj: asn1\x_nx509.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\a_object.obj: asn1\a_object.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\x_long.obj: asn1\x_long.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\i2d_pr.obj: asn1\i2d_pr.c asn1\asn1locl.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\f_enum.obj: asn1\f_enum.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\t_pkey.obj: asn1\t_pkey.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\asn_pack.obj: asn1\asn_pack.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\a_verify.obj: asn1\a_verify.c asn1\asn1locl.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\f_string.obj: asn1\f_string.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\evp_asn1.obj: asn1\evp_asn1.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\a_d2i_fp.obj: asn1\a_d2i_fp.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\p5_pbe.obj: asn1\p5_pbe.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\a_strex.obj: asn1\a_strex.c asn1\asn1locl.h asn1\charmap.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\t_x509.obj: asn1\t_x509.c asn1\asn1locl.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\asn1_lib.obj: asn1\asn1_lib.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\bio_asn1.obj: asn1\bio_asn1.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\a_enum.obj: asn1\a_enum.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\x_algor.obj: asn1\x_algor.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\d2i_pr.obj: asn1\d2i_pr.c asn1\asn1locl.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\tasn_prn.obj: asn1\tasn_prn.c asn1\asn1locl.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\a_type.obj: asn1\a_type.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\amethlib.obj: asn1\amethlib.c asn1\asn1locl.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\x_bignum.obj: asn1\x_bignum.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\tasn_utl.obj: asn1\tasn_utl.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\tasn_new.obj: asn1\tasn_new.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\tasn_dec.obj: asn1\tasn_dec.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\n_pkey.obj: asn1\n_pkey.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\bio_ndef.obj: asn1\bio_ndef.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\tasn_enc.obj: asn1\tasn_enc.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\x_exten.obj: asn1\x_exten.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\t_crl.obj: asn1\t_crl.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\x_sig.obj: asn1\x_sig.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\t_spki.obj: asn1\t_spki.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\a_strnid.obj: asn1\a_strnid.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\t_req.obj: asn1\t_req.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\x_x509a.obj: asn1\x_x509a.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\x_val.obj: asn1\x_val.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\tasn_fre.obj: asn1\tasn_fre.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\nsseq.obj: asn1\nsseq.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\x_attrib.obj: asn1\x_attrib.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\asn_moid.obj: asn1\asn_moid.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\a_int.obj: asn1\a_int.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\a_i2d_fp.obj: asn1\a_i2d_fp.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\d2i_pu.obj: asn1\d2i_pu.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\x_req.obj: asn1\x_req.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\x_pkey.obj: asn1\x_pkey.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\x_spki.obj: asn1\x_spki.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\x_crl.obj: asn1\x_crl.c asn1\asn1locl.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\asn_mime.obj: asn1\asn_mime.c asn1\asn1locl.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\a_dup.obj: asn1\a_dup.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\c_ofb64.obj: cast\c_ofb64.c cast\cast_lcl.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\c_skey.obj: cast\c_skey.c cast\cast_lcl.h cast\cast_s.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\c_ecb.obj: cast\c_ecb.c cast\cast_lcl.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\c_enc.obj: cast\c_enc.c cast\cast_lcl.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\c_cfb64.obj: cast\c_cfb64.c cast\cast_lcl.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\merged.obj: chacha\merged.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\chacha.obj: chacha\chacha.c chacha\merged.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\hm_ameth.obj: hmac\hm_ameth.c asn1\asn1locl.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\hmac.obj: hmac\hmac.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\hm_pmeth.obj: hmac\hm_pmeth.c evp\evp_locl.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\pk7_lib.obj: pkcs7\pk7_lib.c asn1\asn1locl.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\pk7_doit.obj: pkcs7\pk7_doit.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\pk7_asn1.obj: pkcs7\pk7_asn1.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\pkcs7err.obj: pkcs7\pkcs7err.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\pk7_attr.obj: pkcs7\pk7_attr.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\pk7smime.obj: pkcs7\pk7smime.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\pk7_mime.obj: pkcs7\pk7_mime.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\bio_pk7.obj: pkcs7\bio_pk7.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\md5_one.obj: md5\md5_one.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\md5_dgst.obj: md5\md5_dgst.c md5\md5_locl.h md32comm.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\err_prn.obj: err\err_prn.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\err_all.obj: err\err_all.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\err.obj: err\err.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\conf_api.obj: conf\conf_api.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\conf_def.obj: conf\conf_def.c conf\conf_def.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\conf_err.obj: conf\conf_err.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\conf_mod.obj: conf\conf_mod.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\conf_lib.obj: conf\conf_lib.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\confmall.obj: conf\confmall.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\conf_sap.obj: conf\conf_sap.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\cmac.obj: cmac\cmac.c
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\cm_ameth.obj: cmac\cm_ameth.c asn1\asn1locl.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\cm_pmeth.obj: cmac\cm_pmeth.c evp\evp_locl.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\i_ofb64.obj: idea\i_ofb64.c idea\idea_lcl.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\i_cbc.obj: idea\i_cbc.c idea\idea_lcl.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\i_ecb.obj: idea\i_ecb.c idea\idea_lcl.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\i_skey.obj: idea\i_skey.c idea\idea_lcl.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

$(OBJ)\i_cfb64.obj: idea\i_cfb64.c idea\idea_lcl.h
	*$(CC) $(CFLAGS) -fo=$@ $[@

