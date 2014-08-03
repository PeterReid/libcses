CC=gcc
CFLAGS=-Wall -Wextra -pedantic

SOURCES=src/conn.c src/server.c src/crypter.c src/memzero.c
TEST_SOURCES=src/test/all.c src/test/rng.c

LIBSODIUM=../libsodium

LIBSODIUM_FILES=\
  ( cat \
  src/crypto_prelude.h \
  $(LIBSODIUM)/src/libsodium/include/sodium/utils.h \
  $(LIBSODIUM)/src/libsodium/crypto_verify/16/ref/verify_16.c \
  $(LIBSODIUM)/src/libsodium/crypto_verify/32/ref/verify_32.c \
  $(LIBSODIUM)/src/libsodium/crypto_scalarmult/curve25519/donna_c64/api.h \
  $(LIBSODIUM)/src/libsodium/crypto_scalarmult/curve25519/donna_c64/smult_curve25519_donna_c64.c \
  $(LIBSODIUM)/src/libsodium/crypto_scalarmult/curve25519/donna_c64/base_curve25519_donna_c64.c \
  $(LIBSODIUM)/src/libsodium/include/sodium/crypto_secretbox_xsalsa20poly1305.h \
  $(LIBSODIUM)/src/libsodium/crypto_secretbox/xsalsa20poly1305/ref/api.h \
  $(LIBSODIUM)/src/libsodium/include/sodium/crypto_core_hsalsa20.h \
  $(LIBSODIUM)/src/libsodium/include/sodium/crypto_onetimeauth_poly1305.h \
  $(LIBSODIUM)/src/libsodium/include/sodium/crypto_stream_salsa20.h \
  $(LIBSODIUM)/src/libsodium/include/sodium/crypto_secretbox.h \
  $(LIBSODIUM)/src/libsodium/crypto_secretbox/crypto_secretbox_easy.c \
  $(LIBSODIUM)/src/libsodium/include/sodium/crypto_int32.h \
  $(LIBSODIUM)/src/libsodium/include/sodium/crypto_int64.h \
  $(LIBSODIUM)/src/libsodium/include/sodium/crypto_uint32.h \
  $(LIBSODIUM)/src/libsodium/include/sodium/crypto_uint64.h \
  ; cat \
    $(LIBSODIUM)/src/libsodium/include/sodium/crypto_hash_sha512.h \
    $(LIBSODIUM)/src/libsodium/crypto_hash/sha512/cp/api.h \
    $(LIBSODIUM)/src/libsodium/crypto_hash/sha512/cp/hash_sha512.c \
    | sed 's/SHR/hash_sha512_SHR/g' \
  ; cat \
    $(LIBSODIUM)/src/libsodium/include/sodium/crypto_sign_ed25519.h \
    $(LIBSODIUM)/src/libsodium/crypto_sign/ed25519/ref10/api.h \
    $(LIBSODIUM)/src/libsodium/crypto_sign/ed25519/ref10/fe.h \
    $(LIBSODIUM)/src/libsodium/crypto_sign/ed25519/ref10/ge.h \
    $(LIBSODIUM)/src/libsodium/crypto_sign/ed25519/ref10/fe_0.c \
    $(LIBSODIUM)/src/libsodium/crypto_sign/ed25519/ref10/fe_1.c \
    $(LIBSODIUM)/src/libsodium/crypto_sign/ed25519/ref10/fe_add.c \
    $(LIBSODIUM)/src/libsodium/crypto_sign/ed25519/ref10/fe_cmov.c \
    $(LIBSODIUM)/src/libsodium/crypto_sign/ed25519/ref10/fe_copy.c \
  ; cat \
    $(LIBSODIUM)/src/libsodium/crypto_sign/ed25519/ref10/fe_frombytes.c \
    | sed 's/load_3/fe_frombytes_load_3/g' \
    | sed 's/load_4/fe_frombytes_load_4/g' \
  ; grep -v "}\|return" $(LIBSODIUM)/src/libsodium/crypto_sign/ed25519/ref10/fe_invert.c \
  ; cat $(LIBSODIUM)/src/libsodium/crypto_sign/ed25519/ref10/pow225521.h \
  ; echo "}" \
  ; cat \
    $(LIBSODIUM)/src/libsodium/crypto_sign/ed25519/ref10/fe_isnegative.c \
    $(LIBSODIUM)/src/libsodium/crypto_sign/ed25519/ref10/fe_isnonzero.c \
    $(LIBSODIUM)/src/libsodium/crypto_sign/ed25519/ref10/fe_mul.c \
    $(LIBSODIUM)/src/libsodium/crypto_sign/ed25519/ref10/fe_neg.c \
  ; grep -v "}\|return" $(LIBSODIUM)/src/libsodium/crypto_sign/ed25519/ref10/fe_pow22523.c \
  ; cat $(LIBSODIUM)/src/libsodium/crypto_sign/ed25519/ref10/pow22523.h \
  ; echo "}" \
  ; cat \
    $(LIBSODIUM)/src/libsodium/crypto_sign/ed25519/ref10/fe_sq.c \
    $(LIBSODIUM)/src/libsodium/crypto_sign/ed25519/ref10/fe_sq2.c \
    $(LIBSODIUM)/src/libsodium/crypto_sign/ed25519/ref10/fe_sub.c \
    $(LIBSODIUM)/src/libsodium/crypto_sign/ed25519/ref10/fe_tobytes.c \
  ; grep -v "}\|return" $(LIBSODIUM)/src/libsodium/crypto_sign/ed25519/ref10/ge_add.c \
  ; cat $(LIBSODIUM)/src/libsodium/crypto_sign/ed25519/ref10/ge_add.h \
  ; echo "}" \
  ; cat \
    $(LIBSODIUM)/src/libsodium/crypto_sign/ed25519/ref10/ge_double_scalarmult.c \
    $(LIBSODIUM)/src/libsodium/crypto_sign/ed25519/ref10/ge_frombytes.c \
  ; grep -v "}\|return" $(LIBSODIUM)/src/libsodium/crypto_sign/ed25519/ref10/ge_madd.c \
  ; cat $(LIBSODIUM)/src/libsodium/crypto_sign/ed25519/ref10/ge_madd.h \
  ; echo "}" \
  ; grep -v "}\|return" $(LIBSODIUM)/src/libsodium/crypto_sign/ed25519/ref10/ge_msub.c \
  ; cat $(LIBSODIUM)/src/libsodium/crypto_sign/ed25519/ref10/ge_msub.h \
  ; echo "}" \
  ; cat \
    $(LIBSODIUM)/src/libsodium/crypto_sign/ed25519/ref10/ge_p1p1_to_p2.c \
    $(LIBSODIUM)/src/libsodium/crypto_sign/ed25519/ref10/ge_p1p1_to_p3.c \
    $(LIBSODIUM)/src/libsodium/crypto_sign/ed25519/ref10/ge_p2_0.c \
  ; grep -v "}\|return" $(LIBSODIUM)/src/libsodium/crypto_sign/ed25519/ref10/ge_p2_dbl.c \
  ; cat $(LIBSODIUM)/src/libsodium/crypto_sign/ed25519/ref10/ge_p2_dbl.h \
  ; echo "}" \
  ; cat \
    $(LIBSODIUM)/src/libsodium/crypto_sign/ed25519/ref10/ge_p3_dbl.c \
    $(LIBSODIUM)/src/libsodium/crypto_sign/ed25519/ref10/ge_p3_0.c \
    $(LIBSODIUM)/src/libsodium/crypto_sign/ed25519/ref10/ge_p3_tobytes.c \
    $(LIBSODIUM)/src/libsodium/crypto_sign/ed25519/ref10/ge_p3_to_cached.c \
    $(LIBSODIUM)/src/libsodium/crypto_sign/ed25519/ref10/ge_p3_to_p2.c \
    $(LIBSODIUM)/src/libsodium/crypto_sign/ed25519/ref10/ge_precomp_0.c \
    $(LIBSODIUM)/src/libsodium/crypto_sign/ed25519/ref10/ge_scalarmult_base.c \
  ; grep -v "}\|return" $(LIBSODIUM)/src/libsodium/crypto_sign/ed25519/ref10/ge_sub.c \
  ; cat $(LIBSODIUM)/src/libsodium/crypto_sign/ed25519/ref10/ge_sub.h \
  ; echo "}" \
  ; cat \
    $(LIBSODIUM)/src/libsodium/crypto_sign/ed25519/ref10/ge_tobytes.c \
    $(LIBSODIUM)/src/libsodium/crypto_sign/ed25519/ref10/keypair.c \
  ; cat \
    $(LIBSODIUM)/src/libsodium/crypto_sign/ed25519/ref10/sc_reduce.c \
    | sed 's/load_3/sc_reduce_load_3/g' \
    | sed 's/load_4/sc_reduce_load_4/g' \
  ; cat \
    $(LIBSODIUM)/src/libsodium/crypto_sign/ed25519/ref10/sc_muladd.c \
    | sed 's/load_3/sc_muladd_load_3/g' \
    | sed 's/load_4/sc_muladd_load_4/g' \
  ; cat \
    $(LIBSODIUM)/src/libsodium/crypto_sign/ed25519/ref10/sign.c \
    $(LIBSODIUM)/src/libsodium/crypto_sign/ed25519/ref10/open.c \
  ; cat \
    $(LIBSODIUM)/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna.h \
    $(LIBSODIUM)/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna64.h \
    $(LIBSODIUM)/src/libsodium/crypto_onetimeauth/poly1305/donna/auth_poly1305_donna.c \
    $(LIBSODIUM)/src/libsodium/crypto_onetimeauth/poly1305/donna/verify_poly1305_donna.c \
    | sed 's/U64TO8/poly1305_U64TO8/g' \
    | sed 's/U8TO64/poly1305_U8TO64/g' \
  ; cat \
    $(LIBSODIUM)/src/libsodium/crypto_core/hsalsa20/ref2/api.h \
    $(LIBSODIUM)/src/libsodium/crypto_core/hsalsa20/ref2/core_hsalsa20.c \
    src/undef_core.h \
    | sed 's/rotate/core_hsalsa20_rotate/g' \
    | sed 's/store_littleendian/core_hsalsa20_store_littleendian/g' \
    | sed 's/load_littleendian/core_hsalsa20_load_littleendian/g' \
  ; cat \
    $(LIBSODIUM)/src/libsodium/crypto_core/salsa20/ref/api.h \
    $(LIBSODIUM)/src/libsodium/crypto_core/salsa20/ref/core_salsa20.c \
    src/undef_core.h \
  ; cat \
    $(LIBSODIUM)/src/libsodium/crypto_stream/salsa20/ref/api.h \
    $(LIBSODIUM)/src/libsodium/crypto_stream/salsa20/ref/stream_salsa20_ref.c \
    | sed 's/sigma/stream_salsa20_sigma/g' \
  ; cat \
    $(LIBSODIUM)/src/libsodium/crypto_stream/salsa20/ref/api.h \
    $(LIBSODIUM)/src/libsodium/crypto_stream/salsa20/ref/xor_salsa20_ref.c \
    $(LIBSODIUM)/src/libsodium/crypto_stream/salsa20/stream_salsa20_api.c \
    | sed 's/sigma/xor_salsa20_sigma/g' \
  ; cat \
    src/crypto_short.c \
  )


all: test

crypto:
	$(LIBSODIUM_FILES) | sed 's/crypto_/cses_crypto_/g' | sed '/# *include "/c\' > build/crypto.c
	gcc -DHAVE_TI_MODE -c build/crypto.c

test: crypto
	gcc $(CFLAGS) -g -o tester -I src/include $(SOURCES) $(TEST_SOURCES) crypto.o -lsodium

valgrind: test
	valgrind --tool=memcheck --leak-check=yes --show-reachable=yes --num-callers=20 --track-fds=yes ./tester

