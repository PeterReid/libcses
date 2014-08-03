CC=gcc
CFLAGS=-Wall -Wextra -pedantic

SOURCES=src/conn.c src/server.c src/crypter.c
TEST_SOURCES=src/test/all.c src/test/rng.c

LIBSODIUM=../libsodium
SIGNPATH=$(LIBSODIUM)/src/libsodium/crypto_sign/ed25519/ref10

libsodium_amalgamation:
	( cat \
  src/crypto_prelude.h \
  $(LIBSODIUM)/src/libsodium/include/sodium/utils.h \
  $(LIBSODIUM)/src/libsodium/sodium/utils.c \
  $(LIBSODIUM)/src/libsodium/crypto_verify/16/ref/verify_16.c \
  $(LIBSODIUM)/src/libsodium/crypto_verify/32/ref/verify_32.c \
  $(LIBSODIUM)/src/libsodium/crypto_scalarmult/curve25519/donna_c64/api.h \
  $(LIBSODIUM)/src/libsodium/crypto_scalarmult/curve25519/donna_c64/smult_curve25519_donna_c64.c \
  $(LIBSODIUM)/src/libsodium/crypto_scalarmult/curve25519/donna_c64/base_curve25519_donna_c64.c \
  $(LIBSODIUM)/src/libsodium/include/sodium/crypto_secretbox_xsalsa20poly1305.h \
  $(LIBSODIUM)/src/libsodium/crypto_secretbox/xsalsa20poly1305/ref/api.h \
  ; echo "#define crypto_secretbox_detached crypto_secretbox_xsalsa20poly1305_detached" \
  ; echo "#define crypto_secretbox_open_detached crypto_secretbox_xsalsa20poly1305_open_detached" \
  ; cat \
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
    $(SIGNPATH)/api.h \
    $(SIGNPATH)/fe.h \
    $(SIGNPATH)/ge.h \
    $(SIGNPATH)/fe_0.c \
    $(SIGNPATH)/fe_1.c \
    $(SIGNPATH)/fe_add.c \
    $(SIGNPATH)/fe_cmov.c \
    $(SIGNPATH)/fe_copy.c \
  ; cat \
    $(SIGNPATH)/fe_frombytes.c \
    | sed 's/load_3/fe_frombytes_load_3/g' \
    | sed 's/load_4/fe_frombytes_load_4/g' \
  ; cat $(SIGNPATH)/fe_invert.c \
    | awk '/#include "pow225521.h"/{system("cat $(SIGNPATH)/pow225521.h");next}1' \
  ; cat \
    $(SIGNPATH)/fe_isnegative.c \
    $(SIGNPATH)/fe_isnonzero.c \
    $(SIGNPATH)/fe_mul.c \
    $(SIGNPATH)/fe_neg.c \
  ; cat $(SIGNPATH)/fe_pow22523.c \
    | awk '/#include "pow22523.h"/{system("cat $(SIGNPATH)/pow22523.h");next}1' \
  ; cat \
    $(SIGNPATH)/fe_sq.c \
    $(SIGNPATH)/fe_sq2.c \
    $(SIGNPATH)/fe_sub.c \
    $(SIGNPATH)/fe_tobytes.c \
  ; cat $(SIGNPATH)/ge_add.c \
    | awk '/#include "ge_add.h"/{system("cat $(SIGNPATH)/ge_add.h");next}1' \
  ; cat $(SIGNPATH)/ge_double_scalarmult.c \
    | awk '/#include "base2.h"/{system("cat $(SIGNPATH)/base2.h");next}1' \
  ; cat \
    $(SIGNPATH)/ge_frombytes.c \
    | awk '/#include "d.h"/{system("cat $(SIGNPATH)/d.h");next}1' \
    | awk '/#include "sqrtm1.h"/{system("cat $(SIGNPATH)/sqrtm1.h");next}1' \
  ; cat $(SIGNPATH)/ge_madd.c \
    | awk '/#include "ge_madd.h"/{system("cat $(SIGNPATH)/ge_madd.h");next}1' \
  ; cat $(SIGNPATH)/ge_msub.c \
    | awk '/#include "ge_msub.h"/{system("cat $(SIGNPATH)/ge_msub.h");next}1' \
  ; cat \
    $(SIGNPATH)/ge_p1p1_to_p2.c \
    $(SIGNPATH)/ge_p1p1_to_p3.c \
    $(SIGNPATH)/ge_p2_0.c \
  ; cat $(SIGNPATH)/ge_p2_dbl.c \
    | awk '/#include "ge_p2_dbl.h"/{system("cat $(SIGNPATH)/ge_p2_dbl.h");next}1' \
  ; cat \
    $(SIGNPATH)/ge_p3_dbl.c \
    $(SIGNPATH)/ge_p3_0.c \
    $(SIGNPATH)/ge_p3_tobytes.c \
  ; cat $(SIGNPATH)/ge_p3_to_cached.c \
    | awk '/#include "d2.h"/{system("cat $(SIGNPATH)/d2.h");next}1' \
  ; cat \
    $(SIGNPATH)/ge_p3_to_p2.c \
    $(SIGNPATH)/ge_precomp_0.c \
  ; cat $(SIGNPATH)/ge_scalarmult_base.c \
    | awk '/#include "base.h"/{system("cat $(SIGNPATH)/base.h");next}1' \
  ; cat $(SIGNPATH)/ge_sub.c \
    | awk '/#include "ge_sub.h"/{system("cat $(SIGNPATH)/ge_sub.h");next}1' \
  ; cat \
    $(SIGNPATH)/ge_tobytes.c \
  ; cat \
    $(SIGNPATH)/sc_reduce.c \
    | sed 's/load_3/sc_reduce_load_3/g' \
    | sed 's/load_4/sc_reduce_load_4/g' \
  ; cat \
    $(SIGNPATH)/sc_muladd.c \
    | sed 's/load_3/sc_muladd_load_3/g' \
    | sed 's/load_4/sc_muladd_load_4/g' \
  ; cat \
    $(SIGNPATH)/sign.c \
    $(SIGNPATH)/open.c \
  ; cat \
    $(SIGNPATH)/keypair.c \
    | sed 's/int crypto_sign_keypair/static int unused_keypair/g' \
    | sed 's/randombytes//g' \
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
    src/crypto_suffix.c \
  ) \
  | sed 's/crypto_/libcses_/g' | sed '/# *include "/c\' \
  | sed 's/^int/LIBCSES_PRIVATE int/g' \
  | sed 's/^size_t/LIBCSES_PRIVATE size_t/g' \
  | sed 's/^void/LIBCSES_PRIVATE void/g' \
  | sed 's/^struct/static struct/g' \
  | sed 's/^char \*/LIBCSES_PRIVATE char */g' \
  | sed 's/^unsigned char \*/LIBCSES_PRIVATE unsigned char */g' \
  | sed 's/^const char \*/LIBCSES_PRIVATE const char */g' \
  | sed 's/extern void/static void/g' \
  | sed 's/extern int/static int/g' \
  | sed 's/extern struct/static struct/g' \
  > build/crypto.c

crypto_consts:
	cat \
	  $(LIBSODIUM)/src/libsodium/include/sodium/crypto_scalarmult_curve25519.h \
	  $(LIBSODIUM)/src/libsodium/include/sodium/crypto_sign_ed25519.h \
	  $(LIBSODIUM)/src/libsodium/include/sodium/crypto_stream_salsa20.h \
	| grep "#define crypto_.* [0-9]" \
	| sed 's/crypto_/libcses_/g' \
	> build/crypto_consts.h

all: test

crypto: libsodium_amalgamation
	gcc -DHAVE_TI_MODE -c build/crypto.c

amalgamation: libsodium_amalgamation
	(echo "#include \"cses.h\"" \
        ; cat \
	    build/crypto.c \
	    build/crypto_consts.h \
            src/cses_internal.h \
	    src/conn.c \
	    src/crypter.c \
	    src/server.c \
          | sed '/# *include "/c\' \
        ) \
	> build/cses.c

cses.o: amalgamation crypto_consts
	gcc -DHAVE_TI_MODE -c -DLIBCSES_AMALGAMATION -o build/cses.o build/cses.c

lib: cses.o
	ar -rcs cses.a build/cses.o

test: crypto crypto_consts
	gcc $(CFLAGS) -g -o tester -I src/include -I build $(SOURCES) $(TEST_SOURCES) crypto.o -lsodium



valgrind: test
	valgrind --tool=memcheck --leak-check=yes --show-reachable=yes --num-callers=20 --track-fds=yes ./tester

