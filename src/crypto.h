#include "crypto_consts.h"

int libcses_scalarmult_base(unsigned char *q,const unsigned char *n);

int
libcses_secretbox_xsalsa20poly1305_detached_short(unsigned char *c, unsigned char *mac,
                          const unsigned char *m,
                          unsigned int mlen, const unsigned char *n,
                          const unsigned char *k);

int
libcses_secretbox_xsalsa20poly1305_open_detached_short(unsigned char *m, const unsigned char *c,
                               const unsigned char *mac,
                               unsigned int clen,
                               const unsigned char *n,
                               const unsigned char *k);


int
libcses_scalarmult_curve25519(unsigned char *mypublic, const unsigned char *secret, const unsigned char *basepoint);

int libcses_scalarmult_curve25519_base(unsigned char *q,const unsigned char *n);

int libcses_stream_salsa20_short(unsigned char *c, unsigned int clen,
                          const unsigned char *n, const unsigned char *k);

int libcses_sign_ed25519_detached_short(unsigned char *sig, unsigned int *siglen,
                         const unsigned char *m, unsigned int mlen,
                         const unsigned char *sk);

int libcses_sign_ed25519_verify_detached_short(const unsigned char *sig,
                                const unsigned char *m,
                                unsigned int mlen,
                                const unsigned char *pk);

int libcses_sign_ed25519_seed_keypair(unsigned char *pk, unsigned char *sk,
                             const unsigned char *seed);

void libcses_memzero(void * const pnt, const size_t len);
