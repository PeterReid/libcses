#include "crypto_consts.h"

int cses_crypto_scalarmult_base(unsigned char *q,const unsigned char *n);

int
cses_crypto_secretbox_detached_short(unsigned char *c, unsigned char *mac,
                          const unsigned char *m,
                          unsigned int mlen, const unsigned char *n,
                          const unsigned char *k);

int
cses_crypto_secretbox_open_detached_short(unsigned char *m, const unsigned char *c,
                               const unsigned char *mac,
                               unsigned int clen,
                               const unsigned char *n,
                               const unsigned char *k);


int
cses_crypto_scalarmult_curve25519(unsigned char *mypublic, const unsigned char *secret, const unsigned char *basepoint);

int cses_crypto_scalarmult_curve25519_base(unsigned char *q,const unsigned char *n);

int cses_crypto_stream_salsa20_short(unsigned char *c, unsigned int clen,
                          const unsigned char *n, const unsigned char *k);

int cses_crypto_sign_ed25519_detached_short(unsigned char *sig, unsigned int *siglen,
                         const unsigned char *m, unsigned int mlen,
                         const unsigned char *sk);

int cses_crypto_sign_ed25519_verify_detached_short(const unsigned char *sig,
                                const unsigned char *m,
                                unsigned int mlen,
                                const unsigned char *pk);

int cses_crypto_sign_ed25519_seed_keypair(unsigned char *pk, unsigned char *sk,
                             const unsigned char *seed);
