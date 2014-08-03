
int amal_crypto_scalarmult_base(unsigned char *q,const unsigned char *n);

int
amal_crypto_secretbox_detached(unsigned char *c, unsigned char *mac,
                          const unsigned char *m,
                          unsigned long long mlen, const unsigned char *n,
                          const unsigned char *k);

int
amal_crypto_secretbox_open_detached(unsigned char *m, const unsigned char *c,
                               const unsigned char *mac,
                               unsigned long long clen,
                               const unsigned char *n,
                               const unsigned char *k);


int
amal_crypto_scalarmult_curve25519(unsigned char *mypublic, const unsigned char *secret, const unsigned char *basepoint);

int amal_crypto_scalarmult_curve25519_base(unsigned char *q,const unsigned char *n);

int amal_crypto_stream_salsa20(unsigned char *c, unsigned long long clen,
                          const unsigned char *n, const unsigned char *k);

int amal_crypto_sign_ed25519_detached(unsigned char *sig, unsigned long long *siglen,
                         const unsigned char *m, unsigned long long mlen,
                         const unsigned char *sk);

int amal_crypto_sign_ed25519_verify_detached(const unsigned char *sig,
                                const unsigned char *m,
                                unsigned long long mlen,
                                const unsigned char *pk);

