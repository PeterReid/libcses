/* The hyper-pedantic options we pass to gcc do not allow unsigned long longs.
** So, we wrap the functions that take unsigned long longs with variants that
** take unsigned ints.
*/

int crypto_secretbox_xsalsa20poly1305_detached_short(
  unsigned char *c,
  unsigned char *mac,
  const unsigned char *m, unsigned int mlen,
  const unsigned char *n,
  const unsigned char *k
){
  crypto_secretbox_xsalsa20poly1305_detached(c, mac, m, mlen, n, k);
}

int crypto_secretbox_xsalsa20poly1305_open_detached_short(
  unsigned char *m,
  const unsigned char *c,
  const unsigned char *mac,
  unsigned int clen,
  const unsigned char *n,
  const unsigned char *k
){
  crypto_secretbox_xsalsa20poly1305_open_detached(m, c, mac, clen, n, k);
}

int crypto_stream_salsa20_short(
  unsigned char *c, unsigned int clen,
  const unsigned char *n,
  const unsigned char *k
){
  crypto_stream_salsa20(c, clen, n, k);
}

int crypto_sign_ed25519_detached_short(
  unsigned char *sig,
  unsigned int *siglen,
  const unsigned char *m, unsigned int mlen,
  const unsigned char *sk
){
  unsigned long long long_siglen = 0;
  crypto_sign_ed25519_detached(sig, &long_siglen, m, mlen, sk);
  if( siglen ) *siglen = (unsigned int)long_siglen;
}

int crypto_sign_ed25519_verify_detached_short(
  const unsigned char *sig,
  const unsigned char *m,
  unsigned int mlen,
  const unsigned char *pk
){
  crypto_sign_ed25519_verify_detached(sig, m, mlen, pk);
}

/* The "exported" comment here suppresses the sed pass in the makefile that would
** otherwise make this not exported from the library; it checks for certain
** line beginnings. */
/*exported*/ void libcses_memzero(void * const pnt, const size_t len){
  sodium_memzero(pnt, len);
}

