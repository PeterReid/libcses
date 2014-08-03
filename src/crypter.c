
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "cses_internal.h"
#include "crypto.h"

#define AUTHENTICATOR_BYTES libcses_onetimeauth_poly1305_BYTES

LIBCSES_PRIVATE void libcses_crypter_init(
  struct libcses_crypter *box,
  const unsigned char *key
){
  memcpy(box->key, key, sizeof(box->key));
  memset(box->nonce, 0, sizeof(box->nonce));
}

static void libcses_crypter_next_nonce(struct libcses_crypter *box){
  unsigned int u = 1;
  unsigned int i;
  for( i=0; i<sizeof(box->nonce); i++ ){
    u += box->nonce[i];
    box->nonce[i] = u;
    u >>= 8;
  }
}

LIBCSES_PRIVATE void libcses_crypter_encrypt(
  struct libcses_crypter *box,
  unsigned char *authenticator,
  unsigned char *text, 
  unsigned int text_len
){
  /* libsodium does not provide a declaration for the specifically xsalsa20poly1305 version of this */
  libcses_secretbox_xsalsa20poly1305_detached_short(text, authenticator, text, text_len, box->nonce, box->key);
  libcses_crypter_next_nonce(box);
}

LIBCSES_PRIVATE int libcses_crypter_decrypt(
  struct libcses_crypter *box,
  const unsigned char *authenticator,
  unsigned char *text, unsigned int text_len
){
  /* libsodium does not provide a declaration for the specifically chacha20poly1305 version of this */
  int res = libcses_secretbox_xsalsa20poly1305_open_detached_short(text, text, authenticator, text_len, box->nonce, box->key);
  libcses_crypter_next_nonce(box);
  return res;
}

