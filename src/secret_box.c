#include "secret_box.h"

#include <sodium/crypto_verify_16.h>
#include <sodium/crypto_onetimeauth_poly1305.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "salsa.h"

#define AUTHENTICATOR_BYTES crypto_onetimeauth_poly1305_BYTES

void libcses_secret_box_init(
  struct libcses_secret_box *box,
  const unsigned char *key
){
  memcpy(box->key, key, sizeof(box->key));
  memset(box->nonce, 0, sizeof(box->nonce));
}

static void libcses_secret_box_next_nonce(struct libcses_secret_box *box){
  unsigned int u = 1;
  int i;
  for( i=0; i<sizeof(box->nonce); i++ ){
    u += box->nonce[i];
    box->nonce[i] = u;
    u >>= 8;
  }
}

void libcses_secret_box_encrypt(
  struct libcses_secret_box *box,
  unsigned char *authenticator,
  unsigned char *text, 
  unsigned int text_len
){
  unsigned char subkey[32];
  unsigned char block0[64];
  unsigned int i;
  libcses_xsalsa20_subkey(subkey, box->nonce, box->key);

  memset(block0, 0, 64);
  libcses_salsa20_xor_ic(block0, 64, box->nonce + 16, 0, subkey);

  for( i=0; i<text_len && i<32; i++ ){
    text[i] ^= block0[32 + i];
  }

  libcses_salsa20_xor_ic(text+i,text_len-i, box->nonce + 16, 1, subkey);

  crypto_onetimeauth_poly1305(authenticator, text, text_len, block0);
  libcses_secret_box_next_nonce(box);
}

int libcses_secret_box_decrypt(
  struct libcses_secret_box *box,
  const unsigned char *authenticator,
  unsigned char *text, unsigned int text_len
){
  unsigned char subkey[32];
  unsigned char correct_authenticator[LIBCSES_SECRET_BOX_AUTHENTICATOR_BYTES];
  int i;
  unsigned char block0[64];

  libcses_xsalsa20_subkey(subkey,box->nonce,box->key);
  memset(block0, 0, 64);
  libcses_salsa20_xor_ic(block0, 64, box->nonce + 16, 0, subkey);

  crypto_onetimeauth_poly1305(correct_authenticator, text, text_len, block0);

  for( i=0; i<text_len && i<32; i++ ){
    text[i] ^= block0[32 + i];
  }
  
  libcses_salsa20_xor_ic(text+i,text_len-i, box->nonce + 16, 1, subkey);
  
  libcses_secret_box_next_nonce(box);
  return crypto_verify_16(correct_authenticator, authenticator);
}

