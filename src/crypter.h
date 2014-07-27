#include <sodium/crypto_secretbox_xsalsa20poly1305.h>
#include <sodium/crypto_onetimeauth_poly1305.h>

#include "cses.h"

void libcses_crypter_init(struct libcses_crypter *, const unsigned char *key);

void libcses_crypter_encrypt(
  struct libcses_crypter *box,
  unsigned char *authenticator,
  unsigned char *text, 
  unsigned int text_len
);
int libcses_crypter_decrypt(
  struct libcses_crypter *box,
  const unsigned char *authenticator,
  unsigned char *text, unsigned int text_len
);

