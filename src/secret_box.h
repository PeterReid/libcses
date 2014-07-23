#include <sodium/crypto_secretbox_xsalsa20poly1305.h>
#include <sodium/crypto_onetimeauth_poly1305.h>

#include "cses.h"

void libcses_secret_box_init(struct libcses_secret_box *, const unsigned char *key);

void libcses_secret_box_encrypt(
  struct libcses_secret_box *box,
  unsigned char *authenticator,
  unsigned char *text, 
  unsigned int text_len
);
int libcses_secret_box_decrypt(
  struct libcses_secret_box *box,
  const unsigned char *authenticator,
  unsigned char *text, unsigned int text_len
);

