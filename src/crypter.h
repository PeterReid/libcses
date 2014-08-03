#include "cses.h"
#include "cses_internal.h"

LIBCSES_PRIVATE void libcses_crypter_init(struct libcses_crypter *, const unsigned char *key);

LIBCSES_PRIVATE void libcses_crypter_encrypt(
  struct libcses_crypter *box,
  unsigned char *authenticator,
  unsigned char *text, 
  unsigned int text_len
);
LIBCSES_PRIVATE int libcses_crypter_decrypt(
  struct libcses_crypter *box,
  const unsigned char *authenticator,
  unsigned char *text, unsigned int text_len
);

