#include <string.h>
#include <nacl/crypto_secretbox_xsalsa20poly1305.h>
#include <nacl/crypto_onetimeauth_poly1305.h>

#define LIBCSES_SECRET_BOX_KEY_BYTES crypto_secretbox_xsalsa20poly1305_KEYBYTES
#define LIBCSES_SECRET_BOX_NONCE_BYTES crypto_secretbox_xsalsa20poly1305_NONCEBYTES
#define LIBCSES_SECRET_BOX_AUTHENTICATOR_BYTES crypto_onetimeauth_poly1305_BYTES

struct libcses_secret_box{
  unsigned char key[crypto_secretbox_xsalsa20poly1305_KEYBYTES];
  unsigned char nonce[crypto_secretbox_xsalsa20poly1305_NONCEBYTES];
};

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

