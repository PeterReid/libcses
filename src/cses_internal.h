
#ifndef LIBCSES_PRIVATE
#define LIBCSES_PRIVATE
#endif

#include "crypto_consts.h"
#include "cses.h"

/* Legal values of libcses_conn.state */
#define LIBCSES_CONN_SENDING_CLIENT_HANDSHAKE 1
#define LIBCSES_CONN_AWAITING_CLIENT_HANDSHAKE 2
#define LIBCSES_CONN_SENDING_SERVER_HANDSHAKE 3
#define LIBCSES_CONN_AWAITING_SERVER_HANDSHAKE 4
#define LIBCSES_CONN_VALIDATING_IDENTITY 5
#define LIBCSES_CONN_READING_LENGTH 6
#define LIBCSES_CONN_READING_DATA 7
#define LIBCSES_CONN_COPYING_PLAINTEXT 8
#define LIBCSES_CONN_CORRUPT 9

#define KEY_EXCHANGE_PUBLIC_BYTES 32
#define KEY_EXCHANGE_SECRET_BYTES 32
#define SERVER_PUBLIC_IDENTITY_BYTES 32

/*** Server handshake ***/
/* sizes */
#define SH_STATUS_BYTES 1
#define SH_IDENTITY_BYTES cses_crypto_sign_ed25519_PUBLICKEYBYTES
#define SH_EXCHANGE_BYTES cses_crypto_scalarmult_curve25519_SCALARBYTES 
#define SH_SIGNATURE_BYTES cses_crypto_sign_ed25519_BYTES
/* offsets */
#define SH_STATUS_OFFSET     0
#define SH_IDENTITY_OFFSET (SH_STATUS_OFFSET    + SH_STATUS_BYTES)
#define SH_EXCHANGE_OFFSET  (SH_IDENTITY_OFFSET  + SH_IDENTITY_BYTES)
#define SH_SIGNATURE_OFFSET (SH_EXCHANGE_OFFSET  + SH_EXCHANGE_BYTES)
#define SH_BYTES            (SH_SIGNATURE_OFFSET + SH_SIGNATURE_BYTES)

/*** Client handshake ***/
#define HANDSHAKE_MAGIC "cses_wip"
/* sizes */
#define CH_MAGIC_BYTES 8
#define CH_EXCHANGE_BYTES cses_crypto_scalarmult_curve25519_SCALARBYTES
/* offsets */
#define CH_MAGIC_OFFSET     0
#define CH_EXCHANGE_OFFSET (CH_MAGIC_OFFSET    + CH_MAGIC_BYTES)
#define CH_BYTES           (CH_EXCHANGE_OFFSET + CH_EXCHANGE_BYTES)


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
