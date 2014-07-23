#include <sodium/crypto_sign_ed25519.h>
#include <string.h>
#include <assert.h>

#include "cses.h"

void libcses_server_init(
  struct libcses_server *server,
  const unsigned char *secret
){
  assert(crypto_sign_ed25519_SEEDBYTES==32);
  memset(server, 0, sizeof *server);
  crypto_sign_ed25519_seed_keypair(server->public_key, server->secret_key, secret);
}

