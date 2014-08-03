#include <string.h>
#include <assert.h>

#include "cses.h"
#include "crypto.h"

void libcses_server_init(
  struct libcses_server *server,
  const unsigned char *secret32
){
  assert(libcses_sign_ed25519_SEEDBYTES==32);
  assert(libcses_sign_ed25519_PUBLICKEYBYTES == sizeof server->public_key);
  assert(libcses_sign_ed25519_SECRETKEYBYTES == sizeof server->secret_key);

  memset(server, 0, sizeof *server);
  libcses_sign_ed25519_seed_keypair(server->public_key, server->secret_key, secret32);
}

