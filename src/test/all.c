#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cses.h"

#include "../crypter.h"
#include "../cses_internal.h"

void test_equality(const char *message, const unsigned char *x, const unsigned char *y, unsigned int len){
  if( memcmp(x, y, len) ){
    printf("Test failure: %s\n", message);
  }
}

void test_equality_int(const char *message, int actual, int expected){
  if( expected!=actual ){
    printf("Test failure: %s (expected %d, got %d)\n", message, expected, actual);
  }
}

void crypter_nonce_incrementing(){
  struct libcses_crypter b;
  unsigned char key[LIBCSES_SECRET_BOX_KEY_BYTES] = {
    0x6c, 0x9c, 0xae, 0x48, 0x5b, 0x19, 0x0e, 0x97, 0xa8, 0xec, 0x87, 0x3f, 0xf1, 0xec, 0xba, 0x71, 
    0xe3, 0xba, 0xd8, 0xbb, 0xc4, 0xf5, 0xda, 0x83, 0xe6, 0x69, 0xdf, 0xdd, 0x74, 0xa3, 0xfd, 0x0e, 
  };
  unsigned char expected_nonce[LIBCSES_SECRET_BOX_NONCE_BYTES];
  unsigned char authenticator[LIBCSES_SECRET_BOX_AUTHENTICATOR_BYTES];
  unsigned char text[10];

  memset(expected_nonce, 0, sizeof expected_nonce);
  memset(text, 0, sizeof text);
  libcses_crypter_init(&b, key);
 
  /* Start with a 0 nonce */
  test_equality("initial nonce", expected_nonce, b.nonce, sizeof expected_nonce);

  /* Check that the first increment works */
  libcses_crypter_encrypt(&b, authenticator, text, sizeof text);
  expected_nonce[0] = 1;
  test_equality("nonce after one encryption", expected_nonce, b.nonce, sizeof expected_nonce);

  /* Set up for having to carry the increment over several bytes */ 
  memset(expected_nonce, 0, 11);
  memset(b.nonce, 0xff, 11);
  b.nonce[11] = 46;
  expected_nonce[11] = 47;
  b.nonce[18] = 101;
  expected_nonce[18] = 101;

  libcses_crypter_encrypt(&b, authenticator, text, sizeof text);
  test_equality("nonce after carry", expected_nonce, b.nonce, sizeof expected_nonce);
}

static void populate(unsigned char *dest, int len, int x){
  int i;
  for( i=0; i<len; i++ ){
    dest[i] = (unsigned char)(i*x);
  }
}

void simple_exchange(){
  struct libcses_server server;
  struct libcses_conn cconn;
  struct libcses_conn sconn;
  unsigned char server_secret[LIBCSES_SERVER_SECRET_BYTES];
  unsigned char ciphertext_s_to_c[500];
  unsigned char ciphertext_c_to_s[500];
  unsigned char plaintext_for_server[400];
  unsigned char plaintext_for_client[300];
  unsigned char plaintext_from_server[800];
  unsigned char plaintext_from_client[800];
  unsigned char server_session_randomness[32];
  unsigned char client_session_randomness[32];
  int res;
  int c_plaintext_written = 0;
  int c_plaintext_read = 0;
  int c_ciphertext_written = 0;
  int c_ciphertext_read = 0;
  int s_plaintext_written = 0;
  int s_plaintext_read = 0;
  int s_ciphertext_written = 0;
  int s_ciphertext_read = 0;

  populate(server_secret, sizeof server_secret, 3);
  populate(plaintext_for_server, sizeof plaintext_for_server, 5);
  populate(plaintext_for_client, sizeof plaintext_for_client, 7);
  populate(server_session_randomness, sizeof server_session_randomness, 11);
  populate(client_session_randomness, sizeof client_session_randomness, 13);

  libcses_server_init(&server, server_secret);
  libcses_conn_server_init(&sconn, &server, server_session_randomness);
  libcses_conn_client_init(&cconn, client_session_randomness);

  res = libcses_conn_interact(&cconn,
    plaintext_for_server, sizeof plaintext_for_server, &c_plaintext_read,
    0, 0, 0,
    ciphertext_c_to_s, sizeof ciphertext_c_to_s, &c_ciphertext_written,
    plaintext_from_server, sizeof plaintext_from_server, &c_plaintext_written);
  test_equality_int("client handshake send result", res, LIBCSES_OK);
  test_equality_int("client handshake send - plaintext read", c_plaintext_read, 0);
  test_equality_int("client handshake send - ciphertext written", c_ciphertext_written, 40);
  test_equality_int("client handshake send - plaintext written", c_plaintext_written, 0);
  test_equality_int("client handshake send - ciphertext read", c_ciphertext_read, 0);

  res = libcses_conn_interact(&sconn,
    plaintext_for_client, 300, &s_plaintext_read,
    ciphertext_c_to_s, 40, &s_ciphertext_read,
    ciphertext_s_to_c, 500, &s_ciphertext_written,
    plaintext_from_client, 800, &s_plaintext_written);
  test_equality_int("server handshake+300 -- result", res, LIBCSES_OK);
  test_equality_int("server handshake+300 -- plaintext read", s_plaintext_read, 300);
  test_equality_int("server handshake+300 -- ciphertext written", s_ciphertext_written, 300 + SEGMENT_OVERHEAD + SH_BYTES);
  test_equality_int("server handshake+300 -- ciphertext read", s_ciphertext_read, 40);
  test_equality_int("server handshake+300 -- plaintext written", s_plaintext_written, 0);

  // Receive everything they sent, but have only a small buffer for plaintext out
  c_ciphertext_written = 0;
  res = libcses_conn_interact(&cconn,
    plaintext_for_server, 400, &c_plaintext_read,
    ciphertext_s_to_c, 300+SEGMENT_OVERHEAD+SH_BYTES, &c_ciphertext_read,
    ciphertext_c_to_s, sizeof ciphertext_c_to_s, &c_ciphertext_written,
    plaintext_from_server, 134, &c_plaintext_written);
  test_equality_int("client recv1 -- result", res, LIBCSES_OK);
  test_equality_int("client recv1 -- plaintext read", c_plaintext_read, 400);
  test_equality_int("client recv1 -- plaintext written", c_plaintext_written, 134);
  test_equality_int("client recv1 -- ciphertext read", c_ciphertext_read, 300+SEGMENT_OVERHEAD+SH_BYTES);
  test_equality_int("client recv1 -- ciphertext written", c_ciphertext_written, 400+SEGMENT_OVERHEAD);
 
  // Open up some more plaintext-in-buffer on the client
  res = libcses_conn_interact(&cconn,
    0, 0, 0,
    0, 0, 0,
    0, 0, 0,
    plaintext_from_server, 301, &c_plaintext_written);
  test_equality_int("client recv2 -- result", res, LIBCSES_OK);
  test_equality_int("client recv2 -- plaintext_written", c_plaintext_written, 300);

  // Receive the client message on the server
  s_plaintext_read = 0;
  s_ciphertext_read = 0;
  s_ciphertext_written = 0;
  s_plaintext_written = 0;
  res = libcses_conn_interact(&sconn,
    plaintext_for_client+300, 0, &s_plaintext_read,
    ciphertext_c_to_s, 400+SEGMENT_OVERHEAD, &s_ciphertext_read,
    ciphertext_s_to_c, sizeof ciphertext_s_to_c, &s_ciphertext_written,
    plaintext_from_client, sizeof plaintext_from_client, &s_plaintext_written);
  test_equality_int("server recv -- result", res, LIBCSES_OK);
  test_equality_int("server recv -- plaintext read", s_plaintext_read, 0);
  test_equality_int("server recv -- plaintext written", s_plaintext_written, 400);
  test_equality_int("server recv -- ciphertext read", s_ciphertext_read, 400+SEGMENT_OVERHEAD);
  test_equality_int("server recv -- ciphertext written", s_ciphertext_written, 0);

  // Make sure we actually got the right content
  test_equality("server->client", plaintext_from_server, plaintext_for_client, sizeof plaintext_for_client);
  test_equality("client->server", plaintext_from_client, plaintext_for_server, sizeof plaintext_for_server);
}

int main(){
  crypter_nonce_incrementing();
  simple_exchange();
  printf("Complete\n");
  return 0;
}

