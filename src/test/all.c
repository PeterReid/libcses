#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../cses_internal.h"
#include "rng.h"

static char test_context[256] = "";

void test_equality(const char *message, const unsigned char *x, const unsigned char *y, unsigned int len){
  if( memcmp(x, y, len) ){
    printf("Test failure in %s: %s\n", test_context, message);
  }
}

void test_equality_int(const char *message, int actual, int expected){
  if( expected!=actual ){
    printf("Test failure in %s: %s (expected %d, got %d)\n", test_context, message, expected, actual);
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

  strcpy(test_context, "nonce incrementing");

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
  unsigned char server_secret[sizeof server.secret_key];
  unsigned char ciphertext_s_to_c[500];
  unsigned char ciphertext_c_to_s[500];
  unsigned char plaintext_for_server[400];
  unsigned char plaintext_for_client[300];
  unsigned char plaintext_from_server[800];
  unsigned char plaintext_from_client[800];
  unsigned char server_session_randomness[32];
  unsigned char client_session_randomness[32];
  unsigned char server_identity_on_client[32];
  int res;
  int c_plaintext_written = 0;
  int c_plaintext_read = 0;
  int c_ciphertext_written = 0;
  int c_ciphertext_read = 0;
  int s_plaintext_written = 0;
  int s_plaintext_read = 0;
  int s_ciphertext_written = 0;
  int s_ciphertext_read = 0;

  strcpy(test_context, "simple exchange");

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

  /* Receive the handshake, ignoring the rest until the server identity is validated */
  c_ciphertext_written = 0;
  res = libcses_conn_interact(&cconn,
    plaintext_for_server, 400, &c_plaintext_read,
    ciphertext_s_to_c, 300+SEGMENT_OVERHEAD+SH_BYTES, &c_ciphertext_read,
    ciphertext_c_to_s, sizeof ciphertext_c_to_s, &c_ciphertext_written,
    plaintext_from_server, 134, &c_plaintext_written);
  test_equality_int("client recv1.1 -- result", res, LIBCSES_HAS_IDENTITY);
  test_equality_int("client recv1.1 -- plaintext read", c_plaintext_read, 0);
  test_equality_int("client recv1.1 -- plaintext written", c_plaintext_written, 0);
  test_equality_int("client recv1.1 -- ciphertext read", c_ciphertext_read, SH_BYTES);
  test_equality_int("client recv1.1 -- ciphertext written", c_ciphertext_written, 0);

  libcses_conn_get_server_identity(&cconn, server_identity_on_client);
  test_equality("received server identity", server_identity_on_client, server.public_key, 32);
  libcses_conn_accept_server_identity(&cconn);

  /* Receive everything they sent, but have only a small buffer for plaintext out */
  res = libcses_conn_interact(&cconn,
    plaintext_for_server, 400, &c_plaintext_read,
    ciphertext_s_to_c, 300+SEGMENT_OVERHEAD+SH_BYTES, &c_ciphertext_read,
    ciphertext_c_to_s, sizeof ciphertext_c_to_s, &c_ciphertext_written,
    plaintext_from_server, 134, &c_plaintext_written);
  test_equality_int("client recv1.2 -- result", res, LIBCSES_OK);
  test_equality_int("client recv1.2 -- plaintext read", c_plaintext_read, 400);
  test_equality_int("client recv1.2 -- plaintext written", c_plaintext_written, 134);
  test_equality_int("client recv1.2 -- ciphertext read", c_ciphertext_read, 300+SEGMENT_OVERHEAD+SH_BYTES);
  test_equality_int("client recv1.2 -- ciphertext written", c_ciphertext_written, 400+SEGMENT_OVERHEAD);
 
  /* Open up some more plaintext-in-buffer on the client */
  res = libcses_conn_interact(&cconn,
    0, 0, 0,
    0, 0, 0,
    0, 0, 0,
    plaintext_from_server, 301, &c_plaintext_written);
  test_equality_int("client recv2 -- result", res, LIBCSES_OK);
  test_equality_int("client recv2 -- plaintext_written", c_plaintext_written, 300);

  /* Receive the client message on the server */
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

  /* Make sure we actually got the right content */
  test_equality("server->client", plaintext_from_server, plaintext_for_client, sizeof plaintext_for_client);
  test_equality("client->server", plaintext_from_client, plaintext_for_server, sizeof plaintext_for_server);
}

void random_increase(rng *r, int *val, int limit){
  unsigned int increase_by = rng_int(r, 700);
  *val += increase_by;
  if( *val>limit ) *val = limit;
}

#define ONE_BYTE_BUFFERS 1
#define SHORT_TRANSMISSION 2
void apply_bufferlength_flags(int *limit, int current, int flags){
  if( flags&ONE_BYTE_BUFFERS ){
    if( *limit > current+1 ){
      *limit = current+1;
    }
  }
}

void generic_stream_test(int seed, int verbose, int flags){
  rng r;
  int for_server_length, for_client_length;
  unsigned char *for_server, *for_client, *from_server, *from_client; /* plaintexts */
  unsigned char *c_to_s, *s_to_c;
  struct libcses_server server;
  struct libcses_conn sconn;
  struct libcses_conn cconn;
  unsigned char random[32];
  int s_ciphertext_write = 0, s_ciphertext_write_limit = 0;
  int c_ciphertext_write = 0, c_ciphertext_write_limit = 0;
  int s_ciphertext_read = 0, s_ciphertext_read_limit = 0;
  int c_ciphertext_read = 0, c_ciphertext_read_limit = 0;
  int c_plaintext_read = 0, c_plaintext_read_limit = 0;
  int c_plaintext_write = 0, c_plaintext_write_limit = 0;
  int s_plaintext_read = 0, s_plaintext_read_limit = 0;
  int s_plaintext_write = 0, s_plaintext_write_limit = 0;
  int c_to_s_length;
  int s_to_c_length;
  int res;

  sprintf(test_context, "stream %d", seed);

  rng_init(&r, seed);

  rng_buf(&r, random, 32);
  libcses_server_init(&server, random);
  rng_buf(&r, random, 32);
  libcses_conn_server_init(&sconn, &server, random);
  rng_buf(&r, random, 32);
  libcses_conn_client_init(&cconn, random);

  for_server_length = rng_int(&r, 100000);
  for_client_length = rng_int(&r, 100000);
  /* Determine buffer lengths for the ciphertexts.
  ** 
  ** This does not cover the hard ceiling on the length of the ciphertext,
  ** since we could theoretically send lots of 1-byte segments, but it 
  ** is enough that it is vanishingly unlikely to run into this limit.
  ** Hitting this limit almost certainly means something is very wrong.
  */
  c_to_s_length = for_server_length*10;
  s_to_c_length = for_client_length*10;

  if( flags&SHORT_TRANSMISSION ){
    for_server_length %= 200;
    for_client_length %= 200;
    c_to_s_length = s_to_c_length = 100000; /* In case of lots of degenerate writes */
  }

  for_server = (unsigned char *)malloc(for_server_length);
  for_client = (unsigned char *)malloc(for_client_length);
  from_server = (unsigned char *)malloc(for_client_length);
  from_client = (unsigned char *)malloc(for_server_length);
  c_to_s = (unsigned char *)malloc(c_to_s_length);
  s_to_c = (unsigned char *)malloc(s_to_c_length);

  rng_buf(&r, for_server, for_server_length);
  rng_buf(&r, for_client, for_client_length);

  while( c_plaintext_write<for_client_length || s_plaintext_write<for_server_length ){
    int action = rng_int(&r, 9);
    switch( action ){
    case 0:
      random_increase(&r, &s_ciphertext_write_limit, s_to_c_length);
      apply_bufferlength_flags(&s_ciphertext_write_limit, s_ciphertext_write, flags);
      if( verbose ) printf("s_ciphertext_write_limit = %d\n", s_ciphertext_write_limit);
      break;
    case 1:
      random_increase(&r, &c_ciphertext_write_limit, c_to_s_length);
      apply_bufferlength_flags(&c_ciphertext_write_limit, c_ciphertext_write, flags);
      if( verbose ) printf("c_ciphertext_write_limit = %d\n", s_ciphertext_write_limit);
      break;
    case 2:
      random_increase(&r, &s_ciphertext_read_limit, c_ciphertext_write);
      apply_bufferlength_flags(&s_ciphertext_read_limit, s_ciphertext_read, flags);
      if( verbose ) printf("s_ciphertext_read_limit = %d\n", s_ciphertext_read_limit);
      break;
    case 3:
      random_increase(&r, &c_ciphertext_read_limit, s_ciphertext_write);
      apply_bufferlength_flags(&c_ciphertext_read_limit, c_ciphertext_read, flags);
      if( verbose ) printf("c_ciphertext_read_limit = %d\n", c_ciphertext_read_limit);
      break;
    case 4:
      random_increase(&r, &s_plaintext_write_limit, for_server_length);
      apply_bufferlength_flags(&s_plaintext_write_limit, s_plaintext_write, flags);
      if( verbose ) printf("s_plaintext_write_limit = %d\n", s_plaintext_write_limit);
      break;
    case 5:
      random_increase(&r, &c_plaintext_write_limit, for_client_length);
      apply_bufferlength_flags(&c_plaintext_write_limit, c_plaintext_write, flags);
      if( verbose ) printf("c_plaintext_write_limit = %d\n", s_plaintext_write_limit);
      break;
    case 6:
      random_increase(&r, &s_plaintext_read_limit, for_client_length);
      apply_bufferlength_flags(&s_plaintext_read_limit, s_plaintext_read, flags);
      if( verbose ) printf("s_plaintext_read_limit = %d\n", s_plaintext_read_limit);
      break;
    case 7:
      random_increase(&r, &c_plaintext_read_limit, for_server_length);
      apply_bufferlength_flags(&c_plaintext_read_limit, c_plaintext_read, flags);
      if( verbose ) printf("c_plaintext_read_limit = %d\n", c_plaintext_read_limit);
      break;
    case 8:
      /* Client work */
      res = libcses_conn_interact(&cconn,
        for_server, c_plaintext_read_limit, &c_plaintext_read,
        s_to_c, c_ciphertext_read_limit, &c_ciphertext_read,
        c_to_s, c_ciphertext_write_limit, &c_ciphertext_write,
        from_server, c_plaintext_write_limit, &c_plaintext_write);
      if( verbose ){
        printf("Client interacted (%d)\n", res);
        printf("  Plaintext read: %d of %d\n", c_plaintext_read, c_plaintext_read_limit);
        printf("  Ciphertext read: %d of %d\n", c_ciphertext_read, c_ciphertext_read_limit);
        printf("  Plaintext written: %d of %d\n", c_plaintext_write, c_plaintext_write_limit);
        printf("  Ciphertext written: %d of %d\n", c_ciphertext_write, c_ciphertext_write_limit);
      }
      if( res==LIBCSES_HAS_IDENTITY ){
        libcses_conn_accept_server_identity(&cconn);
      }else{
        test_equality_int("client interact", res, LIBCSES_OK);
        if( res!=LIBCSES_OK ){
          exit(1);
        }
      }
      break;
    case 9:
      /* Server work */
      res = libcses_conn_interact(&sconn,
        for_client, s_plaintext_read_limit, &s_plaintext_read,
        c_to_s, s_ciphertext_read_limit, &s_ciphertext_read,
        s_to_c, s_ciphertext_write_limit, &s_ciphertext_write,
        from_client, s_plaintext_write_limit, &s_plaintext_write);
      if( verbose ){
        printf("Server interacted (%d)\n", res);
        printf("  Plaintext read: %d of %d\n", s_plaintext_read, s_plaintext_read_limit);
        printf("  Ciphertext read: %d of %d\n", s_ciphertext_read, s_ciphertext_read_limit);
        printf("  Plaintext written: %d of %d\n", s_plaintext_write, s_plaintext_write_limit);
        printf("  Ciphertext written: %d of %d\n", s_ciphertext_write, s_ciphertext_write_limit);
      }
      test_equality_int("server interact", res, LIBCSES_OK);
      if( res!=LIBCSES_OK ){
        exit(1);
      }
      break;
    }
  }

  test_equality("server received", for_server, from_client, for_server_length);
  test_equality("client received", for_client, from_server, for_client_length);

  free((void *)for_server);
  free((void *)for_client);
  free((void *)from_server);
  free((void *)from_client);
  free((void *)c_to_s);
  free((void *)s_to_c);
}

void stream_tests(){
  int seed;
  for( seed=0; seed<100; seed++ ){
    generic_stream_test(seed, 0, 0);
  }
}

void tinybuffer_test(){
  generic_stream_test(10000, 0, ONE_BYTE_BUFFERS|SHORT_TRANSMISSION);
}

int main(){
  crypter_nonce_incrementing();
  simple_exchange();
  stream_tests();
  tinybuffer_test();
  printf("Complete\n");
  return 0;
}

