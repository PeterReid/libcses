#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cses.h"

#include "../secret_box.h"
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

#define PAD crypto_secretbox_xsalsa20poly1305_ZEROBYTES 
#include <sodium/crypto_stream.h>
#include <sodium/crypto_secretbox_xsalsa20poly1305.h>

void secret_box_matches_nacl_round(int round_num){
  struct libcses_secret_box encryptor;
  struct libcses_secret_box decryptor;
  unsigned char key[LIBCSES_SECRET_BOX_KEY_BYTES];
  unsigned char nonce[LIBCSES_SECRET_BOX_NONCE_BYTES];
  int text_len;
  int result;
  unsigned char *text;
  unsigned char *padded_ciphertext;
  unsigned char *padded_plaintext;
  unsigned char gen_key[crypto_stream_KEYBYTES];
  unsigned char gen_nonce[crypto_stream_NONCEBYTES];
  unsigned char authenticator[LIBCSES_SECRET_BOX_AUTHENTICATOR_BYTES];
  memset(gen_key, 0, sizeof gen_key);
  memset(gen_nonce, 0, sizeof gen_nonce);

  /* To make this round unique, populate the RNG key with the round number */
  gen_key[0] = round_num & 0xff;
  gen_key[1] = (round_num>>8) & 0xff;

  crypto_stream(key, sizeof key, gen_key, gen_nonce);
  gen_nonce[0] = 1;
  crypto_stream(nonce, sizeof nonce, gen_key, gen_nonce);
  gen_nonce[0] = 2;

  libcses_secret_box_init(&encryptor, key);
  libcses_secret_box_init(&decryptor, key);
  memcpy(encryptor.nonce, nonce, sizeof nonce);
  memcpy(decryptor.nonce, nonce, sizeof nonce);

  for( text_len=1; text_len<4000; text_len = (text_len * 5) / 4 + 1 ){
    /* Get a unique nonce for this encryption pair */
    gen_nonce[1] = text_len & 0xff;
    gen_nonce[2] = (text_len >> 8) & 0xff;

    text = malloc(text_len);
    padded_ciphertext = malloc(text_len + PAD);
    padded_plaintext = malloc(text_len + PAD);

    /* Generate a random-looking plaintext */
    crypto_stream(text, text_len, gen_key, gen_nonce);

    /* Prepare the equivalent nacl call -- a 32-byte string of 0s prefixes the plaintext */
    memset(padded_plaintext, 0, PAD);
    memcpy(padded_plaintext + PAD, text, text_len);

    crypto_secretbox_xsalsa20poly1305(padded_ciphertext, padded_plaintext, text_len + PAD, encryptor.nonce, encryptor.key);

    libcses_secret_box_encrypt(&encryptor, authenticator, text, text_len);
    test_equality("authenticators", authenticator, padded_ciphertext + 16, 16);
    test_equality("ciphertexts", text, padded_ciphertext + PAD, text_len);

    result = libcses_secret_box_decrypt(&decryptor, authenticator, text, text_len);
    test_equality("decrypted plaintext", text, padded_plaintext + PAD, text_len);
    test_equality_int("decryption success", 0, result);
  }
}

void secret_box_matches_nacl(){
  int i;
  for( i=0; i<100; i++ ){
    secret_box_matches_nacl_round(i);
  }
}

void secret_box_nonce_incrementing(){
  struct libcses_secret_box b;
  unsigned char key[LIBCSES_SECRET_BOX_KEY_BYTES] = {
    0x6c, 0x9c, 0xae, 0x48, 0x5b, 0x19, 0x0e, 0x97, 0xa8, 0xec, 0x87, 0x3f, 0xf1, 0xec, 0xba, 0x71, 
    0xe3, 0xba, 0xd8, 0xbb, 0xc4, 0xf5, 0xda, 0x83, 0xe6, 0x69, 0xdf, 0xdd, 0x74, 0xa3, 0xfd, 0x0e, 
  };
  unsigned char expected_nonce[LIBCSES_SECRET_BOX_NONCE_BYTES];
  unsigned char authenticator[LIBCSES_SECRET_BOX_AUTHENTICATOR_BYTES];
  unsigned char text[10];

  memset(expected_nonce, 0, sizeof expected_nonce);
  memset(text, 0, sizeof text);
  libcses_secret_box_init(&b, key);
 
  /* Start with a 0 nonce */
  test_equality("initial nonce", expected_nonce, b.nonce, sizeof expected_nonce);

  /* Check that the first increment works */
  libcses_secret_box_encrypt(&b, authenticator, text, sizeof text);
  expected_nonce[0] = 1;
  test_equality("nonce after one encryption", expected_nonce, b.nonce, sizeof expected_nonce);

  /* Set up for having to carry the increment over several bytes */ 
  memset(expected_nonce, 0, 11);
  memset(b.nonce, 0xff, 11);
  b.nonce[11] = 46;
  expected_nonce[11] = 47;
  b.nonce[18] = 101;
  expected_nonce[18] = 101;

  libcses_secret_box_encrypt(&b, authenticator, text, sizeof text);
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
  secret_box_matches_nacl();
  secret_box_nonce_incrementing();
  simple_exchange();
  printf("Complete\n");
  return 0;
}

