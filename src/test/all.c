#include <stdio.h>
#include <stdlib.h>

#include "cses.h"

#include "../secret_box.h"

void test_equality(const char *message, const unsigned char *x, const unsigned char *y, unsigned int len){
  if( memcmp(x, y, len) ){
    printf("Test failure: %s\n", message);
  }
}

void test_equality_int(const char *message, int expected, int actual){
  if( expected!=actual ){
    printf("Test failure: %s (expected %d, got %d)\n", message, expected, actual);
  }
}

#define PAD crypto_secretbox_xsalsa20poly1305_ZEROBYTES 
#include <nacl/crypto_stream.h>
#include <nacl/crypto_secretbox_xsalsa20poly1305.h>

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



int main(){
  secret_box_matches_nacl();
  secret_box_nonce_incrementing();
  printf("Complete\n");
  return 0;
}

