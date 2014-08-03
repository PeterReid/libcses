#include <string.h>

#include "rng.h"
#include "../crypter.h"

void rng_init(rng *r, unsigned int seed){
  unsigned char key[LIBCSES_SECRET_BOX_KEY_BYTES];
  memset(key, 0, sizeof key);
  key[0] = seed & 0xff;
  key[1] = (seed>>8) & 0xff;
  key[2] = (seed>>16) & 0xff;
  key[3] = (seed>>24) & 0xff;
  libcses_crypter_init(r, key);
}

unsigned int rng_int(rng *r, unsigned int max){
  unsigned int val;
  unsigned int mask = 1;
  unsigned char buf[4];
  unsigned char authenticator[LIBCSES_SECRET_BOX_AUTHENTICATOR_BYTES];

  while( mask<max ){
    mask = (mask<<1) + 1;
  }
  do{
    memset(buf, 0, 4);
    libcses_crypter_encrypt(r, authenticator, buf, 4);
    
    val = (buf[0]<<24) | (buf[1]<<16) | (buf[2]<<8) | buf[3];
    val = val & mask;
  }while( val>max );
  return val;
}

void rng_buf(rng *r, unsigned char *buf, unsigned int len){
  unsigned char authenticator[LIBCSES_SECRET_BOX_AUTHENTICATOR_BYTES];
  memset(buf, 0, len);
  libcses_crypter_encrypt(r, authenticator, buf, len);
}
