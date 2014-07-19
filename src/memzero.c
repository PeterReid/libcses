
void libcses_memzero(unsigned char *xs, unsigned int len){
  volatile unsigned char *vxs = (volatile unsigned char *)xs;
  unsigned int i;

  for( i=0; i<len; i++ ){
    vxs[i] = 0;
  }
}

