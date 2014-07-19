
void libcses_salsa20_xor_ic(
        unsigned char *m,unsigned long long mlen,
  const unsigned char *n, uint64_t ic,
  const unsigned char *k
);

void libcses_xsalsa20_subkey(
        unsigned char *subkey,
  const unsigned char *n,
  const unsigned char *k
);

