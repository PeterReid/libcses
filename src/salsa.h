
void libcses_xsalsa20_prefixed(
        unsigned char *m_prefix,
        unsigned char *m,unsigned long long mlen,
  const unsigned char *n,
  const unsigned char *k
);

int libcses_salsa20_xor_ic(
        unsigned char *m,unsigned long long mlen,
  const unsigned char *n, uint64_t ic,
  const unsigned char *k
);

int libcses_xsalsa20_subkey(
        unsigned char *subkey,
  const unsigned char *n,
  const unsigned char *k,
);

