typedef struct libcses_crypter rng;

/* Generate random numbers that are NOT CRYPTOGRAPHICALLY SECURE for testing purposes. */
void rng_init(rng *r, unsigned int seed);
unsigned int rng_int(rng *r, unsigned int max);
void rng_buf(rng *r, unsigned char *buf, unsigned int len);

