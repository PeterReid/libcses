#include "secret_box.h"

struct libcses_conn{
  int state;
  struct libcses_secret_box encryptor;
  struct libcses_secret_box decryptor;
  unsigned char buffer[1024];
  int buffered_count;
  int expected_count;
};

/* Legal values of libcses_conn.state */
#define LIBCSES_CONN_SENDING_CLIENT_HANDSHAKE 1
#define LIBCSES_CONN_AWAITING_CLIENT_HANDSHAKE 2
#define LIBCSES_CONN_SENDING_SERVER_HANDSHAKE 3
#define LIBCSES_CONN_AWAITING_SERVER_HANDSHAKE 4
#define LIBCSES_CONN_READING_LENGTH 5
#define LIBCSES_CONN_READING_DATA 6
#define LIBCSES_CONN_COPYING_PLAINTEXT 7
#define LIBCSES_CONN_CORRUPT 8



int libcses_conn_interact(
  struct libcses_conn *conn,
  const char *plaintext_in, int plaintext_in_len, int *plaintext_in_read,
  const char *ciphertext_in, int ciphertext_in_len, int *ciphertext_in_read,
  char *ciphertext_out, int ciphertext_out_capacity, int *ciphertext_out_len,
  char *plaintext_out, int plaintext_out_capacity, int *plaintext_out_len
){
  
  return 0;
}
