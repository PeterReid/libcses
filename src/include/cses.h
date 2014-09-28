#ifndef CSES_H
#define CSES_H

struct libcses_client;
struct libcses_conn;
struct libcses_server;

#define LIBCSES_OK 0

/* Invalid arguments -- programming error */
#define LIBCSES_MISUSE 1 

/* Ciphertext shows corruption or tampering */
#define LIBCSES_CORRUPT 2 

/* Stream has been closed */
#define LIBCSES_CLOSED 3 

/* The client side of the stream has received the server identity.
** libscec_client_get_server_identity may be called to validate it.
*/
#define LIBCSES_HAS_IDENTITY 100 

struct libcses_server{
  unsigned char public_key[32];
  unsigned char secret_key[64];
};

/* Initialize a server with the given 32-byte secret. The server's public identity
** is derived from the sercret.
*/
void libcses_server_init(
  struct libcses_server *,
  const unsigned char *secret32
);

#define LIBCSES_SECRET_BOX_KEY_BYTES 32
#define LIBCSES_SECRET_BOX_NONCE_BYTES 24
#define LIBCSES_SECRET_BOX_AUTHENTICATOR_BYTES 16

struct libcses_crypter{
  unsigned char key[LIBCSES_SECRET_BOX_KEY_BYTES];
  unsigned char nonce[LIBCSES_SECRET_BOX_NONCE_BYTES];
};

#define MAX_SEGMENT_LENGTH 1024
#define MAC_LENGTH LIBCSES_SECRET_BOX_AUTHENTICATOR_BYTES
#define SEGMENT_OVERHEAD (2 + MAC_LENGTH + MAC_LENGTH)
#define BUFFER_CAPACITY (MAX_SEGMENT_LENGTH + MAC_LENGTH)
#define DEGENERATE_ENCRYPTION_LENGTH SEGMENT_OVERHEAD
#define OUTPUT_BUFFER_CAPACITY (SEGMENT_OVERHEAD + DEGENERATE_ENCRYPTION_LENGTH)

struct libcses_conn{
  int state;
  struct libcses_crypter encryptor;
  struct libcses_crypter decryptor;
  unsigned char buffer[BUFFER_CAPACITY];
  int buffered_count;
  int expected_count;
  unsigned char output_buffer[OUTPUT_BUFFER_CAPACITY];
  int output_buffer_count;
};
/* Get the size, in bytes, that a conn occupies.
** A memory block of this size should be passed to libcses_conn_init().
*/

int libcses_conn_server_init(
  struct libcses_conn *,
  struct libcses_server *,
  unsigned char *random32
);
int libcses_conn_client_init(
  struct libcses_conn *,
  unsigned char *random32
);


/* Interact with the server side of a connection. Plaintext and ciphertext
** may be sent into and may be received from the connection.
** 
** plaintext_in: (input) plaintext to be sent to the client
** plaintext_in_len: (input) number of bytes of plaintext to be sent.
** plaintext_in_read: (output) number of bytes of plaintext actually consumed.
**   This may be less than plaintext_in_len. Bytes not consumed should be sent
**   again in a later call to libcses_conn_interact.
**
** ciphertext_in: (input) ciphertext received from the client.
** ciphertext_in_len: (input) number of bytes of ciphertext from the client 
**   available to the conn. 
** ciphertext_in_read (output): number of bytes of ciphertext that the conn 
**   consumed. This may be less than ciphertext_in_len. Bytes not consumed 
**   should be sent again in a later call to libcses_conn_interact.
**
** ciphertext_out: (output) ciphertext that must be sent to the client.
** ciphertext_out_capacity: (input) maximum number of bytes of ciphertext that
**   may be returned for sending to the client.
** ciphertext_out_len: (output) actual number of bytes of ciphertext that were 
**   returned for sending to the client.
**
** plaintext_out: (output) plaintext that has been received from the client.
** plaintext_out_capacity: (input) maximum number of bytes of plaintext that
**   may be returned.
** plaintext_out_len: (output) actual number of bytes of plaintext that were
**   returned.
*/
int libcses_conn_interact(struct libcses_conn *,
  const unsigned char *plaintext_in, int plaintext_in_len, int *plaintext_in_read,
  const unsigned char *ciphertext_in, int ciphertext_in_len, int *ciphertext_in_read,
  unsigned char *ciphertext_out, int ciphertext_out_capacity, int *ciphertext_out_len,
  unsigned char *plaintext_out, int plaintext_out_capacity, int *plaintext_out_len);


int libcses_conn_get_server_identity(
  struct libcses_conn *,
  unsigned char *identity
);
int libcses_conn_accept_server_identity(struct libcses_conn *);


/* Close a conn. Subsequent calls to libcses_conn_interact will fail with
** LIBCSES_CLOSED. Closing the underlying data stream is the responsibility of
** the caller.
*/
int libcses_conn_close(struct libcses_conn *);

#endif

