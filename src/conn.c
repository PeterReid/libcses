#include <stdint.h>
#include <string.h>

#include <sodium/crypto_stream_salsa20.h>

#include "cses.h"
#include "crypter.h"
#include "memzero.h"
#include "cses_internal.h"
#include "crypto.h"


static unsigned char *libcses_conn_private(struct libcses_conn *conn){
  return conn->buffer + sizeof(conn->buffer) - KEY_EXCHANGE_SECRET_BYTES;
}
static unsigned char *libcses_conn_handshake(struct libcses_conn *conn){
  /* Assuming SH_BYTES > CH_BYTES */
  return conn->buffer + sizeof(conn->buffer) - KEY_EXCHANGE_SECRET_BYTES - SH_BYTES;
}
static unsigned char *libcses_conn_prospective_identity(struct libcses_conn *conn){
  return conn->buffer + sizeof(conn->buffer) - SH_IDENTITY_BYTES;
}
int libcses_conn_server_init(
  struct libcses_conn *conn,
  struct libcses_server *server,
  unsigned char *random32
){
  unsigned char public_key[32];
  unsigned char *handshake;
  memset(conn, 0, sizeof *conn);
  conn->state = LIBCSES_CONN_AWAITING_CLIENT_HANDSHAKE;

  /* Save the private key -- we need it to finish the key exchange */
  memcpy(libcses_conn_private(conn), random32, 32);
  /* Might as well avoid leaving a copy of the private key sitting around */
  libcses_memzero(random32, 32);

  /* Compute the public key for key exchange */
  amal_crypto_scalarmult_curve25519_base(public_key, libcses_conn_private(conn));

  /* Put together the handshake */
  handshake = libcses_conn_handshake(conn);
  memset(handshake + SH_STATUS_OFFSET, 0, SH_STATUS_BYTES);
  memcpy(handshake + SH_IDENTITY_OFFSET, server->public_key, SH_IDENTITY_BYTES);
  memcpy(handshake + SH_EXCHANGE_OFFSET, public_key, SH_EXCHANGE_BYTES);

  amal_crypto_sign_ed25519_detached_short(
    handshake + SH_SIGNATURE_OFFSET, 0,
    handshake + SH_EXCHANGE_OFFSET, SH_EXCHANGE_BYTES,
    server->secret_key);

  return 0;
}

int libcses_conn_client_init(
  struct libcses_conn *conn,
  unsigned char *random32
){
  unsigned char *handshake;

  memset(conn, 0, sizeof *conn);
  conn->state = LIBCSES_CONN_SENDING_CLIENT_HANDSHAKE;
  memcpy(libcses_conn_private(conn), random32, 32);

  handshake = libcses_conn_handshake(conn);
  /* Include the protocol-identifying prefix */
  memcpy(handshake + CH_MAGIC_OFFSET, HANDSHAKE_MAGIC, CH_MAGIC_BYTES);
  /* Include the key exchange public key */
  amal_crypto_scalarmult_curve25519_base(
    handshake+CH_EXCHANGE_OFFSET,
    libcses_conn_private(conn));
  libcses_memzero(random32, 32);

  return 0;
}

static void libcses_conn_init_crypters(
  struct libcses_conn *conn,
  const unsigned char *public_key,
  unsigned char *private_key,
  int encryptor_first
){
  unsigned char shared[crypto_scalarmult_curve25519_BYTES];
  unsigned char key_bytes[64];
  unsigned char *encryption_key;
  unsigned char *decryption_key;
  unsigned char nonce[crypto_stream_salsa20_NONCEBYTES];

  amal_crypto_scalarmult_curve25519(shared, private_key, public_key);

  memset(nonce, 0, sizeof nonce);
  memset(key_bytes, 0, sizeof key_bytes);
  amal_crypto_stream_salsa20_short(key_bytes, sizeof key_bytes, nonce, shared);
  encryption_key = key_bytes + (encryptor_first ? 0 : 32);
  decryption_key = key_bytes + (encryptor_first ? 32 : 0);

  libcses_crypter_init(&conn->encryptor, encryption_key);
  libcses_crypter_init(&conn->decryptor, decryption_key);

  libcses_memzero(key_bytes, sizeof key_bytes);
  libcses_memzero(private_key, 32);
}

static int min(int x, int y){
  return x<y ? x : y;
}

static int accept_ciphertext(
  struct libcses_conn *conn,
  int wanted_len,
  const unsigned char *ciphertext_in,
  int ciphertext_len,
  int *ciphertext_consumed
){
  int available;
  int more_wanted;
  int will_accept;

  if( ciphertext_len==0 ) return 0;

  available = ciphertext_len - *ciphertext_consumed;
  more_wanted = min(BUFFER_CAPACITY, wanted_len) - conn->buffered_count;
  will_accept = min(available, more_wanted);
  memcpy(
    conn->buffer + conn->buffered_count,
    ciphertext_in + *ciphertext_consumed,
    will_accept);
  *ciphertext_consumed += will_accept;
  conn->buffered_count += will_accept;

  return conn->buffered_count==wanted_len;
}

static int send_handshake(
  struct libcses_conn *conn,
  unsigned char *ciphertext_out,
  int ciphertext_out_capacity,
  int *ciphertext_written
){
  int handshake_size;
  int want_to_send;
  int has_space_to_send;
  int will_send;

  if( ciphertext_out_capacity==0 ) return 0;

  handshake_size = conn->state == LIBCSES_CONN_SENDING_CLIENT_HANDSHAKE
    ? CH_BYTES
    : SH_BYTES;
  /* buffered_count is (ab)used to keep track of how much of the handshake we have sent. */
  want_to_send = handshake_size - conn->buffered_count;
  has_space_to_send = ciphertext_out_capacity - *ciphertext_written;
  will_send = min(want_to_send, has_space_to_send);

  memcpy(
    ciphertext_out + *ciphertext_written,
    libcses_conn_handshake(conn) + *ciphertext_written,
    will_send);
  conn->buffered_count += will_send;
  *ciphertext_written += will_send;
  return conn->buffered_count == handshake_size;
}

int copy_plaintext_out(
  struct libcses_conn *conn,
  unsigned char *plaintext_out,
  int plaintext_out_capacity,
  int *plaintext_written
){
  int want_to_send;
  int has_space_to_send;
  int will_send;

  if( plaintext_out_capacity==0 ) return 0;

  want_to_send = conn->buffered_count - conn->expected_count;
  has_space_to_send = plaintext_out_capacity - *plaintext_written;
  will_send = min(want_to_send, has_space_to_send);
  memcpy(plaintext_out + *plaintext_written,
    conn->buffer + conn->expected_count,
    will_send);
  conn->expected_count += will_send;
  *plaintext_written += will_send;
  return conn->expected_count == conn->buffered_count;
}

unsigned int read_length(const unsigned char *data){
  return data[0] | (data[1]<<8);
}
void write_length(unsigned char *data, unsigned int len){
  data[0] = len & 0xff;
  data[1] = (len >> 8) & 0xff;
}

int detect_forgery(struct libcses_conn *conn){
  unsigned char *mac = conn->buffer;
  unsigned char *ciphertext = conn->buffer + MAC_LENGTH;
  int result;

  result = libcses_crypter_decrypt(&conn->decryptor, mac, ciphertext, conn->buffered_count - MAC_LENGTH);
  if( result ){
    conn->state = LIBCSES_CONN_CORRUPT;
    libcses_memzero(conn->buffer, conn->buffered_count);
  }
  return result;
}


int pipe_ready(struct libcses_conn *conn){
  switch( conn->state ){
    case LIBCSES_CONN_SENDING_CLIENT_HANDSHAKE:
    case LIBCSES_CONN_AWAITING_CLIENT_HANDSHAKE:
    case LIBCSES_CONN_AWAITING_SERVER_HANDSHAKE:
    case LIBCSES_CONN_VALIDATING_IDENTITY:
    case LIBCSES_CONN_CORRUPT:
    default:
      return 0;
   
    case LIBCSES_CONN_SENDING_SERVER_HANDSHAKE:
    case LIBCSES_CONN_READING_LENGTH:
    case LIBCSES_CONN_READING_DATA:
    case LIBCSES_CONN_COPYING_PLAINTEXT:
      return 1;
  }
}

void authencrypted_write(
  struct libcses_conn *conn,
  unsigned char *ciphertext,
  const unsigned char *plaintext,
  int plaintext_len
){
  unsigned char *mac = ciphertext;
  unsigned char *body = mac + MAC_LENGTH;
  memcpy(body, plaintext, plaintext_len);
  libcses_crypter_encrypt(&conn->encryptor, mac, body, plaintext_len);
}

int libcses_conn_interact(
  struct libcses_conn *conn,
  const unsigned char *plaintext_in, int plaintext_in_len, int *plaintext_in_read,
  const unsigned char *ciphertext_in, int ciphertext_in_len, int *ciphertext_in_read,
  unsigned char *ciphertext_out, int ciphertext_out_capacity, int *ciphertext_out_written,
  unsigned char *plaintext_out, int plaintext_out_capacity, int *plaintext_out_written
){
  int done = 0;
  while(!done){
    switch( conn->state ){
      case LIBCSES_CONN_SENDING_CLIENT_HANDSHAKE:
        if( send_handshake(conn, ciphertext_out, ciphertext_out_capacity, ciphertext_out_written) ){
          conn->state = LIBCSES_CONN_AWAITING_SERVER_HANDSHAKE;
          conn->buffered_count = 0;
        }else{
          done = 1;
        }
        break;
      case LIBCSES_CONN_AWAITING_CLIENT_HANDSHAKE:
        if( accept_ciphertext(conn, CH_BYTES, ciphertext_in, ciphertext_in_len, ciphertext_in_read) ){
          if( memcmp(conn->buffer + CH_MAGIC_OFFSET, HANDSHAKE_MAGIC, CH_MAGIC_BYTES) ){
            conn->state = LIBCSES_CONN_CORRUPT;
            done = 1;
          }else{
            unsigned char *client_public = conn->buffer + CH_EXCHANGE_OFFSET;
            unsigned char *server_secret = libcses_conn_private(conn);
            libcses_conn_init_crypters(conn, client_public, server_secret, 0);
            conn->state = LIBCSES_CONN_SENDING_SERVER_HANDSHAKE;
            conn->buffered_count = 0;
          }
        }else{
          done = 1;
        }
        break;
      case LIBCSES_CONN_SENDING_SERVER_HANDSHAKE:
        if( send_handshake(conn, ciphertext_out, ciphertext_out_capacity, ciphertext_out_written) ){
          conn->state = LIBCSES_CONN_READING_LENGTH;
          conn->buffered_count = 0;
        }else{
          done = 1;
        }
        break;

      case LIBCSES_CONN_AWAITING_SERVER_HANDSHAKE:
        if( accept_ciphertext(conn, SH_BYTES, ciphertext_in, ciphertext_in_len, ciphertext_in_read) ){
          unsigned char *server_public = conn->buffer + SH_EXCHANGE_OFFSET;
          unsigned char *server_identity = conn->buffer + SH_IDENTITY_OFFSET;
          unsigned char *signature = conn->buffer + SH_SIGNATURE_OFFSET;
          if( amal_crypto_sign_ed25519_verify_detached_short(signature, server_public, SH_EXCHANGE_BYTES, server_identity) ){
            conn->state = LIBCSES_CONN_CORRUPT;
          }else{
            unsigned char *client_secret = libcses_conn_private(conn);
            libcses_conn_init_crypters(conn, server_public, client_secret, 1);
            memcpy(libcses_conn_prospective_identity(conn), server_identity, SH_IDENTITY_BYTES);
            conn->state = LIBCSES_CONN_VALIDATING_IDENTITY;
            conn->buffered_count = 0;
          }
        }else{
          done = 1;
        }
        break;

      case LIBCSES_CONN_VALIDATING_IDENTITY:
        return LIBCSES_HAS_IDENTITY;

      case LIBCSES_CONN_READING_LENGTH:
        if( accept_ciphertext(conn, 2 + MAC_LENGTH, ciphertext_in, ciphertext_in_len, ciphertext_in_read) ){
          if( detect_forgery(conn) ) break;

          conn->expected_count = read_length(conn->buffer + MAC_LENGTH);
          if( conn->expected_count>MAX_SEGMENT_LENGTH ){
            conn->state = LIBCSES_CONN_CORRUPT;
          }else{
            conn->state = LIBCSES_CONN_READING_DATA;
            conn->buffered_count = 0;
          }
        }else{
          done = 1;
        }
        break;

      case LIBCSES_CONN_READING_DATA:
        if( accept_ciphertext(conn, conn->expected_count + MAC_LENGTH, ciphertext_in, ciphertext_in_len, ciphertext_in_read) ){
          if( detect_forgery(conn) ) break;

          conn->state = LIBCSES_CONN_COPYING_PLAINTEXT;
          conn->expected_count = MAC_LENGTH;
        }else{
          done = 1;
        }
        break;

      case LIBCSES_CONN_COPYING_PLAINTEXT:
        if( copy_plaintext_out(conn, plaintext_out, plaintext_out_capacity, plaintext_out_written) ){
          conn->buffered_count = 0;
          conn->state = LIBCSES_CONN_READING_LENGTH;
        }else{
          done = 1;
        }
        break;

      case LIBCSES_CONN_CORRUPT:
      default:
        return LIBCSES_CORRUPT;
    }
  }

  if( pipe_ready(conn) && ciphertext_out_capacity>0 && plaintext_in_len>0 ){
    while( 1 ){
      int ciphertext_out_available = ciphertext_out_capacity - *ciphertext_out_written;
      int plaintext_in_available = plaintext_in_len - *plaintext_in_read;
      int ciphertext_out_available_body = ciphertext_out_available - SEGMENT_OVERHEAD;
      int will_send = min(
        MAX_SEGMENT_LENGTH,
        min(plaintext_in_available, ciphertext_out_available_body));
      unsigned char length_buf[2];
      if( will_send<=0 ){
        break;
      }

      write_length(length_buf, will_send);

      authencrypted_write(
        conn, 
        ciphertext_out + *ciphertext_out_written,
        length_buf,
        2);
      *ciphertext_out_written += 2 + MAC_LENGTH;
      authencrypted_write(
        conn,
        ciphertext_out + *ciphertext_out_written,
        plaintext_in + *plaintext_in_read,
        will_send);
      *ciphertext_out_written += will_send + MAC_LENGTH;
      *plaintext_in_read += will_send;
    }
  }

  return 0;
}

int libcses_conn_get_server_identity(
  struct libcses_conn *conn,
  unsigned char *identity
){
  if( conn->state!=LIBCSES_CONN_VALIDATING_IDENTITY ){
    memset(identity, 0, SH_IDENTITY_BYTES);
    return LIBCSES_MISUSE;
  }

  memcpy(identity, libcses_conn_prospective_identity(conn), SH_IDENTITY_BYTES);
  return LIBCSES_OK;
}

int libcses_conn_accept_server_identity(struct libcses_conn *conn){
  if( conn->state!=LIBCSES_CONN_VALIDATING_IDENTITY ){
    return LIBCSES_MISUSE;
  }

  conn->state = LIBCSES_CONN_READING_LENGTH;
  return LIBCSES_OK;
}
