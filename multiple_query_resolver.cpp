#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <boost/format.hpp>

#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_openssl.h>

#include <openssl/ssl.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <string>

#include <ev.h>
#include "simple_dns.h"
#include<iostream>

#define REMOTE_HOST "127.0.0.1"
#define REMOTE_PORT "853"
#define ALPN "\007doq-i11"
#define MESSAGE "GET /\r\n"


struct client {
  ngtcp2_crypto_conn_ref conn_ref;
  int fd;
  struct sockaddr_storage local_addr;
  socklen_t local_addrlen;
  ngtcp2_conn *conn;
  SSL_CTX *ssl_ctx;
  SSL *ssl;

  struct {
    int64_t stream_id;
    const uint8_t *data;
    size_t datalen;
    size_t nwrite;
  } stream;

  ngtcp2_connection_close_error last_error;

  ev_io rev;
  ev_timer timer;
};


static int numeric_host_family(const char *hostname, int family) {
  uint8_t dst[sizeof(struct in6_addr)];
  return inet_pton(family, hostname, dst) == 1;
}

static int numeric_host(const char *hostname) {
  return numeric_host_family(hostname, AF_INET) ||
         numeric_host_family(hostname, AF_INET6);
}

static int create_sock(struct sockaddr *addr, socklen_t *paddrlen,
                       const char *host, const char *port) {
  struct addrinfo hints = {0};
  struct addrinfo *res, *rp;
  int rv;
  int fd = -1;

  hints.ai_flags = AF_UNSPEC;
  hints.ai_socktype = SOCK_DGRAM;

  rv = getaddrinfo(host, port, &hints, &res);
  if (rv != 0) {
    fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
    return -1;
  }

  for (rp = res; rp; rp = rp->ai_next) {
    fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
    if (fd == -1) {
      continue;
    }
    break;
  }

  if (fd == -1) {
    goto end;
  }

  *paddrlen = rp->ai_addrlen;
  memcpy(addr, rp->ai_addr, rp->ai_addrlen);

end:
  freeaddrinfo(res);
  return fd;
}

static int connect_sock(struct sockaddr *local_addr, socklen_t *plocal_addrlen,
                        int fd, const struct sockaddr *remote_addr,
                        size_t remote_addrlen) {
  socklen_t len;

  if (connect(fd, remote_addr, (socklen_t)remote_addrlen) != 0) {
    fprintf(stderr, "connect: %s\n", strerror(errno));
    return -1;
  }

  len = *plocal_addrlen;

  if (getsockname(fd, local_addr, &len) == -1) {
    fprintf(stderr, "getsockname: %s\n", strerror(errno));
    return -1;
  }

  *plocal_addrlen = len;
  return 0;
}

int recv_crypto_data(ngtcp2_conn *conn, ngtcp2_crypto_level crypto_level,
                     uint64_t offset, const uint8_t *data, size_t datalen,
                     void *user_data) {

  return ngtcp2_crypto_recv_crypto_data_cb(conn, crypto_level, offset, data,
                                           datalen, user_data);
}

static uint64_t timestamp(void) {
  struct timespec tp;

  if (clock_gettime(CLOCK_MONOTONIC, &tp) != 0) {
    fprintf(stderr, "clock_gettime: %s\n", strerror(errno));
    exit(EXIT_FAILURE);
  }

  return (uint64_t)tp.tv_sec * NGTCP2_SECONDS + (uint64_t)tp.tv_nsec;
}

static int client_ssl_init(struct client *c) {
  c->ssl_ctx = SSL_CTX_new(TLS_client_method());
  if (!c->ssl_ctx) {
    fprintf(stderr, "SSL_CTX_new: %s\n",
            ERR_error_string(ERR_get_error(), NULL));
    return -1;
  }

  if (ngtcp2_crypto_openssl_configure_client_context(c->ssl_ctx) != 0) {
    fprintf(stderr, "ngtcp2_crypto_openssl_configure_client_context failed\n");
    return -1;
  }

  c->ssl = SSL_new(c->ssl_ctx);
  if (!c->ssl) {
    fprintf(stderr, "SSL_new: %s\n", ERR_error_string(ERR_get_error(), NULL));
    return -1;
  }

  SSL_set_app_data(c->ssl, &c->conn_ref);
  SSL_set_connect_state(c->ssl);

  printf("Initiating SSL ALPN protocols... %s: %s \n", REMOTE_HOST, ALPN);

  SSL_set_alpn_protos(c->ssl, (const unsigned char *)ALPN, sizeof(ALPN) - 1);

  if (!numeric_host(REMOTE_HOST)) {
    SSL_set_tlsext_host_name(c->ssl, REMOTE_HOST);
  }

  /* For NGTCP2_PROTO_VER_V1 */
  SSL_set_quic_transport_version(c->ssl, TLSEXT_TYPE_quic_transport_parameters);

  return 0;
}

static void rand_cb(uint8_t *dest, size_t destlen,
                    const ngtcp2_rand_ctx *rand_ctx) {
  size_t i;
  (void)rand_ctx;

  for (i = 0; i < destlen; ++i) {
    *dest = (uint8_t)random();
  }
}

static int get_new_connection_id_cb(ngtcp2_conn *conn, ngtcp2_cid *cid,
                                    uint8_t *token, size_t cidlen,
                                    void *user_data) {
  (void)conn;
  (void)user_data;

  if (RAND_bytes(cid->data, (int)cidlen) != 1) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }

  cid->datalen = cidlen;

  if (RAND_bytes(token, NGTCP2_STATELESS_RESET_TOKENLEN) != 1) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }

  return 0;
}

static int extend_max_local_streams_bidi(ngtcp2_conn *conn,
                                         uint64_t max_streams,
                                         void *user_data) {

  struct client *c = user_data;
  int rv;
  int64_t stream_id;
  (void)max_streams;

  if (c->stream.stream_id != -1) {
    return 0;
  }

  rv = ngtcp2_conn_open_bidi_stream(conn, &stream_id, NULL);
  if (rv != 0) {
    return 0;
  }

  char buf[1024];
	int buf_len = sizeof(buf);

  char host[] = "www.google.com";

  int len = SimpleDNS::BuildDnsQueryPacket(host, buf, 0, buf_len);
  
  printf("Created DNS packed for %s: length: %d \n", host, len);

  c->stream.stream_id = stream_id;
  c->stream.data = (const uint8_t *)buf;
  c->stream.datalen = len;

  return 0;
}

static void log_printf(void *user_data, const char *fmt, ...) {
  va_list ap;
  (void)user_data;

  va_start(ap, fmt);
  vfprintf(stderr, fmt, ap);
  va_end(ap);

  fprintf(stderr, "\n");
}

static size_t client_get_message(struct client *c, int64_t *pstream_id,
                                 int *pfin, ngtcp2_vec *datav,
                                 size_t datavcnt) {
  if (datavcnt == 0) {
    return 0;
  }
  fprintf(stdout, "Client get message: stream-id: %ld, size: %ld, datalen: %ld \n", 
    c->stream.stream_id, c->stream.nwrite , c->stream.datalen);
  if (c->stream.stream_id != -1 && c->stream.nwrite < c->stream.datalen) {
    *pstream_id = c->stream.stream_id;
    *pfin = 1;
    datav->base = (uint8_t *) c->stream.data + c->stream.nwrite;
    datav->len = c->stream.datalen - c->stream.nwrite;
    return 1;
  }

  *pstream_id = -1;
  *pfin = 0;
  datav->base = NULL;
  datav->len = 0;
  
  return 0;
}

int take_domain_input(char *host) {
  std::cin >> host;
  printf("%s", host);
}

int recv_stream_data(ngtcp2_conn *conn, uint32_t flags, int64_t stream_id,
                     uint64_t offset, const uint8_t *data, size_t datalen,
                     void *user_data, void *stream_user_data) {

  auto c = static_cast<client *>(user_data);

  printf("Reached client recv line284. \n");

  fprintf(stdout, "Closing stream %ld! \n", stream_id);
  int stream_close_rv = ngtcp2_conn_shutdown_stream(conn, stream_id, NGTCP2_WRITE_STREAM_FLAG_FIN);
  if (stream_close_rv != 0) {
    fprintf(stdout, "Error while closing stream! \n");
  }

  c->stream.stream_id = stream_id + 1;
  printf("New stream id: %ld \n", c->stream.stream_id);
  int rv = ngtcp2_conn_open_bidi_stream(conn, &c->stream.stream_id, user_data);
  if (rv != 0) {
    return -1;
  }

  char buf[1024];
	int buf_len = sizeof(buf);

  char host[64];
  std::cin >> host;

  int len = SimpleDNS::BuildDnsQueryPacket(host, buf, 0, buf_len);
  printf("Created DNS packed for %s: length: %d \n", host, len);

  c->stream.stream_id = stream_id + 1;
  c->stream.data = (const uint8_t *)buf;
  c->stream.datalen = len;

  return 0;
}

static int client_quic_init(struct client *c,
                            const struct sockaddr *remote_addr,
                            socklen_t remote_addrlen,
                            const struct sockaddr *local_addr,
                            socklen_t local_addrlen) {

  fprintf(stdout, "Initializing quic client... \n");

  ngtcp2_path path = {
      {
          (struct sockaddr *)local_addr,
          local_addrlen,
      },
      {
          (struct sockaddr *)remote_addr,
          remote_addrlen,
      },
      NULL,
  };

  ngtcp2_callbacks callbacks = {
      ngtcp2_crypto_client_initial_cb,
      NULL, /* recv_client_initial */
      ngtcp2_crypto_recv_crypto_data_cb,
      NULL, /* handshake_completed */
      NULL, /* recv_version_negotiation */
      ngtcp2_crypto_encrypt_cb,
      ngtcp2_crypto_decrypt_cb,
      ngtcp2_crypto_hp_mask_cb,
      recv_stream_data, /* recv_stream_data */
      NULL, /* acked_stream_data_offset */
      NULL, /* stream_open */
      NULL, /* stream_close */
      NULL, /* recv_stateless_reset */
      ngtcp2_crypto_recv_retry_cb,
      extend_max_local_streams_bidi,
      NULL, /* extend_max_local_streams_uni */
      rand_cb,
      get_new_connection_id_cb,
      NULL, /* remove_connection_id */
      ngtcp2_crypto_update_key_cb,
      NULL, /* path_validation */
      NULL, /* select_preferred_address */
      NULL, /* stream_reset */
      NULL, /* extend_max_remote_streams_bidi */
      NULL, /* extend_max_remote_streams_uni */
      NULL, /* extend_max_stream_data */
      NULL, /* dcid_status */
      NULL, /* handshake_confirmed */
      NULL, /* recv_new_token */
      ngtcp2_crypto_delete_crypto_aead_ctx_cb,
      ngtcp2_crypto_delete_crypto_cipher_ctx_cb,
      NULL, /* recv_datagram */
      NULL, /* ack_datagram */
      NULL, /* lost_datagram */
      ngtcp2_crypto_get_path_challenge_data_cb,
      NULL, /* stream_stop_sending */
      ngtcp2_crypto_version_negotiation_cb,
      NULL, /* recv_rx_key */
      NULL, /* recv_tx_key */
  };
  ngtcp2_cid dcid, scid;
  ngtcp2_settings settings;
  ngtcp2_transport_params params;
  int rv;

  dcid.datalen = NGTCP2_MIN_INITIAL_DCIDLEN;
  if (RAND_bytes(dcid.data, (int)dcid.datalen) != 1) {
    fprintf(stderr, "RAND_bytes failed\n");
    return -1;
  }

  scid.datalen = 8;
  if (RAND_bytes(scid.data, (int)scid.datalen) != 1) {
    fprintf(stderr, "RAND_bytes failed\n");
    return -1;
  }

  ngtcp2_settings_default(&settings);

  settings.initial_ts = timestamp();
  settings.log_printf = log_printf;

  ngtcp2_transport_params_default(&params);

  params.initial_max_streams_uni = 3;
  params.initial_max_stream_data_bidi_local = 128 * 1024;
  params.initial_max_data = 1024 * 1024;

  rv =
      ngtcp2_conn_client_new(&c->conn, &dcid, &scid, &path, NGTCP2_PROTO_VER_V1,
                             &callbacks, &settings, &params, NULL, c);
  if (rv != 0) {
    fprintf(stderr, "ngtcp2_conn_client_new: %s\n", ngtcp2_strerror(rv));
    return -1;
  }

  ngtcp2_conn_set_tls_native_handle(c->conn, c->ssl);

  fprintf(stdout, "QUIC new client success: %d\n", rv);

  return 0;
}

static int client_read(struct client *c) {
  uint8_t buf[65536];
  struct sockaddr_storage addr;
  struct iovec iov = {buf, sizeof(buf)};
  struct msghdr msg = {0};
  ssize_t nread;
  ngtcp2_path path;
  ngtcp2_pkt_info pi = {0};
  int rv;

  msg.msg_name = &addr;
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;

  fprintf(stdout, "Initializing client read...\n");

  for (;;) {
    msg.msg_namelen = sizeof(addr);

    nread = recvmsg(c->fd, &msg, MSG_DONTWAIT);

    if (nread == -1) {
      if (errno != EAGAIN && errno != EWOULDBLOCK) {
        fprintf(stderr, "recvmsg: %s\n", strerror(errno));
      }

      break;
    }

    path.local.addrlen = c->local_addrlen;
    path.local.addr = (struct sockaddr *)&c->local_addr;
    path.remote.addrlen = msg.msg_namelen;
    path.remote.addr = (struct sockaddr *) msg.msg_name;

    rv = ngtcp2_conn_read_pkt(c->conn, &path, &pi, buf, (size_t)nread,
                              timestamp());
    if (rv != 0) {
      fprintf(stderr, "ngtcp2_conn_read_pkt: %s\n", ngtcp2_strerror(rv));
      if (!c->last_error.error_code) {
        if (rv == NGTCP2_ERR_CRYPTO) {
          ngtcp2_connection_close_error_set_transport_error_tls_alert(
              &c->last_error, ngtcp2_conn_get_tls_alert(c->conn), NULL, 0);
        } else {
          ngtcp2_connection_close_error_set_transport_error_liberr(
              &c->last_error, rv, NULL, 0);
        }
      }
      return -1;
    }
  }

  return 0;
}

static int client_send_packet(struct client *c, const uint8_t *data,
                              size_t datalen) {
  struct iovec iov = {(uint8_t *)data, datalen};
  struct msghdr msg = {0};
  ssize_t nwrite;

  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;

  do {
    nwrite = sendmsg(c->fd, &msg, 0);
  } while (nwrite == -1 && errno == EINTR);

  if (nwrite == -1) {
    fprintf(stderr, "sendmsg: %s\n", strerror(errno));

    return -1;
  }

  return 0;
}

static int client_write_streams(struct client *c) {
  ngtcp2_tstamp ts = timestamp();
  ngtcp2_pkt_info pi;
  ngtcp2_ssize nwrite;
  uint8_t buf[1280];
  ngtcp2_path_storage ps;
  ngtcp2_vec datav;
  size_t datavcnt;
  int64_t stream_id;
  ngtcp2_ssize wdatalen;
  uint32_t flags;
  int fin;

  ngtcp2_path_storage_zero(&ps);

  fprintf(stdout, "Client write streams...\n");

  for (;;) {
    datavcnt = client_get_message(c, &stream_id, &fin, &datav, 1);

    flags = NGTCP2_WRITE_STREAM_FLAG_MORE;
    if (fin) {
      flags |= NGTCP2_WRITE_STREAM_FLAG_FIN;
    }

    fprintf(stdout, "datavcnt: %ld packet info: %d\n", datavcnt, pi.ecn);

    nwrite = ngtcp2_conn_writev_stream(c->conn, &ps.path, &pi, buf, sizeof(buf),
                                       &wdatalen, flags, stream_id, &datav,
                                       datavcnt, ts);

    printf("nwrite: %ld wdatalen: %ld \n", nwrite, wdatalen);
    if (nwrite < 0) {
      switch (nwrite) {
      case NGTCP2_ERR_WRITE_MORE:
        c->stream.nwrite += (size_t)wdatalen;
        continue;
      default:
        fprintf(stderr, "ngtcp2_conn_writev_stream: %s\n",
                ngtcp2_strerror((int)nwrite));
        ngtcp2_connection_close_error_set_transport_error_liberr(
            &c->last_error, (int)nwrite, NULL, 0);
        return -1;
      }
    }

    if (nwrite == 0) {
      return 0;
    }

    if (wdatalen > 0) {
      c->stream.nwrite += (size_t)wdatalen;
    }

    if (client_send_packet(c, buf, (size_t)nwrite) != 0) {
      break;
    }
  }

  return 0;
}

static int client_write(struct client *c) {

  fprintf(stdout, "Client write...\n");

  ngtcp2_tstamp expiry, now;
  ev_tstamp t;

  if (client_write_streams(c) != 0) {
    return -1;
  }

  printf("DONE WRITING STREAM %ld! \n", c->stream.stream_id);
  
  expiry = ngtcp2_conn_get_expiry(c->conn);
  now = timestamp();

  t = expiry < now ? 1e-9 : (ev_tstamp)(expiry - now) / NGTCP2_SECONDS;

  c->timer.repeat = t;
  ev_timer_again(EV_DEFAULT, &c->timer);

  return 0;
}

static int client_handle_expiry(struct client *c) {
  int rv = ngtcp2_conn_handle_expiry(c->conn, timestamp());
  if (rv != 0) {
    fprintf(stderr, "ngtcp2_conn_handle_expiry: %s\n", ngtcp2_strerror(rv));
    return -1;
  }

  return 0;
}

static void client_close(struct client *c) {
  ngtcp2_ssize nwrite;
  ngtcp2_pkt_info pi;
  ngtcp2_path_storage ps;
  uint8_t buf[1280];

  if (ngtcp2_conn_is_in_closing_period(c->conn) ||
      ngtcp2_conn_is_in_draining_period(c->conn)) {
    goto fin;
  }

  ngtcp2_path_storage_zero(&ps);

  nwrite = ngtcp2_conn_write_connection_close(
      c->conn, &ps.path, &pi, buf, sizeof(buf), &c->last_error, timestamp());
  if (nwrite < 0) {
    fprintf(stderr, "ngtcp2_conn_write_connection_close: %s\n",
            ngtcp2_strerror((int)nwrite));
    goto fin;
  }

  client_send_packet(c, buf, (size_t)nwrite);

fin:
  ev_break(EV_DEFAULT, EVBREAK_ALL);
}

static void read_cb(struct ev_loop *loop, ev_io *w, int revents) {
  struct client *c = (struct client*) w->data;
  (void)loop;
  (void)revents;

  if (client_read(c) != 0) {
    client_close(c);
    return;
  }

  printf("READ CALLBACK!! \n");
  if (client_write(c) != 0) {
    client_close(c);
  }
  printf("READ CALLBACK COMPLETED!! \n");
}

static void timer_cb(struct ev_loop *loop, ev_timer *w, int revents) {
  struct client *c = (struct client*) w->data;
  (void)loop;
  (void)revents;

  if (client_handle_expiry(c) != 0) {
    client_close(c);
    return;
  }

  printf("TIMER CALLBACK!! \n");

  if (client_write(c) != 0) {
    client_close(c);
  }

  printf("TIMER CALLBACK COMPLETED!! \n");
}

static ngtcp2_conn *get_conn(ngtcp2_crypto_conn_ref *conn_ref) {
  struct client *c = (struct client*) conn_ref->user_data;
  return c->conn;
}

static int client_init(struct client *c) {

  fprintf(stdout, "Initializing client... \n");
  struct sockaddr_storage remote_addr, local_addr;
  socklen_t remote_addrlen, local_addrlen = sizeof(local_addr);

  memset(c, 0, sizeof(*c));

  ngtcp2_connection_close_error_default(&c->last_error);

  c->fd = create_sock((struct sockaddr *)&remote_addr, &remote_addrlen,
                      REMOTE_HOST, REMOTE_PORT);
  if (c->fd == -1) {
    return -1;
  }

  if (connect_sock((struct sockaddr *)&local_addr, &local_addrlen, c->fd,
                   (struct sockaddr *)&remote_addr, remote_addrlen) != 0) {
    return -1;
  }

  memcpy(&c->local_addr, &local_addr, sizeof(c->local_addr));
  c->local_addrlen = local_addrlen;

  printf("Initiating SSL connection...");
  
  if (client_ssl_init(c) != 0) {
    return -1;
  }

  if (client_quic_init(c, (struct sockaddr *)&remote_addr, remote_addrlen,
                       (struct sockaddr *)&local_addr, local_addrlen) != 0) {
    return -1;
  }

  c->stream.stream_id = -1;

  c->conn_ref.get_conn = get_conn;
  c->conn_ref.user_data = c;

  fprintf(stdout, "Starting connection read...\n"); 

  ev_io_init(&c->rev, read_cb, c->fd, EV_READ);
  c->rev.data = c;
  ev_io_start(EV_DEFAULT, &c->rev);

  ev_timer_init(&c->timer, timer_cb, 0., 0.);
  c->timer.data = c;

  return 0;
}

static void client_free(struct client *c) {
  ngtcp2_conn_del(c->conn);
}

/*
New Definitions
*/

int client_write_on_new_data(struct client *c, int64_t stream_id) {

  fprintf(stdout, "Client write...\n");

  ngtcp2_tstamp expiry, now;
  ev_tstamp t;

  int rv;
  rv = ngtcp2_conn_open_bidi_stream(c->conn, &stream_id, NULL);
  if (rv != 0) {
    return 0;
  }

  char buf[1024];
	int buf_len = sizeof(buf);

  char host[64];

  fprintf(stdout, "Ready to take input: ");

  std::cin >> host;

  int len = SimpleDNS::BuildDnsQueryPacket(host, buf, 0, buf_len);
  
  printf("Created DNS packed for %s: length: %d \n", host, len);

  c->stream.stream_id = stream_id;
  c->stream.data = (const uint8_t *)buf;
  c->stream.datalen = len;

  if (client_write_streams(c) != 0) {
    return -1;
  }

  expiry = ngtcp2_conn_get_expiry(c->conn);
  now = timestamp();

  t = expiry < now ? 1e-9 : (ev_tstamp)(expiry - now) / NGTCP2_SECONDS;

  c->timer.repeat = t;
  ev_timer_again(EV_DEFAULT, &c->timer);

  return 0;
}


int main(void) {
  struct client c;

  srandom((unsigned int)timestamp());

  if (client_init(&c) != 0) {
    exit(EXIT_FAILURE);
  }

  if (client_write(&c) != 0) {
    exit(EXIT_FAILURE);
  }

  // client_write_on_new_data(&c, 1);

  ev_run(EV_DEFAULT, 0);

  client_free(&c);

  return 0;
}


namespace SimpleDNS {

    std::string IPBin2Dec(const std::string& data) {
        if (data.size() < 4) {
            return "";
        }
        char buf[32] = {0};
        snprintf(buf, sizeof(buf), "%d.%d.%d.%d", 
        (unsigned char)data[0], (unsigned char)data[1], 
        (unsigned char)data[2], (unsigned char)data[3]);
        return buf;
    }

    char Char2Hex(unsigned char ch) {
        if (ch >= 0 && ch <= 9) {
            return ch + '0';
        }
        return ch + 'a' - 10;
    }

    void PrintBuffer(char* buf, int len) {
        int width = 16;

        for (int i = 0; i < len; i++) {
            if (i%width == 0) {
                printf ("%02d    ", i/width);
            }
            char ch = ' ';
            if ((i+1) % width == 0) {
                ch = '\n';
            }
            unsigned char byte = buf[i];
            int hi = 0x0f & (byte >> 4);
            int lo = 0x0f & byte;
            
            printf("%c%c%c", Char2Hex(hi), Char2Hex(lo), ch);
        }
        printf("\n");
    }

    int BuildDnsQueryPacket(const char* host, char* buf, int pos, int end) {
        if (buf == NULL || host == NULL) {
        return 0;
    }
    //==========header section===========
    // query transaction id
    unsigned short query_id = 0x00;
    buf[pos++] = 0xff & (query_id>>8);
    buf[pos++] = ' ';
    buf[pos++] = 0xff & query_id;
    buf[pos++] = 0xff & query_id;

    bool req_recursive = true;
    // |qr| opcode |aa|tc|rd|rd|
    buf[pos++] = req_recursive ? 0x01 : 0x00;
    // |ra|reseverd|rcode|
    buf[pos++] = 0x00;
    // query count
    unsigned short query_cnt = 0x01;
    buf[pos++] = 0xff & (query_cnt>>8);
    buf[pos++] = 0xff & query_cnt;

    // ans rr = 0
    buf[pos++] = 0;
    buf[pos++] = 0;
    buf[pos++] = 0;
    buf[pos++] = 0;

    buf[pos++] = 0;
    buf[pos++] = 0;
    //==========query section========
    int cp = 0;
    char ch = 0;
    char last = 0;
    int lp = pos++;
    while ((ch = host[cp++]) != '\0' && pos < end) {
        last = ch;
        if (ch != '.') {
        buf[pos++] = ch;
        continue;
        }
        int len = pos - lp -1;
        if (len <= 0 || len > 63) {
        printf("host name format invalid.\n");
        return -1;
        }
        buf[lp] = len;
        lp = pos++;
    }

    if (pos == end) {
        return -1;    
    }

    if (last != '.') {
        buf[lp] = (pos - lp - 1);
    }
    // else { 
        // 	buf[lp] 	= pos - lp - 1;
        // 	buf[pos++]	= 0;
        // }
    else {
        pos--;
    }
    buf[pos++] = 0;

    //==========query type==========
    unsigned short query_type = 0x01;
    buf[pos++] = 0xff & (query_type >> 8);
    buf[pos++] = 0xff & query_type;

    //==========query class=========
    unsigned short query_class = 0x01;
    buf[pos++] = 0xff & (query_class >> 8);
    buf[pos++] = 0xff & query_class;

    return pos;
    }

    int ParseUnsignedInt(const char* buf, int pos, int end, unsigned int& value) {
        value = 0;
        value = (unsigned char)buf[pos++];
        value = (value << 8)|(unsigned char)buf[pos++];
        value = (value << 8)|(unsigned char)buf[pos++];
        value = (value << 8)|(unsigned char)buf[pos++];

        return pos;
    }

    int ParseUnsignedShort(const char* buf, int pos, int end, unsigned short& value) {
        value = 0;
        value = (unsigned char)buf[pos++];
        value = (value << 8)|(unsigned char)buf[pos++];
        return pos;
    }

    int ParseHost(const char* buf, int pos, int end, std::string& host) {
        if (buf == NULL) {
            return pos;
        }
        unsigned int limit = 0xc0;
        unsigned int len = (unsigned char)buf[pos++];
        while (len != 0 && !(len & limit)) {
            host.append(buf+pos, len);
            pos += len;
            len = (unsigned char)buf[pos++];
            if (len != 0) {
                host.append(".");
            }
        }
        if (len & limit) {
            unsigned int offset = ((limit ^ len) << 8) | (unsigned char)buf[pos++];
            ParseHost(buf, offset, end, host);
        }	
        return pos;
    }

    int ParseQuestionSection(const char* buf, int pos, int end, SimpleDNS::DnsQuestionSection& dns_question_section) {
        pos = ParseHost(buf, pos, end, dns_question_section.host);
        pos = ParseUnsignedShort(buf, pos, end, dns_question_section.query_type);
        pos = ParseUnsignedShort(buf, pos, end, dns_question_section.query_class);
        return pos; 
    }

    int ParseResourceRecord(const char* buf, int pos, int end, SimpleDNS::DnsResource& dns_resource) {
        if (buf == NULL) {
            return pos;
        }
        pos = ParseHost(buf, pos, end, dns_resource.host);
        pos = ParseUnsignedShort(buf, pos, end, dns_resource.domain_type);
        pos = ParseUnsignedShort(buf, pos, end, dns_resource.domain_class);
        pos = ParseUnsignedInt(buf, pos, end, dns_resource.ttl);
        pos = ParseUnsignedShort(buf, pos, end, dns_resource.data_len);
        dns_resource.data_pos = pos;
        pos += dns_resource.data_len;
        return pos;
    }

    int ParseDnsRecordDataField(const char* buf, int pos, int end, SimpleDNS::DnsResource& res) {
        unsigned short type = res.domain_type;
        if (type == 1) {
            res.data = SimpleDNS::IPBin2Dec(std::string(buf + res.data_pos, res.data_len));
        } else if (type == 2 || type == 5) {
            ParseHost(buf, res.data_pos, end, res.data);
        } else if (type == 28) {
            res.data = "IPV6 ADDR";
        } else {
            res.data = "OTHERS";
        }
        return 0;
    }

    int ParseDnsResponsePacket(const char* buf, int end) {
        if (buf == NULL) {
            return -1;
        }
        int pos = 0;
        // query transaction id
        unsigned short query_id = 0;
        query_id = buf[pos++];
        query_id = (query_id << 8) | buf[pos++];
        
        bool req_recursive = false;
        unsigned short opcode_info = 0;
        // |qr| opcode |aa|tc|rd|rd|
        pos = ParseUnsignedShort(buf, pos, end, opcode_info);
        if (opcode_info & 0x0f) {
            printf("dns ret code non-zero, ret = %d\n", opcode_info & 0x0f);
            return -1;
        }
        
        if (opcode_info&0x80) {
            printf("recursived response.\n");
        } else {
            printf("non-recursived response.\n");
        }
        unsigned short query_cnt = 0;
        pos = ParseUnsignedShort(buf, pos, end, query_cnt);

        printf ("response query_cnt = %d\n", query_cnt);

        unsigned short answer_cnt = 0;
        pos = ParseUnsignedShort(buf, pos, end, answer_cnt);
        printf("response answer_cnt = %d\n", answer_cnt);

        unsigned short authority_cnt = 0;
        pos = ParseUnsignedShort(buf, pos, end, authority_cnt);
        printf("response authority_cnt = %d\n", authority_cnt);

        unsigned short additional_cnt = 0;
        pos = ParseUnsignedShort(buf, pos, end, additional_cnt);
        printf("response addtional_cnt = %d\n", additional_cnt);

        //============query section=================
        for (int i = 0; i < query_cnt; i++) {
            SimpleDNS::DnsQuestionSection dns_question;
            pos = ParseQuestionSection(buf, pos, end, dns_question);
            printf("question section: host = %s, type = %2d, class = %2d\n", dns_question.host.c_str(), dns_question.query_type, dns_question.query_class);
        }

        //===========answer section=================
        printf("[  answer section   ]\n");
        for (int i = 0; i < answer_cnt; i++) {
            SimpleDNS::DnsResource res;
            pos = ParseResourceRecord(buf, pos, end, res);
            ParseDnsRecordDataField(buf, pos, end, res);
            printf("host = %s, type = %2d, class = %2d, ttl = %4u, dlen = %2d, data = %s\n",
            res.host.c_str(), res.domain_type, res.domain_class, res.ttl, res.data_len, res.data.c_str());
        }

        //==========authority section==============
        printf("[  authority section   ]\n");
        for (int i = 0; i < authority_cnt; i++) {
            SimpleDNS::DnsResource res;
            pos = ParseResourceRecord(buf, pos, end, res);
            ParseDnsRecordDataField(buf, pos, end, res);
            printf("host = %s, type = %2d, class = %2d, ttl = %4u, dlen = %2d, data = %s\n",
            res.host.c_str(), res.domain_type, res.domain_class, res.ttl, res.data_len, res.data.c_str());
        }

        //==========additional section=============
        printf("[  additional section   ]\n");
        for (int i = 0; i < additional_cnt; i++) {
            SimpleDNS::DnsResource res;
            pos = ParseResourceRecord(buf, pos, end, res);
            ParseDnsRecordDataField(buf, pos, end, res);
            printf("host = %s, type = %2d, class = %2d, ttl = %4u, dlen = %2d, data = %s\n",
            res.host.c_str(), res.domain_type, res.domain_class, res.ttl, res.data_len, res.data.c_str());
        }
        return 0;
}

}
/* end of namespace SimpleDNS */
