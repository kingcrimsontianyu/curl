#ifndef HEADER_CURL_OPENSSL_KTLS_H
#define HEADER_CURL_OPENSSL_KTLS_H
/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * SPDX-License-Identifier: curl
 ***************************************************************************/

#include "curl_setup.h"

#ifdef USE_OPENSSL

#include <openssl/opensslv.h>

#if defined(__linux__) && defined(HAVE_LINUX_TLS_H) && \
  OPENSSL_VERSION_NUMBER >= 0x30000000L && \
  !defined(LIBRESSL_VERSION_NUMBER) && \
  !defined(OPENSSL_IS_BORINGSSL) && !defined(OPENSSL_IS_AWSLC)
#include <linux/tls.h>
#ifdef HAVE_LINUX_TCP_H
#include <linux/tcp.h>
#elif defined(HAVE_NETINET_TCP_H)
#include <netinet/tcp.h>
#endif
#if defined(TLS_RX_EXPECT_NO_PAD) && defined(TLS_1_3_VERSION) && \
  defined(TLS_CIPHER_AES_GCM_256) && defined(TCP_ULP)
#define CURL_OSSL_KTLS_DIRECT_RX 1
#endif
#endif

#define CURL_OSSL_KTLS_SECRET_MAX 64
#define CURL_OSSL_KTLS_CONTROL_MAX (128U * 1024U)

#ifdef CURL_OSSL_KTLS_DIRECT_RX
/* Exact link marker for builds containing the OpenSSL/Linux direct RX
 * implementation. This intentionally remains absent from other builds even
 * though curl.h exposes the portable option and status API. */
CURL_EXTERN unsigned int curl_ktls_direct_rx_build_version_v1(void);
#endif

enum Curl_ossl_ktls_cipher {
  CURL_OSSL_KTLS_CIPHER_NONE = 0,
  CURL_OSSL_KTLS_CIPHER_AES_128_GCM,
  CURL_OSSL_KTLS_CIPHER_AES_256_GCM
};

typedef struct ssl_st SSL;

struct Curl_ossl_ktls_rx {
  unsigned char server_secret[CURL_OSSL_KTLS_SECRET_MAX];
  size_t server_secret_len;
  unsigned char *control;
  size_t control_len;
  size_t digest_len;
  size_t key_len;
  curl_socket_t sockfd;
  unsigned long recv_calls;
  unsigned long control_records;
  unsigned long key_updates;
  enum Curl_ossl_ktls_cipher cipher;
  void (*prior_keylog_cb)(const SSL *ssl, const char *line);
  BIT(capture_failed);
  BIT(requested);
  BIT(active);
  BIT(installed_manually);
  BIT(no_pad);
  BIT(peer_close_notify);
};

struct Curl_cfilter;
struct Curl_easy;
struct ossl_ctx;

void Curl_ossl_ktls_rx_init(struct Curl_ossl_ktls_rx *rx);
void Curl_ossl_ktls_rx_cleanup(struct Curl_ossl_ktls_rx *rx);
void Curl_ossl_ktls_keylog(struct ossl_ctx *octx, const char *line);

CURLcode Curl_ossl_ktls_rx_prepare(struct Curl_cfilter *cf,
                                   struct Curl_easy *data,
                                   struct ossl_ctx *octx);
CURLcode Curl_ossl_ktls_rx_activate(struct Curl_cfilter *cf,
                                    struct Curl_easy *data,
                                    struct ossl_ctx *octx);
ssize_t Curl_ossl_ktls_rx_recv(struct Curl_cfilter *cf,
                               struct Curl_easy *data,
                               struct ossl_ctx *octx,
                               char *buf, size_t len,
                               CURLcode *curlcode);
CURLcode Curl_ossl_ktls_rx_shutdown(struct Curl_cfilter *cf,
                                    struct Curl_easy *data,
                                    struct ossl_ctx *octx,
                                    bool send_shutdown, bool *done);
CURLcode Curl_ossl_ktls_rx_selftest(void);

#ifdef UNITTESTS
bool Curl_ossl_ktls_rx_test_recv_span(size_t len);
bool Curl_ossl_ktls_rx_test_poison_connection(void);
bool Curl_ossl_ktls_rx_test_eof_is_authenticated(bool peer_close_notify);
#ifdef CURL_OSSL_KTLS_DIRECT_RX
bool Curl_ossl_ktls_rx_test_protocol_bounds(
  long configured_min, long configured_max, long *probe_min, long *probe_max);
bool Curl_ossl_ktls_rx_test_fallback_authenticated(
  bool verifypeer, bool verifyhost, long certverifyresult);
CURLcode Curl_ossl_ktls_rx_test_restrict_ciphersuites(
  struct Curl_easy *data, SSL_CTX *ssl_ctx);
CURLcode Curl_ossl_ktls_rx_test_configure_cipher(
  struct Curl_easy *data, struct Curl_ossl_ktls_rx *rx, const char *name);
CURLcode Curl_ossl_ktls_rx_test_no_pad_error(struct Curl_easy *data,
                                             int sockerr);
#endif
#endif

#endif /* USE_OPENSSL */
#endif /* HEADER_CURL_OPENSSL_KTLS_H */
