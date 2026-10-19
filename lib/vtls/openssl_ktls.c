/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Linux TLS 1.3 RX kTLS support for the OpenSSL backend.
 *
 * Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * SPDX-License-Identifier: curl
 ***************************************************************************/

#include "curl_setup.h"

#ifdef USE_OPENSSL

#include "urldata.h"
#include "cfilters.h"
#include "connect.h"
#include "sendf.h"
#include "curl_trc.h"
#include "strerror.h"
#include "vtls.h"
#include "vtls_int.h"
#include "openssl.h"
#include "openssl_ktls.h"

#include <openssl/crypto.h>
#include <openssl/ssl.h>

#ifdef CURL_OSSL_KTLS_DIRECT_RX
#include <linux/tls.h>
#ifdef HAVE_LINUX_TCP_H
#include <linux/tcp.h>
#elif defined(HAVE_NETINET_TCP_H)
#include <netinet/tcp.h>
#endif
#include <sys/socket.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#endif

#define KTLS_PLAINTEXT_RECORD_MAX (16U * 1024U)
#define KTLS_CONTROL_READ_LIMIT 16U

#if defined(CURL_OSSL_KTLS_DIRECT_RX) || defined(UNITTESTS)
/* The configured transfer buffer must hold a maximum-sized plaintext TLS
 * record before direct RX is activated. An individual receive span is a
 * logical limit, however, and can legitimately be smaller: HTTP
 * Content-Length handling narrows the final read to the remaining body and a
 * receive speed limit can narrow any read. Linux kTLS still authenticates the
 * complete record and uses its kernel-buffer copy path when the supplied span
 * cannot support direct placement. */
static bool ktls_recv_span_is_valid(size_t len)
{
  return len != 0;
}

static bool ktls_eof_is_authenticated(const struct Curl_ossl_ktls_rx *rx)
{
  return rx->peer_close_notify;
}

/* TCP_ULP setup and TLS_RX key installation are not transactional, and an
 * installed TLS_RX key cannot be removed from a live socket. Once initial
 * installation has been attempted, an error cannot safely fall back to
 * OpenSSL on that connection. Poison it so any fallback opens a fresh TCP/TLS
 * connection instead. */
static void ktls_poison_rx_connection(struct connectdata *conn)
{
  connclose(conn);
}
#endif

#ifdef UNITTESTS
bool Curl_ossl_ktls_rx_test_recv_span(size_t len)
{
  return ktls_recv_span_is_valid(len);
}

bool Curl_ossl_ktls_rx_test_poison_connection(void)
{
  struct connectdata conn;

  memset(&conn, 0, sizeof(conn));
  ktls_poison_rx_connection(&conn);
  return conn.bits.close;
}

bool Curl_ossl_ktls_rx_test_eof_is_authenticated(bool peer_close_notify)
{
  struct Curl_ossl_ktls_rx rx;

  Curl_ossl_ktls_rx_init(&rx);
  rx.peer_close_notify = peer_close_notify;
  return ktls_eof_is_authenticated(&rx);
}
#endif

void Curl_ossl_ktls_rx_init(struct Curl_ossl_ktls_rx *rx)
{
  memset(rx, 0, sizeof(*rx));
  rx->sockfd = CURL_SOCKET_BAD;
}

void Curl_ossl_ktls_rx_cleanup(struct Curl_ossl_ktls_rx *rx)
{
  if(rx->control) {
    OPENSSL_cleanse(rx->control, CURL_OSSL_KTLS_CONTROL_MAX);
    curlx_safefree(rx->control);
  }
  OPENSSL_cleanse(rx->server_secret, sizeof(rx->server_secret));
  Curl_ossl_ktls_rx_init(rx);
}

#ifdef CURL_OSSL_KTLS_DIRECT_RX

unsigned int curl_ktls_direct_rx_build_version_v1(void)
{
  return 1U;
}

/* Direct RX currently requires TLS 1.3, but a preferred-mode capability
 * probe must be able to authenticate a TLS 1.2-only peer before reporting
 * that direct RX is unavailable. Preserve any stricter SSL_CTX policy set by
 * the caller, raise a weaker minimum to TLS 1.2, and cap an open-ended maximum
 * at TLS 1.3. */
static bool ktls_protocol_bounds(long configured_min, long configured_max,
                                 long *probe_min, long *probe_max)
{
  *probe_min = (!configured_min || configured_min < TLS1_2_VERSION) ?
    TLS1_2_VERSION : configured_min;
  *probe_max = (!configured_max || configured_max > TLS1_3_VERSION) ?
    TLS1_3_VERSION : configured_max;

  return *probe_min <= TLS1_3_VERSION &&
    *probe_max >= TLS1_2_VERSION && *probe_min <= *probe_max;
}

static bool ktls_fallback_is_authenticated(bool verifypeer, bool verifyhost,
                                           long certverifyresult)
{
  return verifypeer && verifyhost && certverifyresult == X509_V_OK;
}

/* Restrict the TLS 1.3 offer before the handshake to ciphers that the Linux
 * kTLS RX handoff below can configure. Derive the intersection from the
 * SSL_CTX after the application callback has run so an explicit caller policy
 * is never broadened. */
static CURLcode ktls_restrict_ciphersuites(struct Curl_easy *data,
                                           SSL_CTX *ssl_ctx)
{
  STACK_OF(SSL_CIPHER) *ciphers = SSL_CTX_get_ciphers(ssl_ctx);
  bool aes_128 = FALSE;
  bool aes_256 = FALSE;
  bool aes_128_first = FALSE;
  const char *selection;
  int i;

  for(i = 0; i < sk_SSL_CIPHER_num(ciphers); ++i) {
    const SSL_CIPHER *cipher = sk_SSL_CIPHER_value(ciphers, i);
    const char *name = SSL_CIPHER_get_name(cipher);

    if(!strcmp(name, "TLS_AES_128_GCM_SHA256")) {
      if(!aes_128 && !aes_256)
        aes_128_first = TRUE;
      aes_128 = TRUE;
    }
    else if(!strcmp(name, "TLS_AES_256_GCM_SHA384")) {
      aes_256 = TRUE;
    }
  }

  if(aes_128 && aes_256) {
    selection = aes_128_first ?
      "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384" :
      "TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256";
  }
  else if(aes_128)
    selection = "TLS_AES_128_GCM_SHA256";
  else if(aes_256)
    selection = "TLS_AES_256_GCM_SHA384";
  else {
    data->info.ktls_direct_rx_status = CURL_KTLS_DIRECT_RX_UNAVAILABLE;
    failf(data, "direct RX kTLS TLS 1.3 policy has no supported "
          "AES-GCM cipher suite");
    return CURLE_NOT_BUILT_IN;
  }

  if(SSL_CTX_set_ciphersuites(ssl_ctx, selection) != 1) {
    failf(data, "direct RX kTLS could not restrict TLS 1.3 ciphers to %s",
          selection);
    return CURLE_SSL_CIPHER;
  }
  infof(data, "direct RX kTLS TLS 1.3 cipher selection: %s", selection);
  return CURLE_OK;
}

#ifdef UNITTESTS
bool Curl_ossl_ktls_rx_test_protocol_bounds(
  long configured_min, long configured_max, long *probe_min, long *probe_max)
{
  return ktls_protocol_bounds(configured_min, configured_max,
                              probe_min, probe_max);
}

bool Curl_ossl_ktls_rx_test_fallback_authenticated(
  bool verifypeer, bool verifyhost, long certverifyresult)
{
  return ktls_fallback_is_authenticated(verifypeer, verifyhost,
                                        certverifyresult);
}

CURLcode Curl_ossl_ktls_rx_test_restrict_ciphersuites(
  struct Curl_easy *data, SSL_CTX *ssl_ctx)
{
  return ktls_restrict_ciphersuites(data, ssl_ctx);
}
#endif

static int ktls_hex_nibble(unsigned char c)
{
  if(c >= '0' && c <= '9')
    return c - '0';
  if(c >= 'a' && c <= 'f')
    return c - 'a' + 10;
  if(c >= 'A' && c <= 'F')
    return c - 'A' + 10;
  return -1;
}

static bool ktls_matches_hex(const unsigned char *value, size_t value_len,
                             const char *expected)
{
  size_t i;

  if(strlen(expected) != value_len * 2U)
    return FALSE;
  for(i = 0; i < value_len; ++i) {
    int high = ktls_hex_nibble((unsigned char)expected[i * 2U]);
    int low = ktls_hex_nibble((unsigned char)expected[i * 2U + 1U]);
    if(high < 0 || low < 0 ||
       value[i] != (unsigned char)((high << 4) | low))
      return FALSE;
  }
  return TRUE;
}

static void ktls_capture_secret(struct Curl_ossl_ktls_rx *rx,
                                const char *line)
{
  static const char label[] = "SERVER_TRAFFIC_SECRET_0";
  const char *p;
  const char *end;
  unsigned char decoded[CURL_OSSL_KTLS_SECRET_MAX];
  size_t encoded_len;
  size_t decoded_len;
  size_t i;

  if(strncmp(line, label, sizeof(label) - 1) ||
     line[sizeof(label) - 1] != ' ')
    return;

  p = line + sizeof(label);
  while(*p == ' ')
    ++p;
  p = strchr(p, ' '); /* skip client random */
  if(!p) {
    rx->capture_failed = TRUE;
    return;
  }
  while(*p == ' ')
    ++p;
  end = p;
  while(*end && *end != ' ')
    ++end;
  encoded_len = (size_t)(end - p);
  if(!encoded_len || (encoded_len & 1U) ||
     encoded_len / 2U > sizeof(decoded)) {
    rx->capture_failed = TRUE;
    return;
  }

  decoded_len = encoded_len / 2U;
  for(i = 0; i < decoded_len; ++i) {
    int high = ktls_hex_nibble((unsigned char)p[i * 2U]);
    int low = ktls_hex_nibble((unsigned char)p[i * 2U + 1U]);
    if(high < 0 || low < 0) {
      rx->capture_failed = TRUE;
      OPENSSL_cleanse(decoded, sizeof(decoded));
      return;
    }
    decoded[i] = (unsigned char)((high << 4) | low);
  }

  if(rx->server_secret_len &&
     (rx->server_secret_len != decoded_len ||
      CRYPTO_memcmp(rx->server_secret, decoded, decoded_len))) {
    rx->capture_failed = TRUE;
    OPENSSL_cleanse(decoded, sizeof(decoded));
    return;
  }
  memcpy(rx->server_secret, decoded, decoded_len);
  rx->server_secret_len = decoded_len;
  OPENSSL_cleanse(decoded, sizeof(decoded));
}

void Curl_ossl_ktls_keylog(struct ossl_ctx *octx, const char *line)
{
  if(!octx || !line)
    return;
  if(octx->ktls_rx.requested)
    ktls_capture_secret(&octx->ktls_rx, line);
}

static CURLcode ktls_hmac(const char *digest_name, size_t digest_len,
                          const unsigned char *key, size_t key_len,
                          const unsigned char *input, size_t input_len,
                          unsigned char *output, size_t output_cap)
{
  EVP_MAC *mac = NULL;
  EVP_MAC_CTX *ctx = NULL;
  OSSL_PARAM params[2];
  char digest[16];
  size_t digest_name_len;
  size_t output_len = 0;
  CURLcode result = CURLE_SSL_CONNECT_ERROR;

  if(output_cap < digest_len)
    return CURLE_BAD_FUNCTION_ARGUMENT;
  mac = EVP_MAC_fetch(NULL, "HMAC", NULL);
  if(!mac)
    goto out;
  ctx = EVP_MAC_CTX_new(mac);
  if(!ctx)
    goto out;
  digest_name_len = strlen(digest_name);
  if(digest_name_len >= sizeof(digest))
    goto out;
  memcpy(digest, digest_name, digest_name_len + 1);
  params[0] = OSSL_PARAM_construct_utf8_string(
    OSSL_MAC_PARAM_DIGEST, digest, 0);
  params[1] = OSSL_PARAM_construct_end();
  if(EVP_MAC_init(ctx, key, key_len, params) != 1 ||
     EVP_MAC_update(ctx, input, input_len) != 1 ||
     EVP_MAC_final(ctx, output, &output_len, output_cap) != 1 ||
     output_len != digest_len)
    goto out;
  result = CURLE_OK;
out:
  EVP_MAC_CTX_free(ctx);
  EVP_MAC_free(mac);
  return result;
}

/* RFC 8446 section 7.1, HKDF-Expand-Label with an empty Context. */
static CURLcode ktls_hkdf_expand_label(const char *digest_name,
                                       size_t digest_len,
                                       const unsigned char *secret,
                                       size_t secret_len,
                                       const char *label,
                                       unsigned char *output,
                                       size_t output_len)
{
  static const char prefix[] = "tls13 ";
  unsigned char info[256];
  unsigned char previous[CURL_OSSL_KTLS_SECRET_MAX];
  unsigned char input[512];
  size_t label_len = strlen(label);
  size_t info_len = 0;
  size_t previous_len = 0;
  size_t produced = 0;
  unsigned int counter = 1;
  CURLcode result = CURLE_OK;

  if(output_len > UINT16_MAX ||
     sizeof(prefix) - 1U + label_len > UINT8_MAX)
    return CURLE_BAD_FUNCTION_ARGUMENT;
  info[info_len++] = (unsigned char)(output_len >> 8U);
  info[info_len++] = (unsigned char)output_len;
  info[info_len++] = (unsigned char)(sizeof(prefix) - 1U + label_len);
  memcpy(info + info_len, prefix, sizeof(prefix) - 1U);
  info_len += sizeof(prefix) - 1U;
  memcpy(info + info_len, label, label_len);
  info_len += label_len;
  info[info_len++] = 0; /* empty Context */

  while(produced < output_len) {
    size_t take;
    if(counter > UINT8_MAX || previous_len + info_len + 1U > sizeof(input)) {
      result = CURLE_BAD_FUNCTION_ARGUMENT;
      break;
    }
    memcpy(input, previous, previous_len);
    memcpy(input + previous_len, info, info_len);
    input[previous_len + info_len] = (unsigned char)counter;
    result = ktls_hmac(digest_name, digest_len, secret, secret_len,
                       input, previous_len + info_len + 1U,
                       previous, sizeof(previous));
    if(result)
      break;
    previous_len = digest_len;
    take = CURLMIN(output_len - produced, previous_len);
    memcpy(output + produced, previous, take);
    produced += take;
    ++counter;
  }
  OPENSSL_cleanse(input, sizeof(input));
  OPENSSL_cleanse(previous, sizeof(previous));
  OPENSSL_cleanse(info, sizeof(info));
  return result;
}

static CURLcode ktls_configure_cipher_name(struct Curl_easy *data,
                                           struct Curl_ossl_ktls_rx *rx,
                                           const char *name)
{
  if(!strcmp(name, "TLS_AES_128_GCM_SHA256")) {
    rx->cipher = CURL_OSSL_KTLS_CIPHER_AES_128_GCM;
    rx->digest_len = 32;
    rx->key_len = TLS_CIPHER_AES_GCM_128_KEY_SIZE;
  }
  else if(!strcmp(name, "TLS_AES_256_GCM_SHA384")) {
    rx->cipher = CURL_OSSL_KTLS_CIPHER_AES_256_GCM;
    rx->digest_len = 48;
    rx->key_len = TLS_CIPHER_AES_GCM_256_KEY_SIZE;
  }
  else {
    /* No RX key has been installed yet, so a prefer-capability caller can
     * safely retry this transfer on a fresh ordinary-TLS connection. */
    data->info.ktls_direct_rx_status = CURL_KTLS_DIRECT_RX_UNAVAILABLE;
    failf(data, "direct RX kTLS requires TLS_AES_128_GCM_SHA256 or "
          "TLS_AES_256_GCM_SHA384; negotiated %s", name);
    return CURLE_NOT_BUILT_IN;
  }
  if(rx->capture_failed || rx->server_secret_len != rx->digest_len) {
    failf(data, "direct RX kTLS did not capture a valid "
          "SERVER_TRAFFIC_SECRET_0");
    return CURLE_SSL_CONNECT_ERROR;
  }
  return CURLE_OK;
}

static CURLcode ktls_configure_cipher(struct Curl_easy *data,
                                      struct ossl_ctx *octx)
{
  const SSL_CIPHER *cipher = SSL_get_current_cipher(octx->ssl);
  const char *name = cipher ? SSL_CIPHER_get_name(cipher) : "unknown";

  return ktls_configure_cipher_name(data, &octx->ktls_rx, name);
}

#ifdef UNITTESTS
CURLcode Curl_ossl_ktls_rx_test_configure_cipher(
  struct Curl_easy *data, struct Curl_ossl_ktls_rx *rx, const char *name)
{
  return ktls_configure_cipher_name(data, rx, name);
}
#endif

/* Errors that mean the running kernel cannot provide the requested facility,
 * as opposed to a TLS or key-installation integrity failure. This distinction
 * lets callers with a prefer/fallback policy retry on the ordinary TLS path;
 * CURLSSLOPT_KTLS_DIRECT_RX itself remains strict and returns the error. */
static bool ktls_is_capability_errno(int sockerr)
{
  return sockerr == ENOPROTOOPT || sockerr == EOPNOTSUPP ||
    sockerr == ENOSYS || sockerr == EPERM || sockerr == SOCKEACCES;
}

static CURLcode ktls_no_pad_error(struct Curl_easy *data, int sockerr)
{
  failf(data, "direct RX kTLS: TLS_RX_EXPECT_NO_PAD failed: %d", sockerr);
  if(ktls_is_capability_errno(sockerr)) {
    data->info.ktls_direct_rx_status = CURL_KTLS_DIRECT_RX_UNAVAILABLE;
    return CURLE_NOT_BUILT_IN;
  }
  return CURLE_SSL_CONNECT_ERROR;
}

#ifdef UNITTESTS
CURLcode Curl_ossl_ktls_rx_test_no_pad_error(struct Curl_easy *data,
                                             int sockerr)
{
  return ktls_no_pad_error(data, sockerr);
}
#endif

static CURLcode ktls_ensure_ulp(struct Curl_easy *data, curl_socket_t sockfd)
{
  char current[16] = { 0 };
  socklen_t current_len = sizeof(current);
  static const char tls_name[] = "tls";

  if(!getsockopt(sockfd, IPPROTO_TCP, TCP_ULP, current, &current_len) &&
     !strncmp(current, tls_name, sizeof(tls_name)))
    return CURLE_OK;
  if(setsockopt(sockfd, IPPROTO_TCP, TCP_ULP,
                tls_name, sizeof(tls_name)) &&
     errno != EEXIST && errno != EBUSY) {
    int sockerr = errno;
    failf(data, "direct RX kTLS: setsockopt(TCP_ULP=tls) failed: %d",
          sockerr);
    if(ktls_is_capability_errno(sockerr)) {
      data->info.ktls_direct_rx_status = CURL_KTLS_DIRECT_RX_UNAVAILABLE;
      return CURLE_NOT_BUILT_IN;
    }
    return CURLE_SSL_CONNECT_ERROR;
  }
  return CURLE_OK;
}

static CURLcode ktls_install_key(struct Curl_easy *data,
                                 struct Curl_ossl_ktls_rx *rx,
                                 const unsigned char *secret,
                                 size_t secret_len, bool initial)
{
  unsigned char key[TLS_CIPHER_AES_GCM_256_KEY_SIZE];
  unsigned char iv[12];
  const char *digest_name = rx->digest_len == 32 ? "SHA256" : "SHA384";
  CURLcode result;
  int rc = -1;
  int sockerr = 0;

  memset(key, 0, sizeof(key));
  memset(iv, 0, sizeof(iv));
  result = ktls_hkdf_expand_label(digest_name, rx->digest_len,
                                  secret, secret_len, "key",
                                  key, rx->key_len);
  if(!result)
    result = ktls_hkdf_expand_label(digest_name, rx->digest_len,
                                    secret, secret_len, "iv",
                                    iv, sizeof(iv));
  if(result)
    goto out;
  if(initial) {
    result = ktls_ensure_ulp(data, rx->sockfd);
    if(result)
      goto out;
  }

  if(rx->cipher == CURL_OSSL_KTLS_CIPHER_AES_128_GCM) {
    struct tls12_crypto_info_aes_gcm_128 info;
    memset(&info, 0, sizeof(info));
    info.info.version = TLS_1_3_VERSION;
    info.info.cipher_type = TLS_CIPHER_AES_GCM_128;
    memcpy(info.key, key, sizeof(info.key));
    memcpy(info.salt, iv, sizeof(info.salt));
    memcpy(info.iv, iv + sizeof(info.salt), sizeof(info.iv));
    rc = setsockopt(rx->sockfd, SOL_TLS, TLS_RX, &info, sizeof(info));
    sockerr = errno;
    OPENSSL_cleanse(&info, sizeof(info));
  }
  else if(rx->cipher == CURL_OSSL_KTLS_CIPHER_AES_256_GCM) {
    struct tls12_crypto_info_aes_gcm_256 info;
    memset(&info, 0, sizeof(info));
    info.info.version = TLS_1_3_VERSION;
    info.info.cipher_type = TLS_CIPHER_AES_GCM_256;
    memcpy(info.key, key, sizeof(info.key));
    memcpy(info.salt, iv, sizeof(info.salt));
    memcpy(info.iv, iv + sizeof(info.salt), sizeof(info.iv));
    rc = setsockopt(rx->sockfd, SOL_TLS, TLS_RX, &info, sizeof(info));
    sockerr = errno;
    OPENSSL_cleanse(&info, sizeof(info));
  }
  if(rc) {
    failf(data, "direct RX kTLS: %s TLS_RX key installation failed: %d",
          initial ? "initial" : "updated", sockerr);
    if(initial && ktls_is_capability_errno(sockerr)) {
      data->info.ktls_direct_rx_status = CURL_KTLS_DIRECT_RX_UNAVAILABLE;
      result = CURLE_NOT_BUILT_IN;
    }
    else
      result = CURLE_SSL_CONNECT_ERROR;
  }
out:
  OPENSSL_cleanse(key, sizeof(key));
  OPENSSL_cleanse(iv, sizeof(iv));
  return result;
}

static CURLcode ktls_update_key(struct Curl_easy *data,
                                struct Curl_ossl_ktls_rx *rx)
{
  unsigned char next[CURL_OSSL_KTLS_SECRET_MAX];
  const char *digest_name = rx->digest_len == 32 ? "SHA256" : "SHA384";
  CURLcode result;

  memset(next, 0, sizeof(next));
  result = ktls_hkdf_expand_label(digest_name, rx->digest_len,
                                  rx->server_secret, rx->server_secret_len,
                                  "traffic upd", next, rx->digest_len);
  if(!result)
    result = ktls_install_key(data, rx, next, rx->digest_len, FALSE);
  if(!result) {
    OPENSSL_cleanse(rx->server_secret, sizeof(rx->server_secret));
    memcpy(rx->server_secret, next, rx->digest_len);
    rx->server_secret_len = rx->digest_len;
    ++rx->key_updates;
  }
  OPENSSL_cleanse(next, sizeof(next));
  return result;
}

static unsigned int ktls_read_u16(const unsigned char *p)
{
  return ((unsigned int)p[0] << 8U) | p[1];
}

static size_t ktls_read_u24(const unsigned char *p)
{
  return ((size_t)p[0] << 16U) | ((size_t)p[1] << 8U) | p[2];
}

enum ktls_control_result {
  KTLS_CONTROL_CONSUMED,
  KTLS_CONTROL_CLOSE,
  KTLS_CONTROL_ERROR
};

static enum ktls_control_result
ktls_process_handshake(struct Curl_cfilter *cf, struct Curl_easy *data,
                       struct Curl_ossl_ktls_rx *rx,
                       const unsigned char *src, size_t len);

static bool ktls_valid_ticket(const unsigned char *body, size_t len)
{
  size_t off = 8;
  size_t n;
  size_t end;

  if(len < 4U + 4U + 1U + 2U + 1U + 2U)
    return FALSE;
  n = body[off++];
  if(n > len - off)
    return FALSE;
  off += n;
  if(len - off < 2)
    return FALSE;
  n = ktls_read_u16(body + off);
  off += 2;
  if(!n || n > len - off)
    return FALSE;
  off += n;
  if(len - off < 2)
    return FALSE;
  n = ktls_read_u16(body + off);
  off += 2;
  if(n != len - off)
    return FALSE;
  end = off + n;
  while(off < end) {
    if(end - off < 4)
      return FALSE;
    n = ktls_read_u16(body + off + 2);
    off += 4;
    if(n > end - off)
      return FALSE;
    off += n;
  }
  return off == end;
}

static bool ktls_valid_key_update(const unsigned char *body, size_t len)
{
  return len == 1 && body[0] <= 1;
}

CURLcode Curl_ossl_ktls_rx_selftest(void)
{
  static const unsigned char secret[32] = {
    0xa1, 0x1a, 0xf9, 0xf0, 0x55, 0x31, 0xf8, 0x56,
    0xad, 0x47, 0x11, 0x6b, 0x45, 0xa9, 0x50, 0x32,
    0x82, 0x04, 0xb4, 0xf4, 0x4b, 0xfb, 0x6b, 0x3a,
    0x4b, 0x4f, 0x1f, 0x3f, 0xcb, 0x63, 0x16, 0x43
  };
  static const unsigned char expected_key[16] = {
    0x9f, 0x02, 0x28, 0x3b, 0x6c, 0x9c, 0x07, 0xef,
    0xc2, 0x6b, 0xb9, 0xf2, 0xac, 0x92, 0xe3, 0x56
  };
  static const unsigned char expected_iv[12] = {
    0xcf, 0x78, 0x2b, 0x88, 0xdd, 0x83,
    0x54, 0x9a, 0xad, 0xf1, 0xe9, 0x84
  };
  static const unsigned char ticket[14] = {
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0xaa, 0, 0
  };
  static const unsigned char ticket_message[18] = {
    4, 0, 0, 14,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0xaa, 0, 0
  };
  static const char keylog[] =
    "SERVER_TRAFFIC_SECRET_0 "
    "0000000000000000000000000000000000000000000000000000000000000000 "
    "a11af9f05531f856ad47116b45a950328204b4f44bfb6b3a4b4f1f3fcb631643";
  struct Curl_ossl_ktls_rx rx;
  unsigned char key[16];
  unsigned char iv[12];
  unsigned char sha384_secret[48];
  unsigned char sha384_key[32];
  unsigned char sha384_iv[12];
  unsigned char sha384_update[48];
  size_t i;
  CURLcode result;

  Curl_ossl_ktls_rx_init(&rx);
  memset(key, 0, sizeof(key));
  memset(iv, 0, sizeof(iv));
  result = ktls_hkdf_expand_label("SHA256", 32, secret, sizeof(secret),
                                  "key", key, sizeof(key));
  if(!result)
    result = ktls_hkdf_expand_label("SHA256", 32, secret, sizeof(secret),
                                    "iv", iv, sizeof(iv));
  if(!result && (CRYPTO_memcmp(key, expected_key, sizeof(key)) ||
                 CRYPTO_memcmp(iv, expected_iv, sizeof(iv))))
    result = CURLE_FAILED_INIT;

  for(i = 0; i < sizeof(sha384_secret); ++i)
    sha384_secret[i] = (unsigned char)i;
  memset(sha384_key, 0, sizeof(sha384_key));
  memset(sha384_iv, 0, sizeof(sha384_iv));
  memset(sha384_update, 0, sizeof(sha384_update));
  if(!result)
    result = ktls_hkdf_expand_label("SHA384", 48,
                                    sha384_secret, sizeof(sha384_secret),
                                    "key", sha384_key, sizeof(sha384_key));
  if(!result)
    result = ktls_hkdf_expand_label("SHA384", 48,
                                    sha384_secret, sizeof(sha384_secret),
                                    "iv", sha384_iv, sizeof(sha384_iv));
  if(!result)
    result = ktls_hkdf_expand_label("SHA384", 48,
                                    sha384_secret, sizeof(sha384_secret),
                                    "traffic upd", sha384_update,
                                    sizeof(sha384_update));
  if(!result &&
     (!ktls_matches_hex(sha384_key, sizeof(sha384_key),
                        "6877d022f1c61d24ebb7487c16752d9a"
                        "4798e40431c75b39320e537c90e23225") ||
      !ktls_matches_hex(sha384_iv, sizeof(sha384_iv),
                        "42822531a0fe88648fc09e9f") ||
      !ktls_matches_hex(sha384_update, sizeof(sha384_update),
                        "401331b63e9d59f202e8f041042d9516"
                        "f4cd7fa2e2ee14631d3b49fc340d7af3"
                        "7fc2c0c9f252d8036f81ec5b85cbe5db")))
    result = CURLE_FAILED_INIT;

  ktls_capture_secret(&rx, keylog);
  if(!result && (rx.capture_failed || rx.server_secret_len != sizeof(secret) ||
                 CRYPTO_memcmp(rx.server_secret, secret, sizeof(secret))))
    result = CURLE_FAILED_INIT;
  if(!result && !ktls_valid_ticket(ticket, sizeof(ticket)))
    result = CURLE_FAILED_INIT;
  if(!result &&
     ktls_process_handshake(NULL, NULL, &rx, ticket_message, 3) !=
       KTLS_CONTROL_CONSUMED)
    result = CURLE_FAILED_INIT;
  if(!result &&
     ktls_process_handshake(NULL, NULL, &rx, ticket_message + 3,
                            sizeof(ticket_message) - 3) !=
       KTLS_CONTROL_CONSUMED)
    result = CURLE_FAILED_INIT;
  if(!result && rx.control_len)
    result = CURLE_FAILED_INIT;
  if(!result) {
    static const unsigned char update0[] = { 0 };
    static const unsigned char update1[] = { 1 };
    static const unsigned char update_bad[] = { 2 };
    if(!ktls_valid_key_update(update0, sizeof(update0)) ||
       !ktls_valid_key_update(update1, sizeof(update1)) ||
       ktls_valid_key_update(update_bad, sizeof(update_bad)) ||
       ktls_valid_key_update(update0, 0))
      result = CURLE_FAILED_INIT;
  }
  OPENSSL_cleanse(key, sizeof(key));
  OPENSSL_cleanse(iv, sizeof(iv));
  OPENSSL_cleanse(sha384_secret, sizeof(sha384_secret));
  OPENSSL_cleanse(sha384_key, sizeof(sha384_key));
  OPENSSL_cleanse(sha384_iv, sizeof(sha384_iv));
  OPENSSL_cleanse(sha384_update, sizeof(sha384_update));
  Curl_ossl_ktls_rx_cleanup(&rx);
  return result;
}

static enum ktls_control_result
ktls_process_handshake(struct Curl_cfilter *cf, struct Curl_easy *data,
                       struct Curl_ossl_ktls_rx *rx,
                       const unsigned char *src, size_t len)
{
  if(!rx->control) {
    rx->control = curlx_calloc(1, CURL_OSSL_KTLS_CONTROL_MAX);
    if(!rx->control)
      return KTLS_CONTROL_ERROR;
  }
  if(len > CURL_OSSL_KTLS_CONTROL_MAX - rx->control_len) {
    failf(data, "direct RX kTLS post-handshake message exceeds 128 KiB");
    return KTLS_CONTROL_ERROR;
  }
  memcpy(rx->control + rx->control_len, src, len);
  rx->control_len += len;

  while(rx->control_len >= 4) {
    unsigned int type = rx->control[0];
    size_t body_len = ktls_read_u24(rx->control + 1);
    size_t message_len;
    size_t remaining;
    unsigned char *body;

    if(body_len > CURL_OSSL_KTLS_CONTROL_MAX - 4U) {
      failf(data, "direct RX kTLS post-handshake length exceeds 128 KiB");
      return KTLS_CONTROL_ERROR;
    }
    message_len = 4U + body_len;
    if(rx->control_len < message_len)
      return KTLS_CONTROL_CONSUMED;
    body = rx->control + 4;
    if(type == 4) { /* NewSessionTicket */
      if(!ktls_valid_ticket(body, body_len)) {
        failf(data, "direct RX kTLS received malformed NewSessionTicket");
        return KTLS_CONTROL_ERROR;
      }
    }
    else if(type == 24) { /* KeyUpdate */
      if(!ktls_valid_key_update(body, body_len)) {
        failf(data, "direct RX kTLS received malformed KeyUpdate");
        return KTLS_CONTROL_ERROR;
      }
      if(ktls_update_key(data, rx))
        return KTLS_CONTROL_ERROR;
      if(body[0] == 1) {
        failf(data, "direct RX kTLS peer requested reciprocal KeyUpdate; "
              "closing instead of risking incoherent TX keys");
        connclose(cf->conn);
        return KTLS_CONTROL_ERROR;
      }
    }
    else {
      failf(data, "direct RX kTLS received unexpected post-handshake "
            "message type %u", type);
      return KTLS_CONTROL_ERROR;
    }
    remaining = rx->control_len - message_len;
    if(remaining)
      memmove(rx->control, rx->control + message_len, remaining);
    OPENSSL_cleanse(rx->control + remaining, rx->control_len - remaining);
    rx->control_len = remaining;
  }
  return KTLS_CONTROL_CONSUMED;
}

static enum ktls_control_result
ktls_process_control(struct Curl_cfilter *cf, struct Curl_easy *data,
                     struct Curl_ossl_ktls_rx *rx, unsigned char record_type,
                     const unsigned char *src, size_t len)
{
  ++rx->control_records;
  if(record_type == SSL3_RT_HANDSHAKE)
    return ktls_process_handshake(cf, data, rx, src, len);
  if(rx->control_len) {
    failf(data, "direct RX kTLS control record interrupted a fragmented "
          "handshake message");
    return KTLS_CONTROL_ERROR;
  }
  if(record_type == SSL3_RT_ALERT) {
    if(len != 2) {
      failf(data, "direct RX kTLS received malformed TLS alert");
      return KTLS_CONTROL_ERROR;
    }
    if(src[1] == SSL_AD_CLOSE_NOTIFY) {
      rx->peer_close_notify = TRUE;
      return KTLS_CONTROL_CLOSE;
    }
    failf(data, "direct RX kTLS alert level=%u description=%u",
          src[0], src[1]);
    return KTLS_CONTROL_ERROR;
  }
  failf(data, "direct RX kTLS received unexpected record type %u",
        record_type);
  return KTLS_CONTROL_ERROR;
}

CURLcode Curl_ossl_ktls_rx_prepare(struct Curl_cfilter *cf,
                                   struct Curl_easy *data,
                                   struct ossl_ctx *octx)
{
  struct ssl_filter_config *config = Curl_ssl_cf_get_filter_config(cf);
  struct Curl_ossl_ktls_rx *rx = &octx->ktls_rx;
  long probe_min;
  long probe_max;

  rx->requested = config->ktls_direct_rx;
  if(!rx->requested)
    return CURLE_OK;
  if(Curl_ssl_cf_is_proxy(cf)) {
    data->info.ktls_direct_rx_status = CURL_KTLS_DIRECT_RX_UNAVAILABLE;
    failf(data, "direct RX kTLS does not support TLS proxy connections");
    return CURLE_NOT_BUILT_IN;
  }
  if(!cf->next) {
    data->info.ktls_direct_rx_status = CURL_KTLS_DIRECT_RX_UNAVAILABLE;
    failf(data, "direct RX kTLS requires a connected TCP transport");
    return CURLE_NOT_BUILT_IN;
  }
  {
    struct Curl_cfilter *lower;
    for(lower = cf->next; lower; lower = lower->next) {
      if(lower->cft->flags & (CF_TYPE_SSL | CF_TYPE_PROXY)) {
        data->info.ktls_direct_rx_status = CURL_KTLS_DIRECT_RX_UNAVAILABLE;
        failf(data, "direct RX kTLS requires a direct TCP connection "
              "without nested TLS or proxy layers");
        return CURLE_NOT_BUILT_IN;
      }
    }
  }
  if(config->earlydata) {
    failf(data, "direct RX kTLS is incompatible with TLS early data");
    return CURLE_BAD_FUNCTION_ARGUMENT;
  }
  if(data->set.buffer_size < KTLS_PLAINTEXT_RECORD_MAX) {
    failf(data, "direct RX kTLS requires CURLOPT_BUFFERSIZE of at least "
          "16 KiB");
    return CURLE_BAD_FUNCTION_ARGUMENT;
  }
  if(!ktls_protocol_bounds(SSL_CTX_get_min_proto_version(octx->ssl_ctx),
                           SSL_CTX_get_max_proto_version(octx->ssl_ctx),
                           &probe_min, &probe_max)) {
    failf(data, "direct RX kTLS requires a TLS policy with at least one "
          "version from TLS 1.2 through TLS 1.3");
    return CURLE_BAD_FUNCTION_ARGUMENT;
  }
  if(SSL_CTX_set_max_proto_version(octx->ssl_ctx, probe_max) != 1 ||
     SSL_CTX_set_min_proto_version(octx->ssl_ctx, probe_min) != 1) {
    failf(data, "direct RX kTLS could not apply TLS 1.2 through TLS 1.3 "
          "probe bounds");
    return CURLE_SSL_CONNECT_ERROR;
  }
  {
    CURLcode result = ktls_restrict_ciphersuites(data, octx->ssl_ctx);
    if(result)
      return result;
  }
  SSL_CTX_set_read_ahead(octx->ssl_ctx, 0);
  SSL_CTX_set_session_cache_mode(octx->ssl_ctx, SSL_SESS_CACHE_OFF);
  SSL_CTX_set_post_handshake_auth(octx->ssl_ctx, 0);
  return CURLE_OK;
}

CURLcode Curl_ossl_ktls_rx_activate(struct Curl_cfilter *cf,
                                    struct Curl_easy *data,
                                    struct ossl_ctx *octx)
{
  struct Curl_ossl_ktls_rx *rx = &octx->ktls_rx;
  struct ssl_connect_data *connssl = cf->ctx;
  struct ssl_filter_config *conn_config = Curl_ssl_cf_get_filter_config(cf);
  struct ssl_easy_config *ssl_config = Curl_ssl_cf_get_easy_config(cf, data);
  CURLcode result;
  int one = 1;

  if(!rx->requested || rx->active)
    return CURLE_OK;
  if(SSL_version(octx->ssl) == TLS1_2_VERSION) {
    /* ossl_connect_step3 calls this only after Curl_ossl_check_peer_cert()
     * succeeds. Its success can be permissive when verification was disabled,
     * so require both verification controls and the verified chain result
     * before granting a caller permission to fall back. */
    ktls_poison_rx_connection(cf->conn);
    if(!ktls_fallback_is_authenticated(conn_config->verifypeer,
                                       conn_config->verifyhost,
                                       ssl_config->certverifyresult)) {
      failf(data, "direct RX kTLS cannot classify TLS 1.2 as unavailable "
            "without complete peer and hostname verification");
      return CURLE_PEER_FAILED_VERIFICATION;
    }
    data->info.ktls_direct_rx_status = CURL_KTLS_DIRECT_RX_UNAVAILABLE;
    failf(data, "direct RX kTLS is unavailable after authenticated TLS 1.2 "
          "negotiation");
    return CURLE_NOT_BUILT_IN;
  }
  if(SSL_version(octx->ssl) != TLS1_3_VERSION) {
    ktls_poison_rx_connection(cf->conn);
    failf(data, "direct RX kTLS negotiated unexpected protocol %s",
          SSL_get_version(octx->ssl));
    return CURLE_SSL_CONNECT_ERROR;
  }
  if(!connssl->negotiated.alpn ||
     strcmp(connssl->negotiated.alpn, ALPN_HTTP_1_1)) {
    data->info.ktls_direct_rx_status = CURL_KTLS_DIRECT_RX_UNAVAILABLE;
    failf(data, "direct RX kTLS currently requires HTTP/1.1 ALPN; got %s",
          connssl->negotiated.alpn ? connssl->negotiated.alpn : "none");
    return CURLE_NOT_BUILT_IN;
  }
  if(SSL_pending(octx->ssl) || SSL_has_pending(octx->ssl)) {
    failf(data, "direct RX kTLS refused handoff with OpenSSL input pending");
    return CURLE_SSL_CONNECT_ERROR;
  }
  result = ktls_configure_cipher(data, octx);
  if(result)
    return result;
  rx->sockfd = Curl_conn_cf_get_socket(cf->next, data);
  if(rx->sockfd == CURL_SOCKET_BAD) {
    failf(data, "direct RX kTLS could not resolve the connected TCP socket");
    return CURLE_SSL_CONNECT_ERROR;
  }
  result = ktls_install_key(data, rx, rx->server_secret,
                            rx->server_secret_len, TRUE);
  if(result) {
    ktls_poison_rx_connection(cf->conn);
    return result;
  }
  rx->installed_manually = TRUE;
  if(setsockopt(rx->sockfd, SOL_TLS, TLS_RX_EXPECT_NO_PAD,
                &one, sizeof(one))) {
    result = ktls_no_pad_error(data, errno);
    goto post_install_fail;
  }
  rx->no_pad = TRUE;
  rx->active = TRUE;
  data->info.ktls_direct_rx_status = CURL_KTLS_DIRECT_RX_ACTIVE;
  infof(data, "direct RX kTLS active: TLSv1.3 %s, recvmsg into caller "
        "buffers, TLS_RX_EXPECT_NO_PAD=yes",
        SSL_CIPHER_get_name(SSL_get_current_cipher(octx->ssl)));
  return CURLE_OK;

post_install_fail:
  ktls_poison_rx_connection(cf->conn);
  return result;
}

ssize_t Curl_ossl_ktls_rx_recv(struct Curl_cfilter *cf,
                               struct Curl_easy *data,
                               struct ossl_ctx *octx,
                               char *buf, size_t len,
                               CURLcode *curlcode)
{
  struct Curl_ossl_ktls_rx *rx = &octx->ktls_rx;
  unsigned int controls = 0;

  DEBUGASSERT(rx->active);
  data->info.ktls_direct_rx_status = CURL_KTLS_DIRECT_RX_ACTIVE;
  if(!ktls_recv_span_is_valid(len)) {
    failf(data, "direct RX kTLS received an empty receive span");
    *curlcode = CURLE_BAD_FUNCTION_ARGUMENT;
    return -1;
  }

  while(controls++ < KTLS_CONTROL_READ_LIMIT) {
    struct iovec iov;
    union {
      struct cmsghdr align;
      unsigned char bytes[CMSG_SPACE(sizeof(unsigned char))];
    } control;
    struct msghdr msg;
    struct cmsghdr *cmsg;
    ssize_t nread;
    unsigned char record_type = 0;
    bool found_type = FALSE;

    memset(&control, 0, sizeof(control));
    memset(&msg, 0, sizeof(msg));
    iov.iov_base = buf;
    iov.iov_len = len;
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control.bytes;
    msg.msg_controllen = sizeof(control.bytes);
    do {
      msg.msg_controllen = sizeof(control.bytes);
      msg.msg_flags = 0;
      ++rx->recv_calls;
      nread = recvmsg(rx->sockfd, &msg, 0);
    } while(nread < 0 && SOCKERRNO == SOCKEINTR);
    if(nread < 0) {
      int sockerr = SOCKERRNO;
      if(SOCK_EAGAIN(sockerr)) {
        *curlcode = CURLE_AGAIN;
        return -1;
      }
      if(sockerr == SOCKEMSGSIZE) {
        failf(data, "direct RX kTLS record exceeds the %zu-byte receive "
              "span", len);
        *curlcode = CURLE_RECV_ERROR;
        connclose(cf->conn);
        return -1;
      }
      failf(data, "direct RX kTLS recvmsg failed: %d", sockerr);
      *curlcode = CURLE_RECV_ERROR;
      connclose(cf->conn);
      return -1;
    }
    if(!nread) {
      if(!ktls_eof_is_authenticated(rx)) {
        failf(data, "direct RX kTLS connection closed without close_notify");
        connclose(cf->conn);
        *curlcode = CURLE_RECV_ERROR;
        return -1;
      }
      connclose(cf->conn);
      *curlcode = CURLE_OK;
      return 0;
    }
    if(msg.msg_flags & (MSG_CTRUNC | MSG_TRUNC)) {
      OPENSSL_cleanse(buf, CURLMIN((size_t)nread, len));
      failf(data, "direct RX kTLS truncated payload or ancillary record");
      *curlcode = CURLE_RECV_ERROR;
      connclose(cf->conn);
      return -1;
    }
    for(cmsg = CMSG_FIRSTHDR(&msg); cmsg; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
      if(cmsg->cmsg_level != SOL_TLS ||
         cmsg->cmsg_type != TLS_GET_RECORD_TYPE ||
         cmsg->cmsg_len != CMSG_LEN(sizeof(unsigned char)) || found_type) {
        OPENSSL_cleanse(buf, CURLMIN((size_t)nread, len));
        failf(data, "direct RX kTLS received invalid ancillary data");
        *curlcode = CURLE_RECV_ERROR;
        connclose(cf->conn);
        return -1;
      }
      record_type = *(unsigned char *)CMSG_DATA(cmsg);
      found_type = TRUE;
    }
    if(!found_type) {
      OPENSSL_cleanse(buf, CURLMIN((size_t)nread, len));
      failf(data, "direct RX kTLS omitted TLS_GET_RECORD_TYPE");
      *curlcode = CURLE_RECV_ERROR;
      connclose(cf->conn);
      return -1;
    }
    if(record_type == SSL3_RT_APPLICATION_DATA) {
      if(rx->control_len) {
        OPENSSL_cleanse(buf, CURLMIN((size_t)nread, len));
        failf(data, "direct RX kTLS application data interrupted a "
              "fragmented handshake message");
        *curlcode = CURLE_RECV_ERROR;
        connclose(cf->conn);
        return -1;
      }
      *curlcode = CURLE_OK;
      return nread;
    }
    else {
      enum ktls_control_result result =
        ktls_process_control(cf, data, rx, record_type,
                             (unsigned char *)buf, (size_t)nread);
      OPENSSL_cleanse(buf, CURLMIN((size_t)nread, len));
      if(result == KTLS_CONTROL_CLOSE) {
        connclose(cf->conn);
        *curlcode = CURLE_OK;
        return 0;
      }
      if(result == KTLS_CONTROL_ERROR) {
        connclose(cf->conn);
        *curlcode = CURLE_RECV_ERROR;
        return -1;
      }
    }
  }
  *curlcode = CURLE_AGAIN;
  return -1;
}

CURLcode Curl_ossl_ktls_rx_shutdown(struct Curl_cfilter *cf,
                                    struct Curl_easy *data,
                                    struct ossl_ctx *octx,
                                    bool send_shutdown, bool *done)
{
  struct ssl_connect_data *connssl = cf->ctx;
  char control[KTLS_PLAINTEXT_RECORD_MAX];
  CURLcode result = CURLE_OK;
  ssize_t nread;

  *done = FALSE;
  if(!send_shutdown) {
    *done = TRUE;
    return CURLE_OK;
  }
  connssl->io_need = CURL_SSL_IO_NEED_NONE;
  ERR_clear_error();
  if(!(SSL_get_shutdown(octx->ssl) & SSL_SENT_SHUTDOWN)) {
    int rc = SSL_shutdown(octx->ssl);
    if(rc < 0) {
      int err = SSL_get_error(octx->ssl, rc);
      if(err == SSL_ERROR_WANT_WRITE) {
        connssl->io_need = CURL_SSL_IO_NEED_SEND;
        return CURLE_OK;
      }
      if(err == SSL_ERROR_WANT_READ) {
        failf(data, "direct RX kTLS SSL_shutdown unexpectedly wants read "
              "before sending close_notify");
        return CURLE_SEND_ERROR;
      }
      return CURLE_SEND_ERROR;
    }
  }
  if(octx->ktls_rx.peer_close_notify) {
    *done = TRUE;
    return CURLE_OK;
  }
  nread = Curl_ossl_ktls_rx_recv(cf, data, octx, control, sizeof(control),
                                 &result);
  if(nread == 0) {
    *done = TRUE;
    return CURLE_OK;
  }
  if(nread > 0) {
    OPENSSL_cleanse(control, (size_t)nread);
    connssl->io_need = CURL_SSL_IO_NEED_RECV;
    return CURLE_OK;
  }
  if(result == CURLE_AGAIN) {
    connssl->io_need = CURL_SSL_IO_NEED_RECV;
    return CURLE_OK;
  }
  return result;
}

#else /* CURL_OSSL_KTLS_DIRECT_RX */

void Curl_ossl_ktls_keylog(struct ossl_ctx *octx, const char *line)
{
  (void)octx;
  (void)line;
}

CURLcode Curl_ossl_ktls_rx_selftest(void)
{
  return CURLE_NOT_BUILT_IN;
}

CURLcode Curl_ossl_ktls_rx_prepare(struct Curl_cfilter *cf,
                                   struct Curl_easy *data,
                                   struct ossl_ctx *octx)
{
  struct ssl_filter_config *config = Curl_ssl_cf_get_filter_config(cf);
  (void)octx;
  if(config->ktls_direct_rx) {
    data->info.ktls_direct_rx_status = CURL_KTLS_DIRECT_RX_UNAVAILABLE;
    failf(data, "direct RX kTLS requires Linux, linux/tls.h, and OpenSSL 3.x");
    return CURLE_NOT_BUILT_IN;
  }
  return CURLE_OK;
}

CURLcode Curl_ossl_ktls_rx_activate(struct Curl_cfilter *cf,
                                    struct Curl_easy *data,
                                    struct ossl_ctx *octx)
{
  (void)cf;
  (void)data;
  (void)octx;
  return CURLE_OK;
}

ssize_t Curl_ossl_ktls_rx_recv(struct Curl_cfilter *cf,
                               struct Curl_easy *data,
                               struct ossl_ctx *octx,
                               char *buf, size_t len,
                               CURLcode *curlcode)
{
  (void)cf;
  (void)data;
  (void)octx;
  (void)buf;
  (void)len;
  *curlcode = CURLE_NOT_BUILT_IN;
  return -1;
}

CURLcode Curl_ossl_ktls_rx_shutdown(struct Curl_cfilter *cf,
                                    struct Curl_easy *data,
                                    struct ossl_ctx *octx,
                                    bool send_shutdown, bool *done)
{
  (void)cf;
  (void)data;
  (void)octx;
  (void)send_shutdown;
  *done = TRUE;
  return CURLE_NOT_BUILT_IN;
}

#endif /* CURL_OSSL_KTLS_DIRECT_RX */
#endif /* USE_OPENSSL */
