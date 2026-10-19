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
#include "unitcheck.h"

#include "urldata.h"
#include "transfer.h"

#ifdef USE_OPENSSL
#include <openssl/opensslv.h>
#include <openssl/ssl.h>
#if defined(__linux__) && defined(HAVE_LINUX_TLS_H)
#include <linux/tls.h>
#ifdef HAVE_LINUX_TCP_H
#include <linux/tcp.h>
#elif defined(HAVE_NETINET_TCP_H)
#include <netinet/tcp.h>
#endif
#endif
#include "vtls/openssl_ktls.h"

#ifdef CURL_OSSL_KTLS_DIRECT_RX
static bool ssl_ctx_has_cipher(SSL_CTX *ssl_ctx, const char *expected)
{
  STACK_OF(SSL_CIPHER) *ciphers = SSL_CTX_get_ciphers(ssl_ctx);
  int i;

  for(i = 0; i < sk_SSL_CIPHER_num(ciphers); ++i) {
    const char *name = SSL_CIPHER_get_name(
      sk_SSL_CIPHER_value(ciphers, i));
    if(!strcmp(name, expected))
      return TRUE;
  }
  return FALSE;
}
#endif
#endif

static CURLcode t1694_setup(void)
{
  CURLcode result = CURLE_OK;

  global_init(CURL_GLOBAL_ALL);
  return result;
}

static void t1694_stop(void)
{
  curl_global_cleanup();
}

static CURLcode test_unit1694(const char *arg)
{
  UNITTEST_BEGIN(t1694_setup())
  struct Curl_easy *easy = curl_easy_init();
  static const curl_ktls_direct_rx_status states[] = {
    CURL_KTLS_DIRECT_RX_NONE,
    CURL_KTLS_DIRECT_RX_REQUESTED,
    CURL_KTLS_DIRECT_RX_ACTIVE,
    CURL_KTLS_DIRECT_RX_UNAVAILABLE
  };
  size_t i;

  abort_unless(easy, "curl_easy_init failed");
  {
    long initial = -1;
    CURLcode result = curl_easy_getinfo(
      easy, CURLINFO_KTLS_DIRECT_RX_STATUS, &initial);
    fail_unless(result == CURLE_OK,
                "initial CURLINFO_KTLS_DIRECT_RX_STATUS failed");
    fail_unless(initial == CURL_KTLS_DIRECT_RX_NONE,
                "new easy handle did not start with direct RX status NONE");
  }
  for(i = 0; i < CURL_ARRAYSIZE(states); ++i) {
    long actual = -1;
    CURLcode result;

    easy->info.ktls_direct_rx_status = states[i];
    result = curl_easy_getinfo(easy,
                               CURLINFO_KTLS_DIRECT_RX_STATUS,
                               &actual);
    fail_unless(result == CURLE_OK,
                "CURLINFO_KTLS_DIRECT_RX_STATUS failed");
    fail_unless(actual == (long)states[i],
                "CURLINFO_KTLS_DIRECT_RX_STATUS returned wrong state");
  }

#ifdef USE_SSL
  {
    const unsigned char preserved =
      (unsigned char)(CURLSSLOPT_NO_REVOKE |
                      CURLSSLOPT_NO_PARTIALCHAIN);
    CURLcode result;

    result = curl_easy_setopt(easy, CURLOPT_SSL_OPTIONS,
                              (long)preserved);
    abort_unless(result == CURLE_OK,
                 "setting preserved SSL options failed");
    fail_unless(easy->set.ssl.ssl_options == preserved,
                "CURLOPT_SSL_OPTIONS did not set the expected mask");

    result = curl_easy_setopt(easy, CURLOPT_SSL_KTLS_DIRECT_RX, 1L);
    abort_unless(result == CURLE_OK,
                 "enabling direct RX kTLS failed");
    fail_unless(easy->set.ssl.ssl_options ==
                  (unsigned char)(preserved | CURLSSLOPT_KTLS_DIRECT_RX),
                "direct RX kTLS replaced unrelated SSL options");

    result = curl_easy_setopt(easy, CURLOPT_SSL_KTLS_DIRECT_RX, 0L);
    abort_unless(result == CURLE_OK,
                 "disabling direct RX kTLS failed");
    fail_unless(easy->set.ssl.ssl_options == preserved,
                "disabling direct RX kTLS cleared unrelated SSL options");

    result = curl_easy_setopt(
      easy, CURLOPT_SSL_OPTIONS,
      (long)(preserved | CURLSSLOPT_KTLS_DIRECT_RX));
    abort_unless(result == CURLE_OK,
                 "setting direct RX kTLS through SSL options failed");
    fail_unless(easy->set.ssl.ssl_options ==
                  (unsigned char)(preserved | CURLSSLOPT_KTLS_DIRECT_RX),
                "the direct RX kTLS SSL option bit was not retained");

    result = curl_easy_setopt(easy, CURLOPT_SSL_OPTIONS,
                              (long)preserved);
    abort_unless(result == CURLE_OK,
                 "replacing the SSL option mask failed");
    fail_unless(easy->set.ssl.ssl_options == preserved,
                "CURLOPT_SSL_OPTIONS did not replace the complete mask");
  }
  {
    long requested = -1;
    CURLcode result;

    result = curl_easy_setopt(easy, CURLOPT_URL,
                              "https://127.0.0.1:1/");
    abort_unless(result == CURLE_OK, "setting pre-TLS test URL failed");
    result = curl_easy_setopt(easy, CURLOPT_SSL_KTLS_DIRECT_RX, 1L);
    abort_unless(result == CURLE_OK,
                 "requesting direct RX kTLS failed");
    result = Curl_pretransfer(easy);
    abort_unless(result == CURLE_OK, "Curl_pretransfer failed");
    result = curl_easy_getinfo(easy, CURLINFO_KTLS_DIRECT_RX_STATUS,
                               &requested);
    fail_unless(result == CURLE_OK,
                "pre-TLS CURLINFO_KTLS_DIRECT_RX_STATUS failed");
    fail_unless(requested == CURL_KTLS_DIRECT_RX_REQUESTED,
                "pre-TLS direct RX status was not REQUESTED");
  }
#else
  {
    CURLcode result =
      curl_easy_setopt(easy, CURLOPT_SSL_KTLS_DIRECT_RX, 1L);
    fail_unless(result == CURLE_UNKNOWN_OPTION,
                "a no-SSL build accepted direct RX kTLS");
  }
  easy->info.ktls_direct_rx_status = CURL_KTLS_DIRECT_RX_REQUESTED;
#endif
  curl_easy_reset(easy);
  {
    long reset = -1;
    CURLcode result = curl_easy_getinfo(
      easy, CURLINFO_KTLS_DIRECT_RX_STATUS, &reset);
    fail_unless(result == CURLE_OK,
                "reset CURLINFO_KTLS_DIRECT_RX_STATUS failed");
    fail_unless(reset == CURL_KTLS_DIRECT_RX_NONE,
                "curl_easy_reset did not reset direct RX status");
  }
  curl_easy_cleanup(easy);
#ifdef USE_OPENSSL
/* curl can narrow an individual receive below one TLS record for the
 * Content-Length tail or CURLOPT_MAX_RECV_SPEED_LARGE. The configured
 * transfer buffer is validated separately at activation. */
fail_unless(!Curl_ossl_ktls_rx_test_recv_span(0),
            "an empty direct RX receive span was accepted");
fail_unless(Curl_ossl_ktls_rx_test_recv_span(1),
            "a one-byte Content-Length tail was rejected");
fail_unless(Curl_ossl_ktls_rx_test_recv_span((16U * 1024U) - 1U),
            "a short Content-Length tail was rejected");
fail_unless(Curl_ossl_ktls_rx_test_recv_span(16U * 1024U),
            "a full TLS-record receive span was rejected");
fail_unless(Curl_ossl_ktls_rx_test_poison_connection(),
            "a failed RX socket-state transition did not close the "
            "connection");
fail_unless(!Curl_ossl_ktls_rx_test_eof_is_authenticated(FALSE),
            "an abrupt TCP EOF was accepted without close_notify");
fail_unless(Curl_ossl_ktls_rx_test_eof_is_authenticated(TRUE),
            "an authenticated close_notify was rejected as EOF");
#endif
#if defined(USE_OPENSSL) && defined(__linux__) && \
defined(HAVE_LINUX_TLS_H) && \
OPENSSL_VERSION_NUMBER >= 0x30000000L && \
!defined(LIBRESSL_VERSION_NUMBER) && \
!defined(OPENSSL_IS_BORINGSSL) && !defined(OPENSSL_IS_AWSLC) && \
defined(TLS_RX_EXPECT_NO_PAD) && defined(TLS_1_3_VERSION) && \
defined(TLS_CIPHER_AES_GCM_256) && defined(TCP_ULP)
fail_unless(curl_ktls_direct_rx_build_version_v1() == 1U,
            "strict RX kTLS backend link marker returned a bad version");
{
  struct Curl_easy *direct_easy = curl_easy_init();
  struct Curl_ossl_ktls_rx rx;
  CURLcode result;
  long probe_min;
  long probe_max;

  abort_unless(direct_easy, "curl_easy_init for cipher test failed");
  fail_unless(Curl_ossl_ktls_rx_test_protocol_bounds(
                0, 0, &probe_min, &probe_max) &&
                probe_min == TLS1_2_VERSION &&
                probe_max == TLS1_3_VERSION,
              "default TLS policy did not become TLS 1.2 through 1.3");
  fail_unless(Curl_ossl_ktls_rx_test_protocol_bounds(
                TLS1_3_VERSION, 0, &probe_min, &probe_max) &&
                probe_min == TLS1_3_VERSION &&
                probe_max == TLS1_3_VERSION,
              "stricter TLS 1.3 minimum was not preserved");
  fail_unless(Curl_ossl_ktls_rx_test_protocol_bounds(
                0, TLS1_2_VERSION, &probe_min, &probe_max) &&
                probe_min == TLS1_2_VERSION &&
                probe_max == TLS1_2_VERSION,
              "stricter TLS 1.2 maximum was not preserved");
  fail_unless(!Curl_ossl_ktls_rx_test_protocol_bounds(
                TLS1_3_VERSION, TLS1_2_VERSION,
                &probe_min, &probe_max),
              "an empty caller TLS policy intersection was accepted");
  fail_unless(!Curl_ossl_ktls_rx_test_protocol_bounds(
                0, TLS1_1_VERSION, &probe_min, &probe_max),
              "a TLS 1.1-only caller policy was accepted");
  fail_unless(Curl_ossl_ktls_rx_test_fallback_authenticated(
                TRUE, TRUE, X509_V_OK),
              "fully verified TLS 1.2 fallback was rejected");
  fail_unless(!Curl_ossl_ktls_rx_test_fallback_authenticated(
                FALSE, TRUE, X509_V_OK),
              "TLS 1.2 fallback without peer verification was accepted");
  fail_unless(!Curl_ossl_ktls_rx_test_fallback_authenticated(
                TRUE, FALSE, X509_V_OK),
              "TLS 1.2 fallback without hostname verification was "
              "accepted");
  fail_unless(!Curl_ossl_ktls_rx_test_fallback_authenticated(
                TRUE, TRUE, X509_V_ERR_CERT_REJECTED),
              "TLS 1.2 fallback with a rejected certificate was accepted");
  {
    SSL_CTX *ssl_ctx = SSL_CTX_new(TLS_client_method());

    abort_unless(ssl_ctx, "SSL_CTX_new for direct RX cipher test failed");
    result = Curl_ossl_ktls_rx_test_restrict_ciphersuites(direct_easy,
                                                          ssl_ctx);
    fail_unless(result == CURLE_OK,
                "the default direct RX cipher policy was rejected");
    fail_unless(ssl_ctx_has_cipher(ssl_ctx, "TLS_AES_128_GCM_SHA256") &&
                  ssl_ctx_has_cipher(ssl_ctx, "TLS_AES_256_GCM_SHA384") &&
                  !ssl_ctx_has_cipher(
                    ssl_ctx, "TLS_CHACHA20_POLY1305_SHA256"),
                "direct RX did not remove unsupported default ciphers");

    abort_unless(SSL_CTX_set_ciphersuites(
                   ssl_ctx,
                   "TLS_CHACHA20_POLY1305_SHA256:TLS_AES_256_GCM_SHA384") ==
                   1,
                 "could not configure direct RX cipher test policy");
    result = Curl_ossl_ktls_rx_test_restrict_ciphersuites(direct_easy,
                                                          ssl_ctx);
    fail_unless(result == CURLE_OK,
                "a compatible direct RX cipher policy was rejected");
    fail_unless(!ssl_ctx_has_cipher(ssl_ctx, "TLS_AES_128_GCM_SHA256") &&
                  ssl_ctx_has_cipher(ssl_ctx, "TLS_AES_256_GCM_SHA384") &&
                  !ssl_ctx_has_cipher(
                    ssl_ctx, "TLS_CHACHA20_POLY1305_SHA256"),
                "direct RX did not preserve the compatible cipher "
                "intersection");

    abort_unless(SSL_CTX_set_ciphersuites(
                   ssl_ctx, "TLS_CHACHA20_POLY1305_SHA256") == 1,
                 "could not configure incompatible cipher test policy");
    direct_easy->info.ktls_direct_rx_status = CURL_KTLS_DIRECT_RX_REQUESTED;
    result = Curl_ossl_ktls_rx_test_restrict_ciphersuites(direct_easy,
                                                          ssl_ctx);
    fail_unless(result == CURLE_NOT_BUILT_IN,
                "an incompatible direct RX cipher policy was accepted");
    fail_unless(direct_easy->info.ktls_direct_rx_status ==
                  CURL_KTLS_DIRECT_RX_UNAVAILABLE,
                "an incompatible cipher policy did not report UNAVAILABLE");
    SSL_CTX_free(ssl_ctx);
  }

  direct_easy->info.ktls_direct_rx_status = CURL_KTLS_DIRECT_RX_REQUESTED;
  Curl_ossl_ktls_rx_init(&rx);
  result = Curl_ossl_ktls_rx_test_configure_cipher(
    direct_easy, &rx, "TLS_CHACHA20_POLY1305_SHA256");
  fail_unless(result == CURLE_NOT_BUILT_IN,
              "unsupported pre-handoff cipher did not report NOT_BUILT_IN");
  fail_unless(direct_easy->info.ktls_direct_rx_status ==
                CURL_KTLS_DIRECT_RX_UNAVAILABLE,
              "unsupported pre-handoff cipher did not report UNAVAILABLE");

  direct_easy->info.ktls_direct_rx_status = CURL_KTLS_DIRECT_RX_REQUESTED;
  result = Curl_ossl_ktls_rx_test_no_pad_error(direct_easy, ENOPROTOOPT);
  fail_unless(result == CURLE_NOT_BUILT_IN,
              "unsupported no-pad facility did not report NOT_BUILT_IN");
  fail_unless(direct_easy->info.ktls_direct_rx_status ==
                CURL_KTLS_DIRECT_RX_UNAVAILABLE,
              "unsupported no-pad facility did not report UNAVAILABLE");

  direct_easy->info.ktls_direct_rx_status = CURL_KTLS_DIRECT_RX_REQUESTED;
  result = Curl_ossl_ktls_rx_test_no_pad_error(direct_easy, EPERM);
  fail_unless(result == CURLE_NOT_BUILT_IN,
              "no-pad EPERM did not report NOT_BUILT_IN");
  fail_unless(direct_easy->info.ktls_direct_rx_status ==
                CURL_KTLS_DIRECT_RX_UNAVAILABLE,
              "no-pad EPERM did not report UNAVAILABLE");

  direct_easy->info.ktls_direct_rx_status = CURL_KTLS_DIRECT_RX_REQUESTED;
  result = Curl_ossl_ktls_rx_test_no_pad_error(direct_easy, SOCKEACCES);
  fail_unless(result == CURLE_NOT_BUILT_IN,
              "no-pad EACCES did not report NOT_BUILT_IN");
  fail_unless(direct_easy->info.ktls_direct_rx_status ==
                CURL_KTLS_DIRECT_RX_UNAVAILABLE,
              "no-pad EACCES did not report UNAVAILABLE");
  Curl_ossl_ktls_rx_cleanup(&rx);
  curl_easy_cleanup(direct_easy);
  fail_unless(Curl_ossl_ktls_rx_selftest() == CURLE_OK,
              "TLS 1.3 RX kTLS derivation/framing self-test failed");
}
#else
#ifdef USE_OPENSSL
  fail_unless(Curl_ossl_ktls_rx_selftest() == CURLE_NOT_BUILT_IN,
              "unsupported RX kTLS build did not report NOT_BUILT_IN");
#else
  (void)0;
#endif
#endif
  UNITTEST_END(t1694_stop())
}
