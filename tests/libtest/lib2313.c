/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
 * SPDX-License-Identifier: curl
 ***************************************************************************/
#include "first.h"

enum t2313_mode {
  T2313_MODE_VALID,
  T2313_MODE_ACQUIRE_ONLY,
  T2313_MODE_RELEASE_ONLY,
  T2313_MODE_INVALID_LOAN,
  T2313_MODE_ACQUIRE_ERROR,
  T2313_MODE_WRITE_PAUSE,
  T2313_MODE_STARVE_ONCE,
  T2313_MODE_CONTENT_DECODE,
  T2313_MODE_STRICT_KTLS_CLEARTEXT,
  T2313_MODE_STRICT_KTLS_CLEARTEXT_NO_LOAN
};

struct t2313_ctx {
  CURL *easy;
  enum t2313_mode mode;
  unsigned char slot[4096];
  size_t acquires;
  size_t releases;
  size_t body_bytes;
  bool may_acquire;
  bool resumed;
  long ktls_status;
};

static curl_recv_buffer_result
t2313_acquire_cb(CURL *easy, size_t suggested_size,
                 struct curl_recv_buffer *buffer, void *userdata)
{
  struct t2313_ctx *ctx = userdata;
  (void)easy;
  (void)suggested_size;
  ctx->acquires++;

  if(ctx->mode == T2313_MODE_ACQUIRE_ERROR)
    return CURL_RECV_BUFFER_ERROR;
  if(ctx->mode == T2313_MODE_STARVE_ONCE && !ctx->may_acquire)
    return CURL_RECV_BUFFER_AGAIN;

  buffer->buffer = ctx->mode == T2313_MODE_INVALID_LOAN ? NULL : ctx->slot;
  buffer->length = sizeof(ctx->slot);
  buffer->token = ctx;
  return CURL_RECV_BUFFER_OK;
}

static void t2313_release_cb(CURL *easy,
                             const struct curl_recv_buffer *buffer,
                             size_t used, void *userdata)
{
  struct t2313_ctx *ctx = userdata;
  (void)easy;
  (void)used;
  if(buffer->token != ctx)
    ctx->releases = SIZE_MAX;
  else
    ctx->releases++;
}

static size_t t2313_write_cb(char *ptr, size_t size, size_t nmemb,
                             void *userdata)
{
  struct t2313_ctx *ctx = userdata;
  size_t len = size * nmemb;
  (void)ptr;
  if(ctx->mode == T2313_MODE_WRITE_PAUSE)
    return CURL_WRITEFUNC_PAUSE;
  ctx->body_bytes += len;
  return len;
}

static int t2313_progress_cb(void *userdata, curl_off_t dltotal,
                             curl_off_t dlnow, curl_off_t ultotal,
                             curl_off_t ulnow)
{
  struct t2313_ctx *ctx = userdata;
  (void)dltotal;
  (void)dlnow;
  (void)ultotal;
  (void)ulnow;
  if(ctx->mode == T2313_MODE_STARVE_ONCE && ctx->acquires &&
     !ctx->may_acquire) {
    ctx->may_acquire = TRUE;
    if(curl_easy_pause(ctx->easy, CURLPAUSE_CONT))
      return 1;
    ctx->resumed = TRUE;
  }
  return 0;
}

static CURLcode t2313_run_case(const char *URL, enum t2313_mode mode,
                               CURLcode expected)
{
  struct t2313_ctx ctx;
  CURLcode result;

  memset(&ctx, 0, sizeof(ctx));
  ctx.mode = mode;
  ctx.easy = curl_easy_init();
  if(!ctx.easy)
    return TEST_ERR_MAJOR_BAD;

  curl_easy_setopt(ctx.easy, CURLOPT_URL, URL);
  curl_easy_setopt(ctx.easy, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_1_1);
  curl_easy_setopt(ctx.easy, CURLOPT_TIMEOUT_MS, 3000L);
  curl_easy_setopt(ctx.easy, CURLOPT_WRITEFUNCTION, t2313_write_cb);
  curl_easy_setopt(ctx.easy, CURLOPT_WRITEDATA, &ctx);

  if(mode != T2313_MODE_RELEASE_ONLY && mode != T2313_MODE_VALID &&
     mode != T2313_MODE_STRICT_KTLS_CLEARTEXT_NO_LOAN)
    curl_easy_setopt(ctx.easy, CURLOPT_RECVBUFFERFUNCTION, t2313_acquire_cb);
  if(mode != T2313_MODE_ACQUIRE_ONLY && mode != T2313_MODE_VALID &&
     mode != T2313_MODE_STRICT_KTLS_CLEARTEXT_NO_LOAN)
    curl_easy_setopt(ctx.easy, CURLOPT_RECVBUFFERRELEASEFUNCTION,
                     t2313_release_cb);
  if(mode != T2313_MODE_VALID &&
     mode != T2313_MODE_STRICT_KTLS_CLEARTEXT_NO_LOAN)
    curl_easy_setopt(ctx.easy, CURLOPT_RECVBUFFERDATA, &ctx);

  if(mode == T2313_MODE_CONTENT_DECODE)
    curl_easy_setopt(ctx.easy, CURLOPT_ACCEPT_ENCODING, "");
  if(mode == T2313_MODE_STRICT_KTLS_CLEARTEXT ||
     mode == T2313_MODE_STRICT_KTLS_CLEARTEXT_NO_LOAN)
    curl_easy_setopt(ctx.easy, CURLOPT_SSL_KTLS_DIRECT_RX, 1L);
  if(mode == T2313_MODE_STARVE_ONCE) {
    curl_easy_setopt(ctx.easy, CURLOPT_XFERINFOFUNCTION, t2313_progress_cb);
    curl_easy_setopt(ctx.easy, CURLOPT_XFERINFODATA, &ctx);
    curl_easy_setopt(ctx.easy, CURLOPT_NOPROGRESS, 0L);
  }

  result = curl_easy_perform(ctx.easy);
  if(mode == T2313_MODE_STRICT_KTLS_CLEARTEXT ||
     mode == T2313_MODE_STRICT_KTLS_CLEARTEXT_NO_LOAN)
    curl_easy_getinfo(ctx.easy, CURLINFO_KTLS_DIRECT_RX_STATUS,
                      &ctx.ktls_status);
  curl_easy_cleanup(ctx.easy);

  if(result != expected) {
    curl_mfprintf(stderr, "mode %d returned %d, expected %d\n",
                  (int)mode, (int)result, (int)expected);
    return TEST_ERR_FAILURE;
  }

  switch(mode) {
  case T2313_MODE_VALID:
    if(ctx.acquires || ctx.releases || ctx.body_bytes != 4)
      return TEST_ERR_FAILURE;
    break;
  case T2313_MODE_ACQUIRE_ONLY:
  case T2313_MODE_RELEASE_ONLY:
  case T2313_MODE_CONTENT_DECODE:
    if(ctx.acquires || ctx.releases)
      return TEST_ERR_FAILURE;
    break;
  case T2313_MODE_STRICT_KTLS_CLEARTEXT:
  case T2313_MODE_STRICT_KTLS_CLEARTEXT_NO_LOAN:
    if(ctx.acquires || ctx.releases || ctx.body_bytes ||
       ctx.ktls_status != CURL_KTLS_DIRECT_RX_UNAVAILABLE)
      return TEST_ERR_FAILURE;
    break;
  case T2313_MODE_INVALID_LOAN:
    if(ctx.acquires != 1 || ctx.releases != 1 || ctx.body_bytes)
      return TEST_ERR_FAILURE;
    break;
  case T2313_MODE_ACQUIRE_ERROR:
    if(ctx.acquires != 1 || ctx.releases || ctx.body_bytes)
      return TEST_ERR_FAILURE;
    break;
  case T2313_MODE_WRITE_PAUSE:
    if(!ctx.acquires || ctx.releases != ctx.acquires || ctx.body_bytes)
      return TEST_ERR_FAILURE;
    break;
  case T2313_MODE_STARVE_ONCE:
    if(ctx.acquires < 2 || !ctx.resumed || !ctx.releases ||
       ctx.body_bytes != 4)
      return TEST_ERR_FAILURE;
    break;
  }

  return CURLE_OK;
}

static CURLcode test_lib2313(const char *URL)
{
  CURLcode result = CURLE_OK;

  global_init(CURL_GLOBAL_ALL);

  result = t2313_run_case(URL, T2313_MODE_VALID, CURLE_OK);
  if(!result)
    result = t2313_run_case(URL, T2313_MODE_ACQUIRE_ONLY,
                            CURLE_BAD_FUNCTION_ARGUMENT);
  if(!result)
    result = t2313_run_case(URL, T2313_MODE_RELEASE_ONLY,
                            CURLE_BAD_FUNCTION_ARGUMENT);
  if(!result)
    result = t2313_run_case(URL, T2313_MODE_INVALID_LOAN,
                            CURLE_BAD_FUNCTION_ARGUMENT);
  if(!result)
    result = t2313_run_case(URL, T2313_MODE_ACQUIRE_ERROR,
                            CURLE_ABORTED_BY_CALLBACK);
  if(!result)
    result = t2313_run_case(URL, T2313_MODE_WRITE_PAUSE, CURLE_WRITE_ERROR);
  if(!result)
    result = t2313_run_case(URL, T2313_MODE_STARVE_ONCE, CURLE_OK);
  if(!result)
    result = t2313_run_case(URL, T2313_MODE_CONTENT_DECODE,
                            CURLE_BAD_FUNCTION_ARGUMENT);
  if(!result)
    result = t2313_run_case(URL, T2313_MODE_STRICT_KTLS_CLEARTEXT,
                            CURLE_NOT_BUILT_IN);
  if(!result)
    result = t2313_run_case(URL, T2313_MODE_STRICT_KTLS_CLEARTEXT_NO_LOAN,
                            CURLE_NOT_BUILT_IN);

  curl_global_cleanup();
  return result;
}
