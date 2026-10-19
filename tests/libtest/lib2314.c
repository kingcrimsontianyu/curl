/***************************************************************************
 * Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
 * SPDX-License-Identifier: curl
 ***************************************************************************/
#include "first.h"

struct t2314_ctx {
  int decision;
  unsigned int calls;
  size_t bytes;
  bool abort_write;
  bool invalid;
};

static size_t t2314_write(char *ptr, size_t size, size_t nmemb, void *userdata)
{
  struct t2314_ctx *ctx = userdata;
  (void)ptr;
  if(ctx->abort_write)
    return CURL_WRITEFUNC_ERROR;
  ctx->bytes += size * nmemb;
  return size * nmemb;
}

static int t2314_reuse(CURL *easy, curl_socket_t socket, void *userdata)
{
  struct t2314_ctx *ctx = userdata;
  long status = 0;
  curl_off_t received = 0;
  ++ctx->calls;
  if(socket == CURL_SOCKET_BAD || ctx->bytes != 4 ||
     curl_easy_getinfo(easy, CURLINFO_RESPONSE_CODE, &status) ||
     status != 200 ||
     curl_easy_getinfo(easy, CURLINFO_SIZE_DOWNLOAD_T, &received) ||
     received != 4)
    ctx->invalid = TRUE;
  return ctx->decision;
}

static CURLcode t2314_case(const char *URL, bool multi_api, bool enabled,
                           int decision, bool abort_write)
{
  CURLM *multi = curl_multi_init();
  CURL *easy = curl_easy_init();
  struct t2314_ctx ctx;
  CURLcode result = CURLE_OK;
  long connections = 0;
  unsigned int i;
  memset(&ctx, 0, sizeof(ctx));
  ctx.decision = decision;
  ctx.abort_write = abort_write;
  if(!multi || !easy) {
    result = TEST_ERR_MAJOR_BAD;
    goto out;
  }
  for(i = 0; i < 2; ++i) {
    long opened = 0;
    ctx.bytes = 0;
    curl_easy_reset(easy);
    curl_easy_setopt(easy, CURLOPT_URL, URL);
    curl_easy_setopt(easy, CURLOPT_PROXY, "");
    curl_easy_setopt(easy, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_1_1);
    curl_easy_setopt(easy, CURLOPT_TIMEOUT_MS, 3000L);
    curl_easy_setopt(easy, CURLOPT_WRITEFUNCTION, t2314_write);
    curl_easy_setopt(easy, CURLOPT_WRITEDATA, &ctx);
    if(enabled) {
      curl_easy_setopt(easy, CURLOPT_CONN_REUSEFUNCTION, t2314_reuse);
      curl_easy_setopt(easy, CURLOPT_CONN_REUSEDATA, &ctx);
    }
    if(multi_api) {
      int running = 0;
      int remaining;
      CURLMsg *msg;
      CURLMcode mc = curl_multi_add_handle(multi, easy);
      do {
        if(!mc)
          mc = curl_multi_perform(multi, &running);
        if(!mc && running)
          mc = curl_multi_poll(multi, NULL, 0, 50, NULL);
      } while(!mc && running);
      msg = curl_multi_info_read(multi, &remaining);
      result = (!mc && msg && msg->msg == CURLMSG_DONE) ?
        msg->data.result : TEST_ERR_MAJOR_BAD;
      curl_multi_remove_handle(multi, easy);
    }
    else
      result = curl_easy_perform(easy);
    if(result != (abort_write ? CURLE_WRITE_ERROR : CURLE_OK)) {
      curl_mfprintf(stderr, "transfer failed: multi=%d enabled=%d decision=%d "
                    "abort=%d result=%d\n", multi_api, enabled, decision,
                    abort_write, result);
      goto out;
    }
    curl_easy_getinfo(easy, CURLINFO_NUM_CONNECTS, &opened);
    connections += opened;
    /* Destroy the easy handle to exercise the multi-owned connection cache. */
    if(multi_api) {
      curl_easy_cleanup(easy);
      easy = curl_easy_init();
      if(!easy) {
        result = TEST_ERR_MAJOR_BAD;
        goto out;
      }
    }
  }
  if(ctx.invalid || ctx.calls != ((enabled && !abort_write) ? 2U : 0U) ||
     connections != ((abort_write || (enabled &&
                      decision == CURL_CONN_REUSE_RETIRE)) ? 2 : 1)) {
    curl_mfprintf(stderr, "reuse mismatch: multi=%d enabled=%d decision=%d "
                  "abort=%d invalid=%d calls=%u connections=%ld\n", multi_api,
                  enabled, decision, abort_write, ctx.invalid, ctx.calls,
                  connections);
    result = TEST_ERR_MAJOR_BAD;
  }
  else
    result = CURLE_OK;
out:
  curl_easy_cleanup(easy);
  curl_multi_cleanup(multi);
  return result;
}

static CURLcode test_lib2314(const char *URL)
{
  CURLcode result;
  int multi_api;
  global_init(CURL_GLOBAL_ALL);
  for(multi_api = 0; multi_api < 2; ++multi_api) {
    result = t2314_case(URL, multi_api != 0, FALSE, 0, FALSE);
    if(result)
      goto out;
    result = t2314_case(URL, multi_api != 0, TRUE,
                        CURL_CONN_REUSE_KEEP, FALSE);
    if(result)
      goto out;
    result = t2314_case(URL, multi_api != 0, TRUE,
                        CURL_CONN_REUSE_RETIRE, FALSE);
    if(result)
      goto out;
    result = t2314_case(URL, multi_api != 0, TRUE, 99, FALSE);
    if(result)
      goto out;
    result = t2314_case(URL, multi_api != 0, TRUE,
                        CURL_CONN_REUSE_RETIRE, TRUE);
    if(result)
      goto out;
  }
out:
  curl_global_cleanup();
  return result;
}
