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

#include <stdint.h>

#define T2312_SLOT_SIZE 8192
#define T2312_READ_SIZE 1024
#define T2312_EXPECTED_BODY_SIZE 70000

CURL_EXTERN unsigned int curl_recv_buffer_build_version_v1(void);

struct t2312_recv_slot {
  unsigned char bytes[T2312_SLOT_SIZE];
  size_t generation;
  bool active;
};

struct t2312_ctx {
  struct t2312_recv_slot slots[2];
  struct t2312_recv_slot *active;
  size_t acquires;
  size_t releases;
  size_t body_bytes;
  bool callback_outside_loan;
  bool bad_release;
  bool saw_appended_reads;
};

static curl_recv_buffer_result
t2312_acquire_cb(CURL *easy, size_t suggested_size,
                 struct curl_recv_buffer *buffer, void *userdata)
{
  struct t2312_ctx *ctx = userdata;
  struct t2312_recv_slot *slot = &ctx->slots[ctx->acquires % 2];
  (void)easy;

  if(suggested_size != T2312_READ_SIZE || slot->active || ctx->active)
    return CURL_RECV_BUFFER_ERROR;

  /* The curl test HTTP server deliberately writes 20 bytes at a time. Let
   * several writes accumulate so this test also verifies that the receive
   * loop appends multiple recv() results to one loan. */
  if(!ctx->acquires)
    curlx_wait_ms(100);

  slot->active = TRUE;
  slot->generation++;
  ctx->active = slot;
  ctx->acquires++;
  buffer->buffer = slot->bytes;
  buffer->length = sizeof(slot->bytes);
  buffer->token = slot;
  return CURL_RECV_BUFFER_OK;
}

static void t2312_release_cb(CURL *easy,
                             const struct curl_recv_buffer *buffer,
                             size_t used, void *userdata)
{
  struct t2312_ctx *ctx = userdata;
  struct t2312_recv_slot *slot = buffer->token;
  (void)easy;

  if(!slot || slot != ctx->active || !slot->active ||
     buffer->buffer != slot->bytes || buffer->length != sizeof(slot->bytes) ||
     used > sizeof(slot->bytes)) {
    ctx->bad_release = TRUE;
  }
  if(used > T2312_READ_SIZE)
    ctx->saw_appended_reads = TRUE;
  if(slot)
    slot->active = FALSE;
  ctx->active = NULL;
  ctx->releases++;
}

static size_t t2312_body_cb(char *ptr, size_t size, size_t nmemb,
                            void *userdata)
{
  struct t2312_ctx *ctx = userdata;
  size_t len = size * nmemb;
  uintptr_t begin;
  uintptr_t end;
  uintptr_t span;
  size_t i;

  if(!ctx->active) {
    ctx->callback_outside_loan = TRUE;
    return 0;
  }
  begin = (uintptr_t)(void *)ctx->active->bytes;
  end = begin + sizeof(ctx->active->bytes);
  span = (uintptr_t)(void *)ptr;
  if(span < begin || span > end || len > (size_t)(end - span)) {
    ctx->callback_outside_loan = TRUE;
    return 0;
  }
  for(i = 0; i < len; ++i) {
    if((unsigned char)ptr[i] != (unsigned char)'x')
      return 0;
  }
  ctx->body_bytes += len;
  return len;
}

static size_t t2312_header_cb(char *ptr, size_t size, size_t nmemb,
                              void *userdata)
{
  (void)ptr;
  (void)userdata;
  return size * nmemb;
}

static CURLcode test_lib2312(const char *URL)
{
  CURL *easy = NULL;
  CURLcode result = CURLE_OK;
  struct t2312_ctx ctx;

  if(curl_recv_buffer_build_version_v1() != 1U)
    return TEST_ERR_FAILURE;

  memset(&ctx, 0, sizeof(ctx));
  global_init(CURL_GLOBAL_ALL);
  easy_init(easy);

  easy_setopt(easy, CURLOPT_URL, URL);
  easy_setopt(easy, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_1_1);
  easy_setopt(easy, CURLOPT_BUFFERSIZE, (long)T2312_READ_SIZE);
  easy_setopt(easy, CURLOPT_WRITEFUNCTION, t2312_body_cb);
  easy_setopt(easy, CURLOPT_WRITEDATA, &ctx);
  easy_setopt(easy, CURLOPT_HEADERFUNCTION, t2312_header_cb);
  easy_setopt(easy, CURLOPT_HEADERDATA, &ctx);
  easy_setopt(easy, CURLOPT_RECVBUFFERFUNCTION, t2312_acquire_cb);
  easy_setopt(easy, CURLOPT_RECVBUFFERRELEASEFUNCTION, t2312_release_cb);
  easy_setopt(easy, CURLOPT_RECVBUFFERDATA, &ctx);

  result = curl_easy_perform(easy);
  if(result)
    goto test_cleanup;

  if(ctx.callback_outside_loan || ctx.bad_release || ctx.active ||
     !ctx.saw_appended_reads || ctx.acquires < 2 ||
     ctx.acquires != ctx.releases ||
     ctx.body_bytes != T2312_EXPECTED_BODY_SIZE) {
    curl_mfprintf(stderr, "loan verification failed: body=%zu acquire=%zu "
                  "release=%zu outside=%d bad-release=%d appended=%d\n",
                  ctx.body_bytes, ctx.acquires, ctx.releases,
                  (int)ctx.callback_outside_loan, (int)ctx.bad_release,
                  (int)ctx.saw_appended_reads);
    result = TEST_ERR_FAILURE;
  }

test_cleanup:
  curl_easy_cleanup(easy);
  curl_global_cleanup();
  return result;
}
