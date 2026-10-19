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
#include <stdio.h>
#include <curl/curl.h>

static size_t discard_body(char *ptr, size_t size, size_t nmemb, void *data)
{
  (void)ptr;
  (void)data;
  return size * nmemb;
}

int main(int argc, char **argv)
{
  CURL *curl;
  CURLcode result;
  long status = CURL_KTLS_DIRECT_RX_NONE;

  if(argc != 2) {
    fprintf(stderr, "usage: %s https://host/object\n", argv[0]);
    return 2;
  }
  if(curl_global_init(CURL_GLOBAL_DEFAULT))
    return 2;
  curl = curl_easy_init();
  if(!curl) {
    curl_global_cleanup();
    return 2;
  }
  curl_easy_setopt(curl, CURLOPT_URL, argv[1]);
  curl_easy_setopt(curl, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_1_1);
  curl_easy_setopt(curl, CURLOPT_SSL_KTLS_DIRECT_RX, 1L);
  curl_easy_setopt(curl, CURLOPT_BUFFERSIZE, 256L * 1024L);
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, discard_body);
  curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
  result = curl_easy_perform(curl);
  curl_easy_getinfo(curl, CURLINFO_KTLS_DIRECT_RX_STATUS, &status);
  fprintf(stderr, "result=%d direct_rx_ktls_status=%ld\n",
          (int)result, status);
  curl_easy_cleanup(curl);
  curl_global_cleanup();
  return (result || status != CURL_KTLS_DIRECT_RX_ACTIVE) ? 1 : 0;
}
