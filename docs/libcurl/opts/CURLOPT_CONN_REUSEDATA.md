---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_CONN_REUSEDATA
Section: 3
Source: libcurl
See-also:
  - CURLOPT_CONN_REUSEFUNCTION (3)
Protocol:
  - All
Added-in: 8.22.0
---

# NAME

CURLOPT_CONN_REUSEDATA - user pointer for the connection reuse callback

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_setopt(CURL *easy, CURLOPT_CONN_REUSEDATA, void *pointer);
~~~

# DESCRIPTION

Pass a *pointer* to be supplied unchanged to CURLOPT_CONN_REUSEFUNCTION(3).
Libcurl does not own this pointer. Its target must remain valid until the
callback is disabled or the transfer handle is no longer in use.

# DEFAULT

NULL

# %PROTOCOLS%

# EXAMPLE

~~~c
static int reuse_callback(CURL *easy, curl_socket_t socket, void *clientp)
{
  (void)easy;
  (void)socket;
  return *(int *)clientp ? CURL_CONN_REUSE_RETIRE : CURL_CONN_REUSE_KEEP;
}

int main(void)
{
  int retire = 1;
  CURL *easy = curl_easy_init();
  if(easy) {
    curl_easy_setopt(easy, CURLOPT_URL, "https://example.com/");
    curl_easy_setopt(easy, CURLOPT_CONN_REUSEFUNCTION, reuse_callback);
    curl_easy_setopt(easy, CURLOPT_CONN_REUSEDATA, &retire);
    curl_easy_perform(easy);
    curl_easy_cleanup(easy);
  }
}
~~~

# AVAILABILITY

Experimental; not an upstream libcurl API.

# RETURN VALUE

curl_easy_setopt(3) returns a CURLcode indicating success or error.

CURLE_OK (0) means everything was OK. A non-zero result means an error occurred.
