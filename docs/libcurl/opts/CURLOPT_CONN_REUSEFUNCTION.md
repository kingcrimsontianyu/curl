---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_CONN_REUSEFUNCTION
Section: 3
Source: libcurl
See-also:
  - CURLOPT_CONN_REUSEDATA (3)
  - CURLOPT_FORBID_REUSE (3)
Protocol:
  - All
Added-in: 8.22.0
---

# NAME

CURLOPT_CONN_REUSEFUNCTION - decide connection reuse after a transfer

# SYNOPSIS

~~~c
#include <curl/curl.h>

int reuse_callback(CURL *easy, curl_socket_t socket, void *clientp);

CURLcode curl_easy_setopt(CURL *easy, CURLOPT_CONN_REUSEFUNCTION,
                         reuse_callback);
~~~

# DESCRIPTION

Experimental API. Pass a callback to inspect a connection after a successful
transfer, before libcurl releases it for reuse. The callback runs outside the
connection cache lock, in the thread driving the transfer. It applies to both
the easy and multi interfaces, including connections owned by a multi handle.

Return *CURL_CONN_REUSE_KEEP* (0) to leave normal reuse decisions unchanged, or
*CURL_CONN_REUSE_RETIRE* (1) to prevent new transfers from using this connection.
Retirement closes the connection once existing transfers finish. It does not
interrupt other streams on a multiplexed connection, fail the completed
transfer, or retry its request. Other return values are treated as KEEP.

*socket* is the borrowed primary connection socket, valid only during the
callback. Do not close it, send or receive data on it, or retain it for later
use. Inspection using socket APIs and curl_easy_getinfo(3) is permitted. The
callback must not recursively drive transfers or remove or clean up handles.

*clientp* is the pointer set with CURLOPT_CONN_REUSEDATA(3).

No callback is made for failed, prematurely terminated or connect-only
transfers, or connections already marked for closure or retirement. Successful
protocol exchanges during redirects or authentication can each invoke the
callback; this is not an application request completion notification. The
socket may be connected to a proxy or use a non-TCP transport. Applications
must check whether their policy is applicable. Returning KEEP never forces an
otherwise non-reusable connection to remain open.

# DEFAULT

NULL (no callback)

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
