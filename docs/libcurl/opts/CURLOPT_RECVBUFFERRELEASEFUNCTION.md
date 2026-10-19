---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_RECVBUFFERRELEASEFUNCTION
Section: 3
Source: libcurl
See-also:
  - CURLOPT_RECVBUFFERDATA (3)
  - CURLOPT_RECVBUFFERFUNCTION (3)
  - CURLOPT_WRITEFUNCTION (3)
Protocol:
  - HTTP
Added-in: 8.22.0
---

# NAME

CURLOPT_RECVBUFFERRELEASEFUNCTION - receive-buffer ownership callback

# SYNOPSIS

~~~c
#include <curl/curl.h>

void release(CURL *easy, const struct curl_recv_buffer *buffer,
             size_t used, void *userdata);

CURLcode curl_easy_setopt(CURL *handle,
                          CURLOPT_RECVBUFFERRELEASEFUNCTION, release);
~~~

# DESCRIPTION

Pass a callback that libcurl invokes after it has stopped referencing an
application-owned response buffer acquired with
CURLOPT_RECVBUFFERFUNCTION(3). This API is experimental.

The members of *buffer* are returned unchanged from the successful acquire.
*used* is the total number of raw response bytes written into the loan. It
includes headers and transfer framing and may be zero. Body spans were
delivered separately through CURLOPT_WRITEFUNCTION(3).

The callback is an ownership fence: after it returns, libcurl does not read or
write the loan. A release can occur after any receive-loop invocation; it does
not imply that the transfer is complete. The application may keep the buffer
unavailable while an asynchronous consumer uses it and return
*CURL_RECV_BUFFER_AGAIN* from later acquire calls. For example, a CUDA consumer
can recycle the storage only after its completion event.

The release callback is also invoked after a transfer error if an acquire had
succeeded. It cannot report an error and must not free the CURL easy handle.

# DEFAULT

NULL. The receive-buffer facility is disabled.

# %PROTOCOLS%

# EXAMPLE

~~~c
static void release(CURL *easy, const struct curl_recv_buffer *buffer,
                    size_t used, void *userdata)
{
  struct slot *slot = buffer->token;
  (void)easy;
  (void)used;
  (void)userdata;
  slot->available = 1;
}
~~~

# %AVAILABILITY%

This option is available when CURL_HAS_RECV_BUFFER_CALLBACKS is defined.

# RETURN VALUE

curl_easy_setopt(3) returns *CURLE_OK* when the option is accepted.
