---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_RECVBUFFERFUNCTION
Section: 3
Source: libcurl
See-also:
  - CURLOPT_RECVBUFFERDATA (3)
  - CURLOPT_RECVBUFFERRELEASEFUNCTION (3)
  - CURLOPT_SSL_KTLS_DIRECT_RX (3)
  - CURLOPT_WRITEFUNCTION (3)
Protocol:
  - HTTP
Added-in: 8.22.0
---

# NAME

CURLOPT_RECVBUFFERFUNCTION - lend response receive buffers to libcurl

# SYNOPSIS

~~~c
#include <curl/curl.h>

curl_recv_buffer_result acquire(CURL *easy, size_t suggested_size,
                                struct curl_recv_buffer *buffer,
                                void *userdata);

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_RECVBUFFERFUNCTION, acquire);
~~~

# DESCRIPTION

Pass a callback that lends application-owned storage to libcurl's response
receive path. This API is experimental. Applications should test
*CURL_HAS_RECV_BUFFER_CALLBACKS* before using it.

On *CURL_RECV_BUFFER_OK*, initialize all members of *buffer*. *buffer* points
to writable, CPU-addressable storage, *length* is its capacity, and *token* is
an opaque value returned unchanged to the release callback. The storage and
token must remain valid until CURLOPT_RECVBUFFERRELEASEFUNCTION(3) is called.
libcurl never frees this storage.

This facility does not require kernel TLS. It works with cleartext HTTP and
with ordinary user-space TLS. CURLOPT_SSL_KTLS_DIRECT_RX(3) can optionally be
combined with it to require strict kernel TLS receive processing.

*suggested_size* is CURLOPT_BUFFERSIZE(3). The callback may return a buffer of
a different nonzero size. libcurl can append several response reads to one
loan. The callback registered with CURLOPT_WRITEFUNCTION(3) receives body
spans in place; their pointers can therefore be mapped into the active loan.
The loan also contains response headers and transfer framing, so the released
raw byte count can exceed the body byte count.

Return *CURL_RECV_BUFFER_AGAIN* when no buffer is currently available. libcurl
suspends receive socket interest without reading or copying response bytes.
After a buffer becomes available, call curl_easy_pause(3) with
*CURLPAUSE_CONT* to resume the transfer.

Return *CURL_RECV_BUFFER_ERROR* to abort with *CURLE_ABORTED_BY_CALLBACK*.
Returning *CURL_RECV_BUFFER_OK* with a NULL pointer or zero length fails with
*CURLE_BAD_FUNCTION_ARGUMENT*.

The acquire and release callbacks must be set together. This implementation
supports HTTP/1.1 only and rejects multiplexed transfers. Content decoding is
rejected unless CURLOPT_HTTP_CONTENT_DECODING(3) is disabled. Applications
should set CURLOPT_HTTP_VERSION(3) to *CURL_HTTP_VERSION_1_1*.

Returning *CURL_WRITEFUNC_PAUSE* from a write callback is an error while this
facility is configured. Apply backpressure by returning
*CURL_RECV_BUFFER_AGAIN* from this callback instead. This rule prevents
libcurl's ordinary pause buffer from introducing a hidden copy.

# DEFAULT

NULL. libcurl uses its ordinary internal transfer buffer.

# %PROTOCOLS%

# EXAMPLE

~~~c
struct slot {
  unsigned char data[256 * 1024];
  int available;
};

static curl_recv_buffer_result acquire(CURL *easy, size_t suggested,
                                       struct curl_recv_buffer *buffer,
                                       void *userdata)
{
  struct slot *slot = userdata;
  (void)easy;
  (void)suggested;
  if(!slot->available)
    return CURL_RECV_BUFFER_AGAIN;
  slot->available = 0;
  buffer->buffer = slot->data;
  buffer->length = sizeof(slot->data);
  buffer->token = slot;
  return CURL_RECV_BUFFER_OK;
}
~~~

# %AVAILABILITY%

This option is available when CURL_HAS_RECV_BUFFER_CALLBACKS is defined.

# RETURN VALUE

curl_easy_setopt(3) returns *CURLE_OK* when the option is accepted.
