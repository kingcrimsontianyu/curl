---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_SSL_KTLS_DIRECT_RX
Section: 3
Source: libcurl
See-also:
  - CURLINFO_KTLS_DIRECT_RX_STATUS (3)
  - CURLOPT_RECVBUFFERFUNCTION (3)
  - CURLOPT_SSL_OPTIONS (3)
Protocol:
  - TLS
TLS-backend:
  - OpenSSL
Added-in: 8.22.0
---

# NAME

CURLOPT_SSL_KTLS_DIRECT_RX - toggle strict direct TLS receive with kTLS

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_SSL_KTLS_DIRECT_RX,
                           long enabled);
~~~

# DESCRIPTION

Pass 1L to require the OpenSSL backend on Linux to hand TLS 1.3 receive
processing to kernel TLS. Pass 0L to disable the requirement.

This option changes only the CURLSSLOPT_KTLS_DIRECT_RX bit in the
CURLOPT_SSL_OPTIONS(3) bitmask. It preserves every other SSL behavior option
already configured on the easy handle. CURLOPT_SSL_OPTIONS(3) continues to
replace the complete bitmask, so the last setter controls the direct RX bit.

Direct RX kTLS is strict rather than best effort. The connection fails if the
requested mode cannot be activated. See CURLOPT_SSL_OPTIONS(3) for the full
set of transport, TLS, cipher, buffer-size, and peer requirements. Use
CURLINFO_KTLS_DIRECT_RX_STATUS(3) to audit activation after the transfer.

A non-TLS origin is rejected before response-buffer acquisition or application
data handoff. curl_easy_perform(3) returns CURLE_NOT_BUILT_IN and
CURLINFO_KTLS_DIRECT_RX_STATUS(3) reports CURL_KTLS_DIRECT_RX_UNAVAILABLE.
Strict mode never silently falls back to ordinary receive processing.

The capability probe preserves stricter caller TLS bounds, enforces a minimum
of TLS 1.2, and caps its maximum at TLS 1.3. A TLS 1.2-only peer is classified
as CURL_KTLS_DIRECT_RX_UNAVAILABLE only after both its certificate and
hostname have been verified. The probe closes that connection before
returning CURLE_NOT_BUILT_IN, allowing a prefer-policy caller to retry on a
fresh connection. A TLS 1.2 handshake without complete peer and hostname
verification is a hard failure and is not classified as unavailable.

After activation, a transport EOF is accepted as clean only after an
authenticated TLS close_notify alert. An abrupt TCP EOF returns
CURLE_RECV_ERROR. A transfer completely framed by HTTP, for example with
Content-Length, does not need to wait for connection shutdown.

# DEFAULT

0

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  CURL *curl = curl_easy_init();
  if(curl) {
    CURLcode result;
    curl_easy_setopt(curl, CURLOPT_URL, "https://example.com/object");
    curl_easy_setopt(curl, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_1_1);
    curl_easy_setopt(curl, CURLOPT_SSL_KTLS_DIRECT_RX, 1L);
    result = curl_easy_perform(curl);
    curl_easy_cleanup(curl);
  }
}
~~~

# %AVAILABILITY%

CURL_HAS_KTLS_DIRECT_RX declares the API surface. A libcurl build without TLS
returns CURLE_UNKNOWN_OPTION when this option is set. Runtime activation
requires Linux kernel kTLS and an OpenSSL 3.x backend. Other TLS backends
reject the transfer with CURLE_NOT_BUILT_IN.

# RETURN VALUE

curl_easy_setopt(3) returns a CURLcode indicating success or error.

CURLE_OK (0) means everything was OK, non-zero means an error occurred, see
libcurl-errors(3).
