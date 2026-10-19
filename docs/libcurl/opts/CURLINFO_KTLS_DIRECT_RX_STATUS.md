---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLINFO_KTLS_DIRECT_RX_STATUS
Section: 3
Source: libcurl
See-also:
  - CURLOPT_SSL_KTLS_DIRECT_RX (3)
  - CURLOPT_SSL_OPTIONS (3)
  - CURLINFO_SSL_VERIFYRESULT (3)
Protocol:
  - TLS
TLS-backend:
  - OpenSSL
Added-in: 8.22.0
---

# NAME

CURLINFO_KTLS_DIRECT_RX_STATUS - strict direct TLS RX kTLS transfer state

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_getinfo(CURL *handle, CURLINFO_KTLS_DIRECT_RX_STATUS,
                           long *status);
~~~

# DESCRIPTION

Pass a pointer to a long. It receives one of these values for the most recent
transfer:

**CURL_KTLS_DIRECT_RX_NONE**

Direct RX kTLS was not requested, or the transfer did not reach a TLS filter
where it could be attempted.

**CURL_KTLS_DIRECT_RX_REQUESTED**

Direct RX kTLS was requested but was not activated. This state also covers TLS
authentication, integrity, protocol, configuration, and I/O failures; it is
not by itself permission to retry without direct RX.

**CURL_KTLS_DIRECT_RX_ACTIVE**

The strict Linux TLS 1.3 RX kTLS path was activated.

**CURL_KTLS_DIRECT_RX_UNAVAILABLE**

A capability or transport restriction rejected direct RX before application
data handoff. A caller with a prefer policy may retry on a fresh connection
without direct RX. This includes a TLS 1.2-only peer only when both its
certificate and hostname were verified first. TLS authentication failures and
TLS 1.2 handshakes with either verification disabled remain REQUESTED and are
hard failures, not fallback permission. A non-TLS origin is one such transport
restriction and is rejected before any response-buffer acquisition.

The ACTIVE state reports mode activation, not a per-record zero-copy
guarantee. Linux can internally retry padded TLS records through a kernel
buffer even after `TLS_RX_EXPECT_NO_PAD` was enabled successfully. Linux may
also use that copy path when libcurl requests a logical receive span smaller
than the incoming record, for example for the remaining Content-Length tail or
receive speed limiting.

ACTIVE reports activation, not successful transfer completion, and can remain
ACTIVE if the transfer later fails. In particular, an observed TCP EOF without
an authenticated close_notify fails with CURLE_RECV_ERROR.

Activation is also reported in verbose output. The strict option fails a
connection rather than silently falling back after it was requested.

# %PROTOCOLS%

# EXAMPLE

~~~c
long status = CURL_KTLS_DIRECT_RX_NONE;
curl_easy_getinfo(curl, CURLINFO_KTLS_DIRECT_RX_STATUS, &status);
~~~

# %AVAILABILITY%

# RETURN VALUE

curl_easy_getinfo(3) returns a CURLcode indicating success or error.

CURLE_OK (0) means everything was OK, non-zero means an error occurred, see
libcurl-errors(3).
