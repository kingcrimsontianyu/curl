---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_SSL_OPTIONS
Section: 3
Source: libcurl
See-also:
  - CURLOPT_PROXY_SSL_OPTIONS (3)
  - CURLOPT_SSL_KTLS_DIRECT_RX (3)
  - CURLOPT_SSLVERSION (3)
  - CURLOPT_SSL_CIPHER_LIST (3)
Protocol:
  - TLS
TLS-backend:
  - All
Added-in: 7.25.0
---

# NAME

CURLOPT_SSL_OPTIONS - SSL behavior options

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_SSL_OPTIONS, long bitmask);
~~~

# DESCRIPTION

Pass a long with a bitmask to tell libcurl about specific SSL behaviors.
Setting this option replaces the complete SSL option bitmask. To toggle strict
direct RX kTLS without changing other SSL behavior options, use
CURLOPT_SSL_KTLS_DIRECT_RX(3). Available bits:

## CURLSSLOPT_ALLOW_BEAST

Tells libcurl to not attempt to use any workarounds for a security flaw in the
SSL3 and TLS1.0 protocols. If this option is not used or this bit is set to 0,
the SSL layer libcurl uses may use a workaround for this flaw although it
might cause interoperability problems with some (older) SSL implementations.

**WARNING:** avoiding this workaround lessens the security, and by setting
this option to 1 you ask for exactly that. This option is only supported for
Secure Transport and OpenSSL.

## CURLSSLOPT_NO_REVOKE

Tells libcurl to disable certificate revocation checks for those SSL backends
where such behavior is present. This option is only supported for Schannel
(the native Windows SSL library), with an exception in the case of Windows'
Untrusted Publishers block list which it seems cannot be bypassed.

## CURLSSLOPT_NO_PARTIALCHAIN

Tells libcurl to not accept "partial" certificate chains, which it otherwise
does by default. This option fails the certificate verification if the chain
ends with an intermediate certificate and not with a root cert.

Works with OpenSSL and its forks (BoringSSL, LibreSSL, etc). (Added in 7.68.0)

Works with Schannel if the user specified certificates to verify the peer.
(Added in 8.15.0)

## CURLSSLOPT_REVOKE_BEST_EFFORT

Tells libcurl to ignore certificate revocation checks in case of missing or
offline distribution points for those SSL backends where such behavior is
present. This option is only supported for Schannel (the native Windows SSL
library). If combined with *CURLSSLOPT_NO_REVOKE*, the latter takes
precedence. (Added in 7.70.0)

## CURLSSLOPT_NATIVE_CA

Tell libcurl to use the operating system's native CA store for certificate
verification. This option is independent of other CA certificate locations set
at run time or build time. Those locations are searched in addition to the
native CA store.

Works with wolfSSL on Windows, Linux (Debian, Fedora, Gentoo, RHEL, Ubuntu),
macOS, Android and iOS (added in 8.3.0); with GnuTLS (added in 8.5.0) and with
OpenSSL and its forks (BoringSSL, LibreSSL, etc) on Windows (Added in 7.71.0).

This works with Rustls on Windows, macOS, Android and iOS. On Linux it is
equivalent to using the Mozilla CA certificate bundle. When used with Rustls
_only_ the native CA store is consulted, not other locations set at run time or
build time. (Added in 8.13.0)

## CURLSSLOPT_AUTO_CLIENT_CERT

Tell libcurl to automatically locate and use a client certificate for
authentication, when requested by the server. This option is only supported
for Schannel (the native Windows SSL library). Prior to 7.77.0 this was the
default behavior in libcurl with Schannel. Since the server can request any
certificate that supports client authentication in the OS certificate store it
could be a privacy violation and unexpected.
(Added in 7.77.0)

## CURLSSLOPT_EARLYDATA

Tell libcurl to try sending application data as TLS1.3 early data. This option
is supported for GnuTLS, OpenSSL, quictls and wolfSSL (but not AWS-LC or
BoringSSL). It works on TCP and QUIC connections using ngtcp2.
This option works on a best effort basis,
in cases when it was not possible to send early data the request is resent
normally post-handshake.
(Added in 8.11.0 for GnuTLS and 8.13.0 for OpenSSL, quictls and wolfSSL)

## CURLSSLOPT_KTLS_DIRECT_RX

Require the OpenSSL backend on Linux to hand TLS 1.3 receive processing to
kernel TLS after the authenticated handshake. libcurl then receives typed,
authenticated TLS records with `recvmsg()` directly into the buffer supplied
by its receive caller. This avoids OpenSSL's plaintext record-buffer copy.
`TLS_RX_EXPECT_NO_PAD` asks Linux for opportunistic direct placement. If a
peer pads a record, Linux may internally retry decryption through a kernel
buffer. The same fallback can occur when libcurl intentionally requests a
short logical span, such as the remaining Content-Length tail or a
receive-speed-limited read. Option activation and
CURLINFO_KTLS_DIRECT_RX_STATUS(3) do not prove that every record avoided the
kernel fallback. Use this mode only with trusted peers: repeated padded records
can force the retry path and substantially increase TLS processing cost.

This option is deliberately strict rather than best effort. The connection
fails unless all of the following hold: an origin TLS URL over a direct,
non-proxied TCP connection, HTTP/1.1 ALPN, TLS 1.3 with AES-128-GCM-SHA256 or
AES-256-GCM-SHA384, no input retained by OpenSSL at handoff, successful Linux
`TLS_RX` installation, and successful `TLS_RX_EXPECT_NO_PAD` activation.
CURLOPT_BUFFERSIZE(3) must be at least 16 KiB when the connection is activated.
An individual receive can be shorter without weakening authentication, but
Linux may use its authenticated kernel-buffer copy path for that record.
Integrations that loan receive storage and require direct placement should
keep at least 16 KiB of writable capacity available for each receive. TLS
session resumption and post-handshake client authentication are disabled for
this mode. TLS early data must not be requested. This option does not work
with QUIC.

Before the handshake, direct RX restricts the enabled TLS 1.3 ciphers to the
intersection of the caller's policy and AES-128-GCM-SHA256 or
AES-256-GCM-SHA384. It does not enable a cipher disabled by the caller. An
empty intersection reports CURL_KTLS_DIRECT_RX_UNAVAILABLE and returns
CURLE_NOT_BUILT_IN before the TLS handshake.

The capability probe preserves any stricter TLS version policy configured by
the caller, while enforcing a minimum of TLS 1.2 and a maximum of TLS 1.3. If
a peer and its hostname are both verified and the handshake negotiates TLS
1.2, libcurl closes the connection, reports
CURL_KTLS_DIRECT_RX_UNAVAILABLE, and returns CURLE_NOT_BUILT_IN. This lets a
prefer-policy caller retry without direct RX on a fresh connection without
mistaking an unauthenticated TLS failure for a capability result. Disabling
either peer or hostname verification makes TLS 1.2 negotiation a hard failure
instead.

NewSessionTicket records are authenticated, validated, and discarded.
Receive KeyUpdate records update the kernel RX key. A peer request for a
reciprocal KeyUpdate closes the connection because OpenSSL continues to own
the transmit key generation. After activation, an observed TCP EOF is accepted
as clean only after an authenticated close_notify alert; otherwise the transfer
fails with CURLE_RECV_ERROR. A transfer completely framed by HTTP does not need
to wait for connection shutdown. Use CURLINFO_KTLS_DIRECT_RX_STATUS(3) to audit
whether the completed transfer used this path. (Added in 8.22.0)

This bit can also be enabled or disabled independently with
CURLOPT_SSL_KTLS_DIRECT_RX(3). Calls to CURLOPT_SSL_OPTIONS(3) still replace
the complete bitmask, so the last setter controls this bit.

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
    curl_easy_setopt(curl, CURLOPT_URL, "https://example.com/");
    /* weaken TLS only for use with silly servers */
    curl_easy_setopt(curl, CURLOPT_SSL_OPTIONS,
                     CURLSSLOPT_ALLOW_BEAST | CURLSSLOPT_NO_REVOKE);
    result = curl_easy_perform(curl);
    curl_easy_cleanup(curl);
  }
}
~~~

# HISTORY

**CURLSSLOPT_*** macros became `long` types in 8.15.0, prior to this version
a `long` cast was necessary when passed to curl_easy_setopt(3).

# %AVAILABILITY%

`CURLSSLOPT_KTLS_DIRECT_RX` is available when `CURL_HAS_KTLS_DIRECT_RX` is
defined, but runtime activation additionally requires Linux kernel kTLS and an
OpenSSL 3.x backend. Other TLS backends return CURLE_NOT_BUILT_IN.

# RETURN VALUE

curl_easy_setopt(3) returns a CURLcode indicating success or error.

CURLE_OK (0) means everything was OK, non-zero means an error occurred, see
libcurl-errors(3).
