---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_RECVBUFFERDATA
Section: 3
Source: libcurl
See-also:
  - CURLOPT_RECVBUFFERFUNCTION (3)
  - CURLOPT_RECVBUFFERRELEASEFUNCTION (3)
Protocol:
  - HTTP
Added-in: 8.22.0
---

# NAME

CURLOPT_RECVBUFFERDATA - receive-buffer callback user pointer

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_RECVBUFFERDATA, void *pointer);
~~~

# DESCRIPTION

Pass a pointer that is passed unchanged to the callbacks configured with
CURLOPT_RECVBUFFERFUNCTION(3) and
CURLOPT_RECVBUFFERRELEASEFUNCTION(3). libcurl does not use or copy the data to
which the pointer refers.

# DEFAULT

NULL

# %PROTOCOLS%

# EXAMPLE

~~~c
struct application_state {
  int buffers_available;
};
struct application_state state = { 4 };

curl_easy_setopt(curl, CURLOPT_RECVBUFFERDATA, &state);
~~~

# %AVAILABILITY%

This option is available when CURL_HAS_RECV_BUFFER_CALLBACKS is defined.

# RETURN VALUE

curl_easy_setopt(3) returns *CURLE_OK* when the option is accepted.
