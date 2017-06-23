#ifndef HEADER_CURL_SSLUSE_H
#define HEADER_CURL_SSLUSE_H
/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2017, Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at https://curl.haxx.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 ***************************************************************************/

#include "curl_setup.h"

#ifdef USE_OPENSSL
/*
 * This header should only be needed to get included by vtls.c and openssl.c
 */

#include "urldata.h"

/* Support HTTPS-proxy */
#define HTTPS_PROXY_SUPPORT 1

const struct Curl_ssl Curl_ssl_openssl;

/* Set the API backend definition to OpenSSL */
#define CURL_SSL_BACKEND CURLSSLBACKEND_OPENSSL

/* this backend supports the CAPATH option */
#define have_curlssl_ca_path 1

/* this backend supports CURLOPT_CERTINFO */
#define have_curlssl_certinfo 1

/* this backend supports CURLOPT_SSL_CTX_* */
#define have_curlssl_ssl_ctx 1

/* this backend supports CURLOPT_PINNEDPUBLICKEY */
#define have_curlssl_pinnedpubkey 1

#define DEFAULT_CIPHER_SELECTION \
  "ALL:!EXPORT:!EXPORT40:!EXPORT56:!aNULL:!LOW:!RC4:@STRENGTH"

#endif /* USE_OPENSSL */
#endif /* HEADER_CURL_SSLUSE_H */
