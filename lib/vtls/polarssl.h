#ifndef HEADER_CURL_POLARSSL_H
#define HEADER_CURL_POLARSSL_H
/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 2012 - 2016, Daniel Stenberg, <daniel@haxx.se>, et al.
 * Copyright (C) 2010, Hoi-Ho Chan, <hoiho.chan@gmail.com>
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

#ifdef USE_POLARSSL

#include <polarssl/sha256.h>

/* Called on first use PolarSSL, setup threading if supported */
int  Curl_polarssl_init(void);
void Curl_polarssl_cleanup(void);
int Curl_polarssl_data_pending(const struct connectdata *conn, int sockindex);


CURLcode Curl_polarssl_connect(struct connectdata *conn, int sockindex);

CURLcode Curl_polarssl_connect_nonblocking(struct connectdata *conn,
                                           int sockindex,
                                           bool *done);

 /* close a SSL connection */
void Curl_polarssl_close(struct connectdata *conn, int sockindex);

void Curl_polarssl_session_free(void *ptr);
size_t Curl_polarssl_version(char *buffer, size_t size);
int Curl_polarssl_shutdown(struct connectdata *conn, int sockindex);

const struct Curl_ssl Curl_ssl_polarssl;

/* Set the API backend definition to PolarSSL */
#define CURL_SSL_BACKEND CURLSSLBACKEND_POLARSSL

/* this backend supports the CAPATH option */
#define have_curlssl_ca_path 1

/* this backends supports CURLOPT_PINNEDPUBLICKEY */
#define have_curlssl_pinnedpubkey 1

#define curlssl_sha256sum(a,b,c,d) sha256(a,b,c,0)

#endif /* USE_POLARSSL */
#endif /* HEADER_CURL_POLARSSL_H */
