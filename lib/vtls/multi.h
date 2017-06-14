#ifndef HEADER_CURL_SSL_AND_SCHANNEL_H
#define HEADER_CURL_SSL_AND_SCHANNEL_H
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

#if defined(USE_MULTISSL)

struct connectdata;

int Curl_multi_init(void);
extern void (*Curl_multi_cleanup)(void);

extern size_t (*Curl_multi_version)(char *buffer, size_t size);
extern int (*Curl_multi_check_cxn)(struct connectdata *cxn);
extern int (*Curl_multi_shutdown)(struct connectdata *conn, int sockindex);
extern bool (*Curl_multi_data_pending)(const struct connectdata *conn,
                            int connindex);

/* return 0 if a find random is filled in */
extern CURLcode (*Curl_multi_random)(struct Curl_easy *data, unsigned char *entropy,
                          size_t length);
extern bool (*Curl_multi_cert_status_request)(void);

extern CURLcode (*Curl_multi_connect)(struct connectdata *conn, int sockindex);
extern CURLcode (*Curl_multi_connect_nonblocking)(struct connectdata *conn,
                                       int sockindex,
                                       bool *done);
extern void (*Curl_multi_close)(struct connectdata *conn, int sockindex);
extern void (*Curl_multi_close_all)(struct Curl_easy *data);
extern CURLcode (*Curl_multi_set_engine)(struct Curl_easy *data, const char *engine);
extern void (*Curl_multi_session_free)(void *ptr);
extern CURLcode (*Curl_multi_set_engine_default)(struct Curl_easy *data);
extern struct curl_slist *(*Curl_multi_engines_list)(struct Curl_easy *data);

/* Support HTTPS-proxy */
#define HTTPS_PROXY_SUPPORT 1

extern enum curlssl_features (*Curl_multi_get_features)(void);

/* API setup for OpenSSL */
#define curlssl_init Curl_multi_init
#define curlssl_cleanup Curl_multi_cleanup
#define curlssl_get_features Curl_multi_get_features
#define curlssl_connect Curl_multi_connect
#define curlssl_connect_nonblocking Curl_multi_connect_nonblocking
#define curlssl_session_free(x) Curl_multi_session_free(x)
#define curlssl_close_all Curl_multi_close_all
#define curlssl_close Curl_multi_close
#define curlssl_shutdown(x,y) Curl_multi_shutdown(x,y)
#define curlssl_set_engine(x,y) Curl_multi_set_engine(x,y)
#define curlssl_set_engine_default(x) Curl_multi_set_engine_default(x)
#define curlssl_engines_list(x) Curl_multi_engines_list(x)
#define curlssl_version Curl_multi_version
#define curlssl_check_cxn Curl_multi_check_cxn
#define curlssl_data_pending(x,y) Curl_multi_data_pending(x,y)
#define curlssl_random(x,y,z) Curl_multi_random(x,y,z)
#define curlssl_cert_status_request() Curl_multi_cert_status_request()

#define DEFAULT_CIPHER_SELECTION \
  "ALL:!EXPORT:!EXPORT40:!EXPORT56:!aNULL:!LOW:!RC4:@STRENGTH"

#endif /* USE_OPENSSL */
#endif /* HEADER_CURL_SSLUSE_H */

