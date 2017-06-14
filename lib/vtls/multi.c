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

/*
 * Source file for an SSL backend that can be configured to use either
 * OpenSSL or Secure Channel (which cURL calls WinSSL). No code but vtls.c
 * should ever call or use these functions.
 */

#include "curl_setup.h"

#define USE_OPENSSL
#define USE_SCHANNEL
#include "urldata.h"
#include "multi.h"

#include "openssl.c"
#define set_ssl_version_min_max schannel_set_ssl_version_min_max
#undef HAS_ALPN
#include "schannel.c"

static int Curl_schannel_check_cxn(struct connectdata *cxn)
{
  return -1;
}

static CURLcode Curl_schannel_random_2(struct Curl_easy *data,
		unsigned char *entropy, size_t length)
{
  return Curl_schannel_random(entropy, length);
}

static bool Curl_schannel_cert_status_request(void)
{
  return FALSE;
}

static void Curl_schannel_close_all(struct Curl_easy *data) {}

static CURLcode Curl_schannel_set_engine(struct Curl_easy *data,
		const char *engine)
{
  return CURLE_NOT_BUILT_IN;
}

static CURLcode Curl_schannel_set_engine_default(struct Curl_easy *data)
{
  return CURLE_NOT_BUILT_IN;
}

static struct curl_slist *Curl_schannel_engines_list(struct Curl_easy *data)
{
  return (struct curl_slist *)NULL;
}

static int (*init)(void);

static void multi_init(void)
{
  if (init)
    return;
  switch (Curl_ssl_backend()) {
    case CURLSSLBACKEND_OPENSSL:
      init = Curl_ossl_init;
      Curl_multi_cleanup = Curl_ossl_cleanup;
      Curl_multi_version = Curl_ossl_version;
      Curl_multi_check_cxn = Curl_ossl_check_cxn;
      Curl_multi_shutdown = Curl_ossl_shutdown;
      Curl_multi_data_pending = Curl_ossl_data_pending;
      Curl_multi_random = Curl_ossl_random;
      Curl_multi_cert_status_request = Curl_ossl_cert_status_request;
      Curl_multi_get_features = Curl_ossl_get_features;
      Curl_multi_connect = Curl_ossl_connect;
      Curl_multi_connect_nonblocking = Curl_ossl_connect_nonblocking;
      Curl_multi_close = Curl_ossl_close;
      Curl_multi_close_all = Curl_ossl_close_all;
      Curl_multi_set_engine = Curl_ossl_set_engine;
      Curl_multi_session_free = Curl_ossl_session_free;
      Curl_multi_set_engine_default = Curl_ossl_set_engine_default;
      Curl_multi_engines_list = Curl_ossl_engines_list;
      break;
    case CURLSSLBACKEND_SCHANNEL:
      init = Curl_schannel_init;
      Curl_multi_cleanup = Curl_schannel_cleanup;
      Curl_multi_version = Curl_schannel_version;
      Curl_multi_check_cxn = Curl_schannel_check_cxn;
      Curl_multi_shutdown = Curl_schannel_shutdown;
      Curl_multi_data_pending = Curl_schannel_data_pending;
      Curl_multi_random = Curl_schannel_random_2;
      Curl_multi_cert_status_request = Curl_schannel_cert_status_request;
      Curl_multi_get_features = Curl_schannel_get_features;
      Curl_multi_connect = Curl_schannel_connect;
      Curl_multi_connect_nonblocking = Curl_schannel_connect_nonblocking;
      Curl_multi_close = Curl_schannel_close;
      Curl_multi_close_all = Curl_schannel_close_all;
      Curl_multi_set_engine = Curl_schannel_set_engine;
      Curl_multi_session_free = Curl_schannel_session_free;
      Curl_multi_set_engine_default = Curl_schannel_set_engine_default;
      Curl_multi_engines_list = Curl_schannel_engines_list;
      break;
    default:
      fprintf(stderr, "fatal: unhandled SSL backend %d\n", Curl_ssl_backend());
      exit(1);
  }
}

int Curl_multi_init(void)
{
  multi_init();
  init();
}

static enum curlssl_features get_features(void)
{
  multi_init();
  return Curl_multi_get_features();
}

static size_t version(char *buffer, size_t size)
{
  multi_init();
  return Curl_multi_version(buffer, size);
}

void (*Curl_multi_cleanup)(void);

size_t (*Curl_multi_version)(char *buffer, size_t size) = version;
int (*Curl_multi_check_cxn)(struct connectdata *cxn);
int (*Curl_multi_shutdown)(struct connectdata *conn, int sockindex);
bool (*Curl_multi_data_pending)(const struct connectdata *conn,
                            int connindex);

/* return 0 if a find random is filled in */
CURLcode (*Curl_multi_random)(struct Curl_easy *data, unsigned char *entropy,
                          size_t length);
bool (*Curl_multi_cert_status_request)(void);

enum curlssl_features (*Curl_multi_get_features)(void) = get_features;

CURLcode (*Curl_multi_connect)(struct connectdata *conn, int sockindex);
CURLcode (*Curl_multi_connect_nonblocking)(struct connectdata *conn,
                                       int sockindex,
                                       bool *done);
void (*Curl_multi_close)(struct connectdata *conn, int sockindex);
void (*Curl_multi_close_all)(struct Curl_easy *data);
CURLcode (*Curl_multi_set_engine)(struct Curl_easy *data, const char *engine);
void (*Curl_multi_session_free)(void *ptr);
CURLcode (*Curl_multi_set_engine_default)(struct Curl_easy *data);
struct curl_slist *(*Curl_multi_engines_list)(struct Curl_easy *data);
