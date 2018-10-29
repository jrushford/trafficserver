/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "common.h"
#include "config.h"
#include "parse.h"
#include "jwt.h"
#include "timing.h"

#include <ts/remap.h>

#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <string.h>
#include <inttypes.h>

#include <cjose/cjose.h>

struct txn_data {
  char *cookie;
  const struct signer *config_signer;
  struct jwt *jwt;
  struct strip_state *stripped_uri;
  double add_nbf;
  double add_exp;
};

/* Structure used for passing continuation data to 410 check callback */
struct txn_data *
txn_data_new(struct jwt *jwt, struct signer *signer, struct strip_state *stripped_uri, double add_nbf, double add_exp)
{
  struct txn_data *callback_data = TSmalloc(sizeof *callback_data);
  callback_data->jwt             = jwt;
  callback_data->config_signer   = signer;
  callback_data->stripped_uri    = stripped_uri;
  callback_data->add_nbf         = add_nbf;
  callback_data->add_exp         = add_exp;
  callback_data->cookie          = NULL;
  return callback_data;
}

/* JWT and Strip state must be deleted. The signer will be destroyed on config cleanup. */
void
txn_data_delete(struct txn_data *callback_data)
{
  if (callback_data->jwt != NULL) {
    jwt_delete(callback_data->jwt);
  }
  if (callback_data->stripped_uri != NULL) {
    strip_state_delete(callback_data->stripped_uri);
  }
  if (callback_data->cookie != NULL) {
    TSfree(callback_data->cookie);
  }
  TSfree(callback_data);
}

/* Plugin registration. */
TSReturnCode
TSRemapInit(TSRemapInterface *api_info, char *errbuf, int errbuf_size)
{
  if (!api_info) {
    strncpy(errbuf, "[tsremap_init] - Invalid TSRemapInterface argument", (size_t)(errbuf_size - 1));
    return TS_ERROR;
  }

  if (api_info->tsremap_version < TSREMAP_VERSION) {
    snprintf(errbuf, errbuf_size, "[TSRemapInit] - Incorrect API version %ld.%ld", api_info->tsremap_version >> 16,
             (api_info->tsremap_version & 0xffff));
    return TS_ERROR;
  }

  TSDebug(PLUGIN_NAME, "plugin is succesfully initialized");
  return TS_SUCCESS;
}

/* Create a new remap instance. *ih is passed to DoRemap and DeleteInstance. */
TSReturnCode
TSRemapNewInstance(int argc, char *argv[], void **ih, char *errbuf, int errbuf_size)
{
  if (argc != 3) {
    snprintf(errbuf, errbuf_size,
             "[TSRemapNewKeyInstance] - Argument count wrong (%d)... Need exactly two pparam= (config file name).", argc);
    return TS_ERROR;
  }

  TSDebug(PLUGIN_NAME, "Initializing remap function of %s -> %s with config from %s", argv[0], argv[1], argv[2]);

  const char *install_dir = TSInstallDirGet();
  size_t config_file_ct   = snprintf(NULL, 0, "%s/%s/%s", install_dir, "etc/trafficserver", argv[2]);
  char *config_file       = TSmalloc(config_file_ct + 1);
  (void)snprintf(config_file, config_file_ct + 1, "%s/%s/%s", install_dir, "etc/trafficserver", argv[2]);
  TSDebug(PLUGIN_NAME, "config file name: %s", config_file);
  struct config *cfg = read_config(config_file);
  if (!cfg) {
    snprintf(errbuf, errbuf_size, "Unable to open config file: \"%s\"", config_file);
    TSfree(config_file);
    return TS_ERROR;
  }
  TSfree(config_file);
  *ih = cfg;

  return TS_SUCCESS;
}

/* Delete remap instance. */
void
TSRemapDeleteInstance(void *ih)
{
  config_delete(ih);
}

/* Callback function checks if response is a 410 and issues a redirect if x1err is configured.
 * This fucntion also adds renewal tokens via cookies if need be. */
int
response_callback(TSCont cont, TSEvent event, void *edata)
{
  struct timer t;
  start_timer(&t);

  TSHttpTxn txn                  = (TSHttpTxn)edata;
  struct txn_data *callback_data = TSContDataGet(cont);
  
  TSMBuffer buffer;
  TSMLoc hdr;

  if (TSHttpTxnClientRespGet(txn, &buffer, &hdr) == TS_ERROR) {
    goto callback_done;
  }

  /* Check to see if response is 410 if jwt is included in txn_data */
  if (callback_data->jwt) {

    if (TSHttpHdrStatusGet(buffer, hdr) == 410) {
      char *re_tok_url =
        redirect_token_url_get(callback_data->jwt->x1ctx, callback_data->jwt->x1err, callback_data->config_signer->issuer,
                               callback_data->config_signer->jwk, callback_data->config_signer->alg, callback_data->add_nbf,
                               callback_data->add_exp, callback_data->stripped_uri->strip_uri, "200");
      if (!re_tok_url) {
        goto callback_done;
      }

      PluginDebug("Redirect Token for 410 callback: %s", re_tok_url);
      /* Clear all existing headers before sending back to client */
      TSMLoc old_field;
      while (TSMimeHdrFieldsCount(buffer, hdr) > 0) {
        old_field = TSMimeHdrFieldGet(buffer, hdr, 0);
        TSMimeHdrFieldDestroy(buffer, hdr, old_field);
        TSHandleMLocRelease(buffer, hdr, old_field);
      }

      if (TSHttpHdrStatusSet(buffer, hdr, 302) != TS_SUCCESS) {
        TSHandleMLocRelease(buffer, TS_NULL_MLOC, hdr);
        TSfree(re_tok_url);
        goto callback_done;
      }

      TSHttpTxnErrorBodySet(txn, TSstrdup(""), 0, NULL);

      if (TSHttpHdrReasonSet(buffer, hdr, "Found", 5) != TS_SUCCESS) {
        TSHandleMLocRelease(buffer, TS_NULL_MLOC, hdr);
        TSfree(re_tok_url);
        goto callback_done;
      }

      TSMLoc loc_field;
      if (TSMimeHdrFieldCreateNamed(buffer, hdr, "Location", 8, &loc_field) != TS_SUCCESS) {
        TSHandleMLocRelease(buffer, TS_NULL_MLOC, hdr);
        TSfree(re_tok_url);
        goto callback_done;
      }

      if (TSMimeHdrFieldAppend(buffer, hdr, loc_field) != TS_SUCCESS) {
        TSHandleMLocRelease(buffer, hdr, loc_field);
        TSHandleMLocRelease(buffer, TS_NULL_MLOC, hdr);
        TSfree(re_tok_url);
        goto callback_done;
      }
      if (TSMimeHdrFieldValueStringInsert(buffer, hdr, loc_field, 0, re_tok_url, -1) != TS_SUCCESS) {
        TSHandleMLocRelease(buffer, hdr, loc_field);
        TSHandleMLocRelease(buffer, TS_NULL_MLOC, hdr);
        TSfree(re_tok_url);
      }
      TSHandleMLocRelease(buffer, hdr, loc_field);
      TSHandleMLocRelease(buffer, TS_NULL_MLOC, hdr);
      goto callback_done;
    }
  }

  if (callback_data->cookie) {

    TSMLoc cook_field;
    if (TSMimeHdrFieldCreateNamed(buffer, hdr, "Set-Cookie", 10, &cook_field) != TS_SUCCESS) {
      TSHandleMLocRelease(buffer, TS_NULL_MLOC, hdr);
      goto callback_done;
    }

    if (TSMimeHdrFieldAppend(buffer, hdr, cook_field) != TS_SUCCESS) {
      TSHandleMLocRelease(buffer, hdr, cook_field);
      TSHandleMLocRelease(buffer, TS_NULL_MLOC, hdr);
      goto callback_done;
    }

    if (TSMimeHdrFieldValueStringInsert(buffer, hdr, cook_field, 0, callback_data->cookie, -1) != TS_SUCCESS) {
      TSHandleMLocRelease(buffer, hdr, cook_field);
      TSHandleMLocRelease(buffer, TS_NULL_MLOC, hdr);
      goto callback_done;
    }

    PluginDebug("Added cookie to request: %s", callback_data->cookie);
    TSHandleMLocRelease(buffer, hdr, cook_field);
    TSHandleMLocRelease(buffer, TS_NULL_MLOC, hdr);
  }

callback_done:
  txn_data_delete(callback_data);
  TSContDestroy(cont);
  TSHttpTxnReenable(txn, TS_EVENT_HTTP_CONTINUE);
  PluginDebug("Spent %" PRId64 " ns uri_signing callback.", mark_timer(&t));
  return 0;
}

/* Execute remap request. */
TSRemapStatus
TSRemapDoRemap(void *ih, TSHttpTxn txnp, TSRemapRequestInfo *rri)
{
  struct timer t;
  start_timer(&t);

  const int max_cpi        = 20;
  int64_t checkpoints[20]  = {0};
  int cpi                  = 0;
  int url_ct               = 0;
  const char *url          = NULL;
  TSRemapStatus status     = TSREMAP_NO_REMAP;
  struct strip_state *strp = NULL;
  bool url_tok             = false;

  /* Used to store state of redirect token values */
  struct jwt *jwt             = NULL;
  struct redir_jwt *redir_jwt = NULL;

  const char *package = "URISigningPackage";

  TSMBuffer mbuf;
  TSMLoc ul;
  TSReturnCode rc = TSHttpTxnPristineUrlGet(txnp, &mbuf, &ul);
  if (rc != TS_SUCCESS) {
    PluginError("Failed call to TSHttpTxnPristineUrlGet()");
    goto fail;
  }
  url = TSUrlStringGet(mbuf, ul, &url_ct);

  TSHandleMLocRelease(mbuf, TS_NULL_MLOC, ul);

  PluginDebug("Processing request for %.*s.", url_ct, url);
  if (cpi < max_cpi) {
    checkpoints[cpi++] = mark_timer(&t);
  }

  strp = strip_state_new(url_ct + 1);

  cjose_jws_t *jws = get_jws_from_uri(url, url_ct, package, url_ct + 1, strp);

  if((int)strp->strip_uri_ct != url_ct) {
    url_tok = true;
  }

  PluginDebug("Stripped URI after parsing: %s", strp->strip_uri);

  if (cpi < max_cpi) {
    checkpoints[cpi++] = mark_timer(&t);
  }
  int checked_cookies = 0;
  if (!jws) {
  check_cookies:
    /* There is no valid token in the url */
    ++checked_cookies;

    TSMLoc field;
    TSMBuffer buffer;
    TSMLoc hdr;

    if (TSHttpTxnClientReqGet(txnp, &buffer, &hdr) == TS_ERROR) {
      goto fail;
    }

    field = TSMimeHdrFieldFind(buffer, hdr, "Cookie", 6);
    if (field == TS_NULL_MLOC) {
      TSHandleMLocRelease(buffer, TS_NULL_MLOC, hdr);
      goto fail;
    }

    const char *client_cookie;
    int client_cookie_ct;
    client_cookie = TSMimeHdrFieldValueStringGet(buffer, hdr, field, 0, &client_cookie_ct);

    TSHandleMLocRelease(buffer, hdr, field);
    TSHandleMLocRelease(buffer, TS_NULL_MLOC, hdr);

    if (!client_cookie || !client_cookie_ct) {
      goto fail;
    }
    size_t client_cookie_sz_ct = client_cookie_ct;
  check_more_cookies:
    if (cpi < max_cpi) {
      checkpoints[cpi++] = mark_timer(&t);
    }
    jws = get_jws_from_cookie(&client_cookie, &client_cookie_sz_ct, package);
  } else {
    /* There has been a JWS found in the url */
    /* Strip the token from the URL for upstream if configured to do so.
     * The uri to use is the remapped URL and not the Pristine URL. */
    if (config_strip_token((struct config *)ih)) {
      if (url_tok){
        int map_url_ct = 0;
        char *map_url  = NULL;
        map_url        = TSUrlStringGet(rri->requestBufp, rri->requestUrl, &map_url_ct);

        PluginDebug("Stripping Token from requestUrl: %s", map_url);

        struct strip_state *map_strp = strip_state_new(map_url_ct + 1);

        cjose_jws_t *map_jws = get_jws_from_uri(map_url, map_url_ct, package, map_url_ct + 1, map_strp);
        cjose_jws_release(map_jws);

        char *strip_uri_start = map_strp->strip_uri;
        char *strip_uri_end   = &map_strp->strip_uri[map_strp->strip_uri_ct - 1 ];
        PluginDebug("Stripping token from upstream url to: %s", strip_uri_start);

        TSParseResult parse_rc = TSUrlParse(rri->requestBufp, rri->requestUrl, (const char **)&strip_uri_start, strip_uri_end);
        if (map_url != NULL) {
          TSfree(map_url);
        }
        if (map_strp != NULL) {
          strip_state_delete(map_strp);
        }

        if (parse_rc != TS_PARSE_DONE) {
          PluginDebug("Error in TSUrlParse");
          goto fail;
        }
        status = TSREMAP_DID_REMAP;
      }
    }
  }
  /* Check auth_dir and pass through if configured */
  if (uri_matches_auth_directive((struct config *)ih, url, url_ct)) {
    if (url != NULL) {
      TSfree((void *)url);
    }
    if (strp != NULL) {
      strip_state_delete(strp);
    }
    return TSREMAP_NO_REMAP;
  }
  if (!jws) {
    goto fail;
  }

  if (cpi < max_cpi) {
    checkpoints[cpi++] = mark_timer(&t);
  }

  /* A token has been found. Validating signature and claim set */
  int validate_rc;
  jwt = validate_jws(jws, (struct config *)ih, strp->strip_uri, strp->strip_uri_ct, &validate_rc);
  cjose_jws_release(jws);

  if (cpi < max_cpi) {
    checkpoints[cpi++] = mark_timer(&t);
  }

  if (validate_rc != 200) {
    /* Properly signed token was found but invalid */
    if (jwt) {
      if (jwt->x1err && jwt->x1ctx) {
        if (jwt->cdniv == -1) {
          /* If redirect token is enabled, save redirect state for future issue of redirect token*/
          if (!redir_jwt) {
            redir_jwt = parse_redir_jwt(jwt, validate_rc, strp->strip_uri);
          }
          /* Use the latest issued token's values for redirect */
          else if (jwt->iat >= redir_jwt->iat) {
            struct redir_jwt *tmp;
            tmp = parse_redir_jwt(jwt, validate_rc, redir_jwt->x1uri);
            redir_jwt_delete(redir_jwt);
            redir_jwt = tmp;
          }
        }
      }
    }
    if (!checked_cookies) {
      goto check_cookies;
    } else {
      goto check_more_cookies;
    }
  }

  /* There has been a validated JWT found in either the cookie or url */
  struct signer *signer = config_signer((struct config *)ih);
  char *renewed_token   = renew(jwt, signer->issuer, signer->jwk, signer->alg, package);

  if (cpi < max_cpi) {
    checkpoints[cpi++] = mark_timer(&t);
  }
  if (renewed_token) {
    /* Redirect renewal */
    if (jwt->cdnistt == -1) {
      PluginDebug("Renewal via Redirect with new token: %s", renewed_token);
      jwt_delete(jwt);
      size_t renew_buff_ct = strp->strip_uri_ct + strlen(renewed_token) + 2;
      char *redirect_url   = TSmalloc(renew_buff_ct);
      char *redirect_end   = redirect_url + renew_buff_ct;
      get_redirect_renew_url(strp, renewed_token, redirect_url, renew_buff_ct);
      char *redirect_start = redirect_url;
      PluginDebug("New Url: %s", redirect_url);
      rri->redirect = 1;
      TSUrlParse(rri->requestBufp, rri->requestUrl, (const char **)&redirect_start, redirect_end);
      TSHttpTxnStatusSet(txnp, TS_HTTP_STATUS_MOVED_TEMPORARILY);
      TSfree(redirect_url);
      TSfree((void *)url);
      TSfree(renewed_token);
      strip_state_delete(strp);
      return TSREMAP_DID_REMAP;
    }
  }

  int64_t last_mark = 0;
  for (int i = 0; i < cpi; ++i) {
    PluginDebug("Spent %" PRId64 " ns in checkpoint %d.", checkpoints[i] - last_mark, i);
    last_mark = checkpoints[i];
  }
  PluginDebug("Spent %" PRId64 " ns uri_signing verification of %.*s.", mark_timer(&t), url_ct, url);

  /* A valid token has been found, no need for redir_token */
  redir_jwt_delete(redir_jwt);

  /* If all checks pass and x1err is not null, schedule a redirect callback to check for 410s */
  if (jwt->cdniv == -1 && jwt->x1err) {
    PluginDebug("Scheduling a 410 check callback");
    TSCont cont                    = TSContCreate(response_callback, NULL);
    struct signer *callback_signer = config_signer((struct config *)ih);
    struct txn_data *callback_data = txn_data_new(jwt, callback_signer, strp, config_get_redir_add_nbf((struct config *)ih),
                                                  config_get_redir_add_exp((struct config *)ih));
    /* Add cookie to data if cookie renewal enabled and a new token has been generated */
    if (renewed_token && jwt->cdnistt == 1) {
      callback_data->cookie = renewed_token;
    }
    TSContDataSet(cont, callback_data);
    TSHttpTxnHookAdd(txnp, TS_HTTP_SEND_RESPONSE_HDR_HOOK, cont);
  } else if (renewed_token && jwt->cdnistt == 1) {
    /* Schedule a cookie callback */
    struct txn_data *cookie_data = TSmalloc(sizeof *cookie_data);
    cookie_data->jwt             = NULL;
    cookie_data->config_signer   = NULL;
    cookie_data->stripped_uri    = NULL;
    cookie_data->add_nbf         = NAN;
    cookie_data->add_exp         = NAN;
    cookie_data->cookie          = renewed_token;
    PluginDebug("Scheduling cookie callback with Token : %s", renewed_token);
    TSCont cookie_cont = TSContCreate(response_callback, NULL);
    TSContDataSet(cookie_cont, cookie_data);
    TSHttpTxnHookAdd(txnp, TS_HTTP_SEND_RESPONSE_HDR_HOOK, cookie_cont);
  } else {
    if (strp != NULL) {
      strip_state_delete(strp);
    }
    if (jwt) {
      jwt_delete(jwt);
    }
  }

  TSfree((void *)url);
  return status;

fail:
  /* Issue a redirect access token if need be */
  if (redir_jwt) {
    char *re_tok_url;
    struct signer *redirect_signer = config_signer((struct config *)ih);
    char rc_string[4];
    snprintf(rc_string, 4, "%d", redir_jwt->x1ec);
    re_tok_url = redirect_token_url_get(redir_jwt->x1ctx, redir_jwt->x1err, redirect_signer->issuer, redirect_signer->jwk,
                                        redirect_signer->alg, config_get_redir_add_nbf((struct config *)ih),
                                        config_get_redir_add_exp((struct config *)ih), redir_jwt->x1uri, rc_string);
    if (!re_tok_url) {
      PluginDebug("Cannot create redirect access token");
      goto redir_fail;
    }
    PluginDebug("Issuing a redirect token to %s", re_tok_url);
    char *re_tok_end   = re_tok_url + strlen(re_tok_url);
    char *re_tok_start = re_tok_url;
    rri->redirect      = 1;
    TSUrlParse(rri->requestBufp, rri->requestUrl, (const char **)&re_tok_start, re_tok_end);
    TSHttpTxnStatusSet(txnp, TS_HTTP_STATUS_MOVED_TEMPORARILY);
    TSfree(re_tok_url);
    TSfree((void *)url);
    jwt_delete(jwt);
    redir_jwt_delete(redir_jwt);
    strip_state_delete(strp);
    return TSREMAP_DID_REMAP;
  }

redir_fail:
  PluginDebug("Invalid JWT for %.*s", url_ct, url);
  TSHttpTxnStatusSet(txnp, TS_HTTP_STATUS_FORBIDDEN);
  PluginDebug("Spent %" PRId64 " ns uri_signing verification of %.*s.", mark_timer(&t), url_ct, url);

  if (jwt != NULL) {
    jwt_delete(jwt);
  }

  if (redir_jwt != NULL) {
    redir_jwt_delete(redir_jwt);
  }

  if (url != NULL) {
    TSfree((void *)url);
  }
  if (strp != NULL) {
    strip_state_delete(strp);
  }

  return TSREMAP_DID_REMAP;
}
