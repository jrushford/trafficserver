/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the
 * License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

#include <string.h>

#include "ts/ts.h"
#include "ts/remap.h"

#include "ch_pselect.h"
#include "ch_config.h"

namespace
{
void
handle_server_read_response(TSHttpTxn txnp, const CHConfig *config)
{
  ;
}

int
transaction_handler(TSCont contp, TSEvent event, void *edata)
{
  TSHttpTxn txnp   = static_cast<TSHttpTxn>(edata);
  CHConfig *config = static_cast<CHConfig *>(TSContDataGet(contp));

  switch (event) {
  case TS_EVENT_HTTP_READ_RESPONSE_HDR:
    CH_Debug("handling server read response");
    handle_server_read_response(txnp, config);
    break;
  case TS_EVENT_HTTP_TXN_CLOSE:
    CH_Debug("handling transaction close");
    if (config != nullptr) {
      TSContDataSet(contp, nullptr);
    }
    TSContDestroy(contp);
    break;
  default:
    CH_Debug("unexpected event");
    break;
  }

  TSHttpTxnReenable(txnp, TS_EVENT_HTTP_CONTINUE);

  return TS_SUCCESS;
}
} // namespace

/**
 * Delete Remap instance
 */
void
TSRemapDeleteInstance(void *ih)
{
  CHConfig *config = static_cast<CHConfig *>(ih);

  if (config != nullptr) {
    CH_Debug("freed  config for remap, config->remap_from_url: %s, config->remap_to_url: %s", config->remap_from_url.c_str(),
             config->remap_to_url.c_str());
  }

  if (config != nullptr) {
    delete config;
  }
}

/**
 * Remap entry point.
 */
TSRemapStatus
TSRemapDoRemap(void *ih, TSHttpTxn txnp, TSRemapRequestInfo *rri)
{
  int pathLen    = 0;
  uint64_t sm_id = TSHttpTxnIdGet(txnp);
  LookupResult result;
  CHConfig *config = static_cast<CHConfig *>(ih);
  TSCont txn_contp = nullptr;

  const char *path = TSUrlPathGet(rri->requestBufp, rri->requestUrl, &pathLen);
  if (path == nullptr) {
    CH_Error("[%ld] - unable to get the URL request path.", sm_id);
    return TSREMAP_NO_REMAP;
  }
  std::string requestPath(path, pathLen);

  config->findNextHop(txnp, requestPath, result);

  txn_contp = TSContCreate(static_cast<TSEventFunc>(transaction_handler), nullptr);
  if (nullptr == txn_contp) {
    CH_Error("failed to create a tranaction handler continuation.");
  } else {
    TSContDataSet(txn_contp, config);
  }
  TSHttpTxnHookAdd(txnp, TS_HTTP_READ_RESPONSE_HDR_HOOK, txn_contp);
  TSHttpTxnHookAdd(txnp, TS_HTTP_TXN_CLOSE_HOOK, txn_contp);

  return TSREMAP_NO_REMAP;
}

/**
 * Remap initialization.
 */
TSReturnCode
TSRemapInit(TSRemapInterface *api_info, char *errbuf, int errbuf_size)
{
  if (!api_info) {
    strncpy(errbuf, "[tsremap_init] - Invalid TSRemapInterface argument", errbuf_size - 1);
    return TS_ERROR;
  }

  if (api_info->tsremap_version < TSREMAP_VERSION) {
    snprintf(errbuf, errbuf_size, "[TSRemapInit] - Incorrect API version %ld.%ld", api_info->tsremap_version >> 16,
             (api_info->tsremap_version & 0xffff));
    return TS_ERROR;
  }

  CH_Debug("%s is successfully initialized.", PLUGIN_NAME);
  return TS_SUCCESS;
}

/**
 * New Remap Instance
 */
TSReturnCode
TSRemapNewInstance(int argc, char *argv[], void **ih, char *errbuff, int errbuff_size)
{
  CHConfig *config = new CHConfig;
  std::string fileName;
  char file_path[4096] = {0};

  if (argc != 3) {
    CH_Error("insufficient number of arguments, %d, no config file argument.", argc);
    return TS_ERROR;
  }

  if (*argv[2] == '/') {
    fileName = argv[2];
  } else {
    snprintf(file_path, sizeof(file_path), "%s/%s", TSConfigDirGet(), argv[2]);
    fileName = file_path;
  }

  char *remap_from_url = argv[0];
  char *remap_to_url   = argv[1];

  if (TS_ERROR == CHash::loadConfig(*config, remap_from_url, remap_to_url, fileName)) {
    return TS_ERROR;
  } else {
    *ih = config;
  }

  return TS_SUCCESS;
}
