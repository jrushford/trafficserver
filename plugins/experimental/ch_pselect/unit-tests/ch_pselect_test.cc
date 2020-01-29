/*
  Licensed to the Apache Software Foundation (ASF) under one
  or more contributor license agreements.  See the NOTICE file
  distributed with this work for additional information
  regarding copyright ownership.  The ASF licenses this file
  to you under the Apache License, Version 2.0 (the
  "License"); you may not use this file except in compliance
  with the License.  You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
*/

/*
 * Unit tests for ch_pselect.
 */

#include <stdint.h>
#include <string.h>

// mock TSHttpTxn
struct tsapi_httptxn {
  uint64_t sm_id    = 0;
  char *request_url = nullptr;
};
typedef struct tsapi_httptxn *TSHttpTxn;

#ifdef __cplusplus
extern "C" {

#endif /* __cplusplus */

#include <stdarg.h>
#include <stdio.h>

void
PrintToStdErr(const char *fmt, ...)
{
  va_list args;
  va_start(args, fmt);
  vfprintf(stderr, fmt, args);
  va_end(args);
}

// mocks
char *
TSHttpTxnEffectiveUrlStringGet(TSHttpTxn txn, int *length)
{
  if (txn != nullptr && txn->request_url != nullptr) {
    *length = strlen(txn->request_url);
  }

  return txn->request_url;

  return nullptr;
}

uint64_t
TSHttpTxnIdGet(TSHttpTxn txn)
{
  return txn->sm_id;
}

void
TSHttpTxnParentProxySet(TSHttpTxn txnp, const char *hostname, int port)
{
  return;
}

#ifdef __cplusplus
}
#endif /* __cplusplus */

#define CATCH_CONFIG_MAIN

#include <catch.hpp>

#include "../ch_pselect.h"
#include "../ch_config.h"

TEST_CASE("1", "[Config file loading]")
{
  INFO("TEST 1, Test loading a yaml config file.");

  SECTION("Load a config file.")
  {
    CHConfig config;
    std::string fileName       = "experimental/ch_pselect/unit-tests/test-config.yaml";
    std::string remap_from_url = "http://www.foo.com";
    std::string remap_to_url   = "http://origin.foo.com";
    REQUIRE(CHash::loadConfig(config, remap_from_url, remap_to_url, fileName) == 0);
    REQUIRE(config.scheme == "http");
    REQUIRE(config.remap_from_url == remap_from_url);
    REQUIRE(config.remap_to_url == remap_to_url);
    REQUIRE(config.go_direct == false);
    REQUIRE(config.ring_mode == EXHAUST_RING);
    REQUIRE(config.simple_retry.contains(404));
    REQUIRE(!config.simple_retry.contains(200));
    REQUIRE(config.unavailable_server.contains(500));
    REQUIRE(!config.unavailable_server.contains(503));
    REQUIRE(config.hosts.size() == 2);
    for (uint32_t ii = 0; ii < config.hosts.size(); ii++) {
      std::shared_ptr<CH_HostRecord> h = config.hosts[ii];
      switch (ii) {
      case 0:
        REQUIRE(h->hostname == "r640-1.cdnlab.comcast.net");
        REQUIRE(h->weight == 0.5);
        REQUIRE(h->protocols.size() == 1);
        REQUIRE(h->protocols[0]->scheme == NH_SCHEME_HTTP);
        REQUIRE(h->protocols[0]->port == 8080);
        break;
      case 1:
        REQUIRE(h->hostname == "r640-2.cdnlab.comcast.net");
        REQUIRE(h->weight == 0.5);
        REQUIRE(h->protocols.size() == 1);
        REQUIRE(h->protocols[0]->scheme == NH_SCHEME_HTTP);
        REQUIRE(h->protocols[0]->port == 8080);
        break;
      }
    }
  }
}
