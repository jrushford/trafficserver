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

#pragma once

#include "ts/ts.h"
#include "tscore/HashSip.h"

#include <algorithm>
#include <memory>
#include <vector>

enum RingMode {
  ALTERNATE_RING = 0,
  EXHAUST_RING,
};

enum NHSchemeType { NH_SCHEME_NONE = 0, NH_SCHEME_HTTP, NH_SCHEME_HTTPS };

struct CHProtocol {
  NHSchemeType scheme;
  uint32_t port;
  std::string health_check_url;
};

struct CH_HostRecord : ATSConsistentHashNode {
  std::string hostname;
  time_t failedAt    = 0;
  uint32_t failCount = 0;
  time_t upAt        = 0;
  float weight       = 0.1;
  int host_index     = -1;
  std::vector<std::shared_ptr<CHProtocol>> protocols;

  CH_HostRecord()
  {
    hostname   = "";
    failedAt   = 0;
    failCount  = 0;
    upAt       = 0;
    weight     = 0.1;
    host_index = -1;
    available  = true;
  }

  CH_HostRecord &
  operator=(const CH_HostRecord &o)
  {
    hostname   = o.hostname;
    failedAt   = o.failedAt;
    upAt       = o.upAt;
    weight     = o.weight;
    host_index = o.host_index;
    available  = o.available;
    return *this;
  }

  std::shared_ptr<CHProtocol>
  getProtocolByScheme(NHSchemeType stype)
  {
    for (std::shared_ptr<CHProtocol> proto : protocols) {
      if (proto->scheme == stype) {
        return proto;
      }
    }
    return nullptr;
  }
};

struct ResponseCodes {
  ResponseCodes(){};
  std::vector<int> codes;

  void
  add(int code)
  {
    codes.push_back(code);
  }

  bool
  contains(int code)
  {
    return std::binary_search(codes.begin(), codes.end(), code);
  }

  void
  sort()
  {
    std::sort(codes.begin(), codes.end());
  }
};

struct LookupResult {
  char *hostName = nullptr;
  int port       = -1;
  char *requestPath;
};

struct CHConfig {
  ATSConsistentHash *chash = new ATSConsistentHash();
  bool go_direct           = false;
  std::string scheme;
  std::string remap_from_url;
  std::string remap_to_url;
  RingMode ring_mode = EXHAUST_RING;
  uint32_t num_hosts = 0;
  ResponseCodes simple_retry;
  ResponseCodes unavailable_server;
  std::vector<std::shared_ptr<CH_HostRecord>> hosts;
  uint64_t getHash(const char *string);
  void findNextHop(TSHttpTxn txnp, std::string &requestPath, LookupResult &result);
};

namespace CHash
{
TSReturnCode loadConfig(CHConfig &config, const std::string &remap_from_url, const std::string &remap_to_url,
                        const std::string &fileName);
} // namespace CHash
