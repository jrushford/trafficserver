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

#include "ts/ts.h"
#include "tscore/ConsistentHash.h"

#include "ch_pselect.h"
#include "ch_config.h"

#include <string>
#include <string.h>
#include <algorithm>
#include <cstdio>
#include <cstring>
#include <memory>
#include <utility>
#include <vector>

#include <yaml-cpp/yaml.h>

namespace CHash
{
TSReturnCode
loadConfig(CHConfig &config, const std::string &remap_from_url, const std::string &remap_to_url, const std::string &fileName)
{
  CH_Debug("loading config from %s", fileName.c_str());

  // get the config scheme.
  if (remap_to_url.compare(0, 8, "https://") == 0) {
    config.scheme = "https";
  } else if (remap_to_url.compare(0, 7, "http://") == 0) {
    config.scheme = "http";
  } else {
    CH_Error("unable to determine the scheme from the to_url %s", remap_to_url.c_str());
    return TS_ERROR;
  }

  // save the from_url.
  config.remap_from_url = remap_from_url;
  // save the to_url.
  config.remap_to_url = remap_to_url;

  try {
    YAML::Node root = YAML::LoadFile(fileName);

    // verify top node
    YAML::Node top = root["ch_pselect"];
    if (top.Type() != YAML::NodeType::Map) {
      CH_Error("malformed config file, %s, expected a 'ch_pselect' top level map", fileName.c_str());
      return TS_ERROR;
    }
    // get go_direct value
    if (top["go_direct"]) {
      config.go_direct = top["go_direct"].as<bool>();
    } else {
      config.go_direct = false;
    }
    // get the ring_mode value.
    if (top["ring_mode"]) {
      auto rm_value = top["ring_mode"].as<std::string>();
      if (rm_value == "exhaust_ring") {
        config.ring_mode = EXHAUST_RING;
      } else if (rm_value == "alternate_ring") {
        config.ring_mode = ALTERNATE_RING;
      } else {
        CH_Error("invalid 'ring_mode' setting, %s, in config", rm_value.c_str());
        return TS_ERROR;
      }
    }
    // get simple_retry codes.
    if (top["simple_retry"]) {
      if (top["simple_retry"].Type() != YAML::NodeType::Sequence) {
        CH_Error("malformed config file %s, expected that simple_retry is a sequence.", fileName.c_str());
        return TS_ERROR;
      } else {
        for (uint32_t ii = 0; ii < top["simple_retry"].size(); ii++) {
          auto code = top["simple_retry"][ii].as<int>();
          config.simple_retry.add(code);
        }
        config.simple_retry.sort();
      }
    }
    // get unavailable_server codes.
    if (top["unavailable_server"]) {
      if (top["unavailable_server"].Type() != YAML::NodeType::Sequence) {
        CH_Error("malformed config file %s, expected that 'unavailable_retry' sequence.", fileName.c_str());
        return TS_ERROR;
      } else {
        for (uint32_t ii = 0; ii < top["unavailable_server"].size(); ii++) {
          auto code = top["unavailable_server"][ii].as<int>();
          config.unavailable_server.add(code);
        }
        config.unavailable_server.sort();
      }
    }
    // parse and load the host data
    YAML::Node hosts_node;
    if (top["hosts"]) {
      hosts_node = top["hosts"];
      if (hosts_node.Type() != YAML::NodeType::Sequence) {
        CH_Error("malformed config file %s, expected a 'hosts' sequence.", fileName.c_str());
        return TS_ERROR;
      }
      for (uint32_t hst = 0; hst < hosts_node.size(); hst++) {
        std::shared_ptr<CH_HostRecord> host_rec = std::make_shared<CH_HostRecord>(hosts_node[hst].as<CH_HostRecord>());
        host_rec->host_index                    = hst;
        config.hosts.push_back(host_rec);
        config.num_hosts++;
      }
    }
  } catch (const YAML::Exception &e) {
    CH_Error("Exception \"%s\", when parsing the config file %s for %s", e.what(), fileName.c_str(), PLUGIN_NAME);
    return TS_ERROR;
  }

  // initialize the consistent hash ring.
  for (uint32_t ii = 0; ii < config.hosts.size(); ii++) {
    ATSHash64Sip24 hasher;
    CH_HostRecord *p = config.hosts[ii].get();
    CH_Debug("loading consistent hash ring, p->name: %s, p->weight: %f", p->name, p->weight);
    config.chash->insert(p, p->weight, &hasher);
  }

  return TS_SUCCESS;
}
} // namespace CHash

namespace YAML
{
template <> struct convert<CH_HostRecord> {
  static bool
  decode(const Node &node, CH_HostRecord &nh)
  {
    // lookup the hostname
    if (node["host"]) {
      nh.hostname = node["host"].Scalar();
      nh.name     = const_cast<char *>(nh.hostname.c_str());
    } else {
      throw std::invalid_argument("Invalid host definition, missing host name.");
    }

    // lookup the weight
    if (node["weight"]) {
      nh.weight = node["weight"].as<float>();
    }

    // lookup the port numbers supported by this host.
    YAML::Node proto = node["protocol"];

    if (proto.Type() != YAML::NodeType::Sequence) {
      throw std::invalid_argument("Invalid host protocol definition, expected a sequence.");
    } else {
      for (unsigned int ii = 0; ii < proto.size(); ii++) {
        YAML::Node protocol_node       = proto[ii];
        std::shared_ptr<CHProtocol> pr = std::make_shared<CHProtocol>(protocol_node.as<CHProtocol>());
        nh.protocols.push_back(std::move(pr));
      }
    }

    return true;
  }
};

template <> struct convert<CHProtocol> {
  static bool
  decode(const Node &node, CHProtocol &nh)
  {
    if (node["scheme"]) {
      if (node["scheme"].Scalar() == "http") {
        nh.scheme = NH_SCHEME_HTTP;
      } else if (node["scheme"].Scalar() == "https") {
        nh.scheme = NH_SCHEME_HTTPS;
      } else {
        nh.scheme = NH_SCHEME_NONE;
      }
    }
    if (node["port"]) {
      nh.port = node["port"].as<int>();
    }
    if (node["health_check_url"]) {
      nh.health_check_url = node["health_check_url"].Scalar();
    }
    return true;
  }
};
} // namespace YAML

uint64_t
CHConfig::getHash(const char *string)
{
  ATSHash64Sip24 hasher;
  int length = strlen(string);
  CH_Debug("hash string: %s, length: %d", string, length);
  hasher.update("/", 1);
  hasher.update(string, length);
  hasher.final();
  return hasher.get();
}

void
CHConfig::findNextHop(TSHttpTxn txnp, std::string &requestPath, LookupResult &result)
{
  int port         = -1;
  bool wrap_around = false;
  ATSConsistentHashIter chashIter;
  uint64_t sm_id = TSHttpTxnIdGet(txnp);
  uint64_t hash_val;
  CH_HostRecord *rec = nullptr;
  NHSchemeType stype = NH_SCHEME_NONE;

  if (scheme == "http") {
    stype = NH_SCHEME_HTTP;
  } else if (scheme == "https") {
    stype = NH_SCHEME_HTTPS;
  }

  hash_val = getHash(requestPath.c_str());

  CH_Debug("[%ld] - next hop hash string from path: %s", sm_id, requestPath.c_str());

  rec                               = static_cast<CH_HostRecord *>(chash->lookup_by_hashval(hash_val, &chashIter, &wrap_around));
  std::shared_ptr<CHProtocol> proto = rec->getProtocolByScheme(stype);

  if (proto != nullptr) {
    port = proto->port;
  }

  if (rec != nullptr) {
    CH_Debug("hash_val: %ld, selected host is: %s:%d", hash_val, rec->hostname.c_str(), port);
    TSHttpTxnParentProxySet(txnp, rec->hostname.c_str(), port);
  } else {
    CH_Debug("rec is null.");
  }
}
