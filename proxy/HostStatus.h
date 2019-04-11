/** @file

  A brief file description

  @section license License

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

/*****************************************************************************
 *
 *  HostStatus.h - Interface to Host Status System
 *
 *
 ****************************************************************************/

#pragma once

#include <time.h>
#include <string>
#include "tscore/ink_rwlock.h"
#include "records/P_RecProcess.h"

#include <unordered_map>

enum HostStatus_t {
  HOST_STATUS_INIT,
  HOST_STATUS_DOWN,
  HOST_STATUS_UP,
};

enum StatusReason_t {
  R_ACTIVE = 1,
  R_LOCAL,
  R_MANUAL,
  R_SELF_DETECT,
};

/**
 * Host Status Reasons
 */
struct HostStatusReason {
  static constexpr const char *active      = "active";
  static constexpr const char *local       = "local";
  static constexpr const char *manual      = "manual";
  static constexpr const char *self_detect = "self_detect";

  // defaults to manual
  const char *reason               = manual;
  const StatusReason_t reason_code = R_MANUAL;

  HostStatusReason(){};

  constexpr HostStatusReason(StatusReason_t r) : reason_code(r)
  {
    switch (r) {
    case R_ACTIVE:
      reason = active;
      break;
    case R_LOCAL:
      reason = local;
      break;
    case R_MANUAL:
      reason = manual;
      break;
    case R_SELF_DETECT:
      reason = self_detect;
      break;
    }
  }

  const char *
  c_str()
  {
    return reason;
  }

  bool
  operator==(const HostStatusReason &rhs)
  {
    return this->reason_code == rhs.reason_code;
  }

  friend bool
  operator==(const HostStatusReason &lhs, const HostStatusReason &rhs)
  {
    return lhs.reason_code == rhs.reason_code;
  }
};

struct HostStatRec_t {
  HostStatus_t status;
  time_t marked_down;     // the time that this host was marked down.
  unsigned int down_time; // number of seconds that the host should be down, 0 is indefinately
  const HostStatusReason *reason;
};

namespace Reason
{
static constexpr const char *reasons[4] = {HostStatusReason::active, HostStatusReason::local, HostStatusReason::manual,
                                           HostStatusReason::self_detect};

static constexpr const HostStatusReason ACTIVE(R_ACTIVE);
static constexpr const HostStatusReason LOCAL(R_LOCAL);
static constexpr const HostStatusReason MANUAL(R_MANUAL);
static constexpr const HostStatusReason SELF_DETECT(R_SELF_DETECT);

inline bool
validReason(const char *reason)
{
  for (const char *i : reasons) {
    if (strcmp(i, reason) == 0) {
      return true;
    }
  }
  return false;
}

inline const HostStatusReason *
getReason(const char *r)
{
  if (strcmp(r, HostStatusReason::active) == 0) {
    return &ACTIVE;
  } else if (strcmp(r, HostStatusReason::local) == 0) {
    return &LOCAL;
  } else if (strcmp(r, HostStatusReason::manual) == 0) {
    return &MANUAL;
  } else if (strcmp(r, HostStatusReason::self_detect) == 0) {
    return &SELF_DETECT;
  }
  return nullptr;
}

inline const HostStatusReason *
getReason(const StatusReason_t r)
{
  if (r == R_ACTIVE) {
    return &ACTIVE;
  } else if (r == R_LOCAL) {
    return &LOCAL;
  } else if (r == R_MANUAL) {
    return &MANUAL;
  } else if (r == R_SELF_DETECT) {
    return &SELF_DETECT;
  }
  return nullptr;
}
} // namespace Reason

static const std::string stat_prefix = "proxy.process.host_status.";

/**
 * Singleton placeholder for next hop status.
 */
struct HostStatus {
  ~HostStatus();

  static HostStatus &
  instance()
  {
    static HostStatus instance;
    return instance;
  }
  void setHostStatus(const char *name, const HostStatus_t status, const unsigned int down_time, const HostStatusReason *reason);
  HostStatRec_t *getHostStatus(const char *name);
  void createHostStat(const char *name);
  void loadHostStatusFromStats();
  int getHostStatId(const char *name);

private:
  int next_stat_id = 1;
  HostStatus();
  HostStatus(const HostStatus &obj) = delete;
  HostStatus &operator=(HostStatus const &) = delete;

  // next hop status, key is hostname or ip string, data is bool (available).
  std::unordered_map<std::string, HostStatRec_t *> hosts_statuses;
  // next hop stat ids, key is hostname or ip string, data is int stat id.
  std::unordered_map<std::string, int> hosts_stats_ids;

  ink_rwlock host_status_rwlock;
  ink_rwlock host_statids_rwlock;
};
