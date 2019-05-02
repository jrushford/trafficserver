/** @file

  host.cc

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
#include "traffic_ctl.h"
#include "records/P_RecUtils.h"
const std::string stat_prefix = "host_status.";
static int
status_get(unsigned argc, const char **argv)
{
  if (!CtrlProcessArguments(argc, argv, nullptr, 0) || n_file_arguments < 1) {
    return CtrlCommandUsage("host status HOST  [HOST  ...]", nullptr, 0);
  }

  for (unsigned i = 0; i < n_file_arguments; ++i) {
    CtrlMgmtRecord record;
    TSMgmtError error;
    std::string str = stat_prefix + it;

    error = record.fetch(str.c_str());
    if (error != TS_ERR_OKAY) {
      CtrlMgmtError(error, "failed to fetch %s", it.c_str());
      status_code = CTRL_EX_ERROR;
      return;
    }

    if (REC_TYPE_IS_STAT(record.rclass())) {
      std::cout << record.name() << ' ' << CtrlMgmtRecordValue(record).c_str() << std::endl;
    }
  }

  return CTRL_EX_OK;
}

static int
status_down(unsigned argc, const char **argv)
{
  const char *usage      = "traffic_ctl host down --reason 'active | local | manual' --time seconds host ....";
  unsigned int down_time = 0;
  std::string reason     = arguments.get("reason").value();
  std::string down       = arguments.get("time").value();

  // if reason is not set, set it to manual (default)
  if (reason.empty()) {
    reason = Reason::MANUAL;
  }
  if (!down.empty()) {
    down_time = atoi(down.c_str());
  }

  if (!Reason::validReason(reason.c_str())) {
    fprintf(stderr, "\nInvalid reason: '%s'\n\n", reason.c_str());
    fprintf(stderr, "Usage: %s\n\n", usage);
    status_code = CTRL_EX_ERROR;
    return;
  }

  TSMgmtError error = TS_ERR_OKAY;
  for (const auto &it : arguments.get("down")) {
    if (strncmp(it.c_str(), "--", 2) == 0) {
      fprintf(stderr, "\nInvalid option: %s\n", it.c_str());
      fprintf(stderr, "Usage: %s\n\n", usage);
      status_code = CTRL_EX_ERROR;
      return;
    }
    error = TSHostStatusSetDown(it.c_str(), down_time, reason.c_str());
    if (error != TS_ERR_OKAY) {
      CtrlMgmtError(error, "failed to set %s", file_arguments[i]);
      return CTRL_EX_ERROR;
    }
  }

  return CTRL_EX_OK;
}
static int
status_up(unsigned argc, const char **argv)
{
  const char *usage  = "traffic_ctl host up --reason 'active | local | manual' host ....";
  std::string reason = arguments.get("reason").value();

  // if reason is not set, set it to manual (default)
  if (reason.empty()) {
    reason = Reason::MANUAL;
  }

  if (!Reason::validReason(reason.c_str())) {
    fprintf(stderr, "\nInvalid reason: '%s'\n\n", reason.c_str());
    fprintf(stderr, "Usage: %s\n\n", usage);
    status_code = CTRL_EX_ERROR;
    return;
  }
  TSMgmtError error;
  for (const auto &it : arguments.get("up")) {
    error = TSHostStatusSetUp(it.c_str(), 0, reason.c_str());
    if (strncmp("--", it.c_str(), 2) == 0) {
      fprintf(stderr, "\nInvalid option: %s\n", it.c_str());
      fprintf(stderr, "Usage: %s\n\n", usage);
      status_code = CTRL_EX_ERROR;
    }
    if (error != TS_ERR_OKAY) {
      CtrlMgmtError(error, "failed to set %s", file_arguments[i]);
      return CTRL_EX_ERROR;
    }
  }

  return CTRL_EX_OK;
}

int
subcommand_host(unsigned argc, const char **argv)
{
  const subcommand commands[] = {
    {status_get, "status", "Get one or more host statuses"},
    {status_down, "down", "Set down one or more host(s) "},
    {status_up, "up", "Set up one or more host(s) "},

  };

  return CtrlGenericSubcommand("host", commands, countof(commands), argc, argv);
}
