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

#include <stdatomic.h>

#define PLUGIN_NAME "throttle"
#define PluginDebug(...) TSDebug(PLUGIN_NAME, __VA_ARGS__)

#define HTTP_VALUE_STALE_WHILE_REVALIDATE "stale-while-revalidate"
#define HTTP_VALUE_STALE_IF_ERROR         "stale-if-error"
#define HTTP_VALUE_STALE_WARNING          "110 Response is stale"

#define MAX_ID_LEN 512

struct RemapThrottle {
	unsigned int max;
	int staletime;
	unsigned int statfreq;
	unsigned int terminated;
	_Atomic unsigned int current;
	_Atomic unsigned int high;
	_Atomic unsigned int req_unavailable;
	_Atomic unsigned int req_stale;
	char id[MAX_ID_LEN];
};
