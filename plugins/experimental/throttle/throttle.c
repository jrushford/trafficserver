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

#include "throttle.h"
#include "headers.h"
#include "state.h"
#include "config.h"
#include "stats.h"

#include <ts/ts.h>
#include <ts/remap.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

static TSTextLogObject logger;

TSReturnCode
TSRemapInit(TSRemapInterface *api_info, char *errbuf, int errbuf_sz)
{
	if (!api_info) {
		snprintf(errbuf, errbuf_sz, "[throttle] Invalid TSRemapInterface");
		return TS_ERROR;
	}

	if (api_info->tsremap_version < TSREMAP_VERSION) {
		snprintf(errbuf, errbuf_sz, "[TSRemapInit] - Incorrect API version %ld.%ld", api_info->tsremap_version >> 16,
				(api_info->tsremap_version & 0xffff));
		return TS_ERROR;
	}

	/* Initialize global logger object. */
	TSTextLogObjectCreate("throttle.log", TS_LOG_MODE_ADD_TIMESTAMP, &logger);

	/* Set up rolling with hardcoded defaults.
	 * These should reall go into a config file somewhere.
	 */
	TSTextLogObjectRollingEnabledSet(logger, 3);
	TSTextLogObjectRollingIntervalSecSet(logger, 60*60*24);
	TSTextLogObjectRollingSizeMbSet(logger, 1024);

	PluginDebug("Successfully initialized");
	return TS_SUCCESS;
}

TSReturnCode
TSRemapNewInstance(int argc, char *argv[], void **ih, char *errbuf, int errbuf_sz)
{
	struct RemapThrottle *r = calloc(1, sizeof(struct RemapThrottle));
	int i;
	PluginDebug("Beginning remap %s -> %s initialization.", argv[0], argv[1]);

	for (i = 2; i < argc; ++i) {
		if (!read_config(argv[i], r, errbuf, errbuf_sz))
			goto fail;
	}
	if (!r->max) {
		snprintf(errbuf, errbuf_sz, "No maximum set.");
		goto fail;
	}
	*ih = r;
	start_stats(logger, r);
	PluginDebug("Initializing remap %s -> %s with maximum of %u, staletime of %d", argv[0], argv[1], r->max, r->staletime);
	return TS_SUCCESS;
fail:
	PluginDebug("Initialization of remap unsuccessful: %s", errbuf);
	free(r);
	return TS_ERROR;
}

void
TSRemapDeleteInstance(void *ih)
{
	PluginDebug("Terminating instance.");
	if (ih) {
		/* The stats writer will clean it up on it's next run. */
		((struct RemapThrottle*)ih)->terminated = 1;
	}
}

TSRemapStatus
TSRemapDoRemap(void *ih, TSHttpTxn txnp, TSRemapRequestInfo *rri)
{
	TSCont cont = TSContCreate(handle_event, NULL);
	TSContDataSet(cont, ih);
	TSHttpTxnHookAdd(txnp, TS_HTTP_CACHE_LOOKUP_COMPLETE_HOOK, cont);
	PluginDebug("Scheduled events.");
	return TSREMAP_DID_REMAP;
}

