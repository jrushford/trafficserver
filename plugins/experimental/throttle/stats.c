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
#include "ts/ts.h"
#include <stdlib.h>

struct LogData {
	TSTextLogObject logger;
	struct RemapThrottle *r;
};

int write_stats(TSCont cont, TSEvent event, void *edata);
void start_stats(TSTextLogObject logger, struct RemapThrottle *r)
{
	TSCont cont = TSContCreate(write_stats, TSMutexCreate());
	struct LogData *d = calloc(1,sizeof(struct LogData));
	TSContDataSet(cont, d);
	d->r = r;
	d->logger = logger;

	TSContSchedule(cont, r->statfreq?r->statfreq:1000, TS_THREAD_POOL_TASK);
}

int write_stats(TSCont cont, TSEvent event, void *edata)
{
	struct LogData *d = TSContDataGet(cont);

	unsigned int high = atomic_exchange(&d->r->high, 0);
	unsigned int req_unavailable = atomic_exchange(&d->r->req_unavailable, 0);
	unsigned int req_stale = atomic_exchange(&d->r->req_stale, 0);

	if (d->r->statfreq > 0) {
		TSTextLogObjectWrite(d->logger, "tpid=%s tph=%u tpu=%u tps=%u", d->r->id, high, req_unavailable, req_stale);
	}

	if (d->r->terminated) {
		TSContDestroy(cont);
		free(d->r);
		free(d);
		PluginDebug("Terminated and freed instance.");
	} else {
		TSContSchedule(cont, d->r->statfreq?d->r->statfreq:1000, TS_THREAD_POOL_TASK);
	}
	return 0;
}
