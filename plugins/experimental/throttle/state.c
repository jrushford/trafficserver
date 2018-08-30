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

#include "state.h"
#include "throttle.h"
#include "headers.h"

#include <string.h>

/* Plugin-specific handlers.
 * These handlers take plugin-specific data and return the next hook for which
 * to schedule a callback. They return TS_LAST_HOOK to indicate no additional
 * processing is required.
 */
TSHttpHookID begin(TSHttpTxn txn, TSCont cont, struct RemapThrottle *r);
TSHttpHookID end(TSHttpTxn txn, TSCont cont, struct RemapThrottle *r);
TSHttpHookID add_warning(TSHttpTxn txn, TSCont cont, struct RemapThrottle *r);

TSHttpHookID (*get_handler(TSEvent event))(TSHttpTxn, TSCont, struct RemapThrottle*)
{
	switch (event) {
		case TS_EVENT_HTTP_CACHE_LOOKUP_COMPLETE:
			return begin;
		case TS_EVENT_HTTP_TXN_CLOSE:
			return end;
		case TS_EVENT_HTTP_SEND_RESPONSE_HDR:
			return add_warning;
		default:
			TSReleaseAssert(!"Unknown state.");
	}
}

/** handle_event is a generic event handler that serves as the handler for the TSCont.
 * It retrieves the plugin-specific data and calls the appropriate specific handler.
 */
int
handle_event(TSCont cont, TSEvent event, void *edata) {
	TSHttpTxn txn = (TSHttpTxn)edata;
	struct RemapThrottle *r = TSContDataGet(cont);
	TSHttpHookID next;
	PluginDebug("Processing Event %d", event);

	next = (*get_handler(event))(txn, cont, r);

	if (next < TS_HTTP_LAST_HOOK) {
		TSHttpTxnHookAdd(txn, next, cont);
		TSHttpTxnReenable(txn, TS_EVENT_HTTP_CONTINUE);
	} else {
		TSContDestroy(cont);
		if (next > TS_HTTP_LAST_HOOK) {
			TSHttpTxnReenable(txn, TS_EVENT_HTTP_ERROR);
		} else {
			TSHttpTxnReenable(txn, TS_EVENT_HTTP_CONTINUE);
		}
	}
	return 0;
}

/** begin starts a request and potentially denies it.
 * begin can transition to either end or add_warning, depending on whether the
 * content was served or served stale.
 */
TSHttpHookID begin(TSHttpTxn txn, TSCont cont, struct RemapThrottle *r)
{
	int obj, obj_valid = 0;
	unsigned int current = ++r->current, high = r->high;

	/* Update the high mark, if necessary. */
	do if (high >= current)
		break;
	while (!atomic_compare_exchange_weak(&r->high, &high, current));

	/* If the object is being returned from cache, don't count toward the throttle. */
	if (TSHttpTxnCacheLookupStatusGet(txn, &obj) != TS_ERROR)
	{
		obj_valid = 1;
		if (obj == TS_CACHE_LOOKUP_HIT_FRESH) {
			--r->current;
			return TS_HTTP_LAST_HOOK;
		}
	}

	/* If we've got too much in-flight, don't go upstream with this. */
	if (current > r->max) {

		/* If we can't serve the request, check to see if it's ok
		 * to serve it stale.
		 */
		if (obj_valid && obj == TS_CACHE_LOOKUP_HIT_STALE) {
			struct CachedHeaderInfo chi;
			time_t now, age, stale;
			get_cached_header_info(txn, &chi);
			time(&now);

			age = now-chi.date;

			/* Use the greater of the configured stale time or
			 * the stale_on_error on the cached object.
			 *
			 * This is a very limited use of stale_on_error,
			 * but falls within the guidelines for its usage.
			 */
			stale = r->staletime;
			if (chi.stale_on_error > stale) {
				stale = chi.stale_on_error;
			}
			if (stale > 0 && age >= 0 && age < chi.max_age + stale) {
				PluginDebug("To many connections; serving stale object: %u", current);
				TSHttpTxnCacheLookupStatusSet(txn, TS_CACHE_LOOKUP_HIT_FRESH);
				--r->current;
				++r->req_stale;
				return TS_HTTP_SEND_RESPONSE_HDR_HOOK;
			}
		}

		/* Nothing available to serve, reject request. */
		PluginDebug("Too many connections; serving unavailable: %u", current);
		TSHttpTxnSetHttpRetStatus(txn, TS_HTTP_STATUS_SERVICE_UNAVAILABLE);
		--r->current;
		++r->req_unavailable;
		return TS_HTTP_LAST_HOOK+1; /* Greater than last means error. */
	}

	/* We're good to go, serve the content and schedule a callback
	 * to reclaim the resource.
	 */
	PluginDebug("Begin: %u", current);
	return TS_HTTP_TXN_CLOSE_HOOK;
}

/** end finishes a request. Terminal state. */
TSHttpHookID end(TSHttpTxn txn, TSCont cont, struct RemapThrottle *r)
{
	/* Reclaim the resource. */
	unsigned int current = --r->current;

	PluginDebug("End: %u", current);
	return TS_HTTP_LAST_HOOK;
}

/** add_warning adds the required stale warning header to a response being
 * served stale. Terminal state.
 */
TSHttpHookID add_warning(TSHttpTxn txn, TSCont cont, struct RemapThrottle *r)
{
	TSMBuffer buf;
	TSMLoc loc, warn_loc;

	PluginDebug("Set warning header");
	TSHttpTxnClientRespGet(txn, &buf, &loc);
	TSMimeHdrFieldCreateNamed(buf, loc, TS_MIME_FIELD_WARNING, TS_MIME_LEN_WARNING, &warn_loc);
	TSMimeHdrFieldValueStringInsert(buf, loc, warn_loc, -1, HTTP_VALUE_STALE_WARNING, strlen(HTTP_VALUE_STALE_WARNING));
	TSMimeHdrFieldAppend(buf, loc, warn_loc);
	TSHandleMLocRelease(buf, loc, warn_loc);
	TSHandleMLocRelease(buf, TS_NULL_MLOC, loc);

	return TS_HTTP_LAST_HOOK;
}
