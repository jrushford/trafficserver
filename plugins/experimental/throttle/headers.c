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

#include "headers.h"
#include "throttle.h"
#include <stdlib.h>
#include <string.h>

/* This is cribbed more-or-less directly from the old stale_while_revalidate
 * plugin.
 */
void
get_cached_header_info(TSHttpTxn txn, struct CachedHeaderInfo *chi)
{
	TSMBuffer cr_buf;
	TSMLoc cr_hdr_loc, cr_date_loc, cr_cache_control_loc, cr_cache_control_dup_loc;
	int cr_cache_control_count, val_len, i;
	char *value, *ptr;

	memset(chi, 0, sizeof(struct CachedHeaderInfo));

	if (TSHttpTxnCachedRespGet(txn, &cr_buf, &cr_hdr_loc) == TS_SUCCESS) {
		cr_date_loc = TSMimeHdrFieldFind(cr_buf, cr_hdr_loc, TS_MIME_FIELD_DATE, TS_MIME_LEN_DATE);
		if (cr_date_loc != TS_NULL_MLOC) {
			chi->date = TSMimeHdrFieldValueDateGet(cr_buf, cr_hdr_loc, cr_date_loc);
			TSHandleMLocRelease(cr_buf, cr_hdr_loc, cr_date_loc);
		}

		cr_cache_control_loc = TSMimeHdrFieldFind(cr_buf, cr_hdr_loc, TS_MIME_FIELD_CACHE_CONTROL, TS_MIME_LEN_CACHE_CONTROL);

		while (cr_cache_control_loc != TS_NULL_MLOC) {
			cr_cache_control_count = TSMimeHdrFieldValuesCount(cr_buf, cr_hdr_loc, cr_cache_control_loc);

			for (i = 0; i < cr_cache_control_count; i++) {
				value = (char *)TSMimeHdrFieldValueStringGet(cr_buf, cr_hdr_loc, cr_cache_control_loc, i, &val_len);
				ptr   = value;

				if (strncmp(value, TS_HTTP_VALUE_MAX_AGE, TS_HTTP_LEN_MAX_AGE) == 0) {
					ptr += TS_HTTP_LEN_MAX_AGE;
					if (*ptr == '=') {
						ptr++;
						chi->max_age = atol(ptr);
					} else {
						ptr = TSstrndup(value, TS_HTTP_LEN_MAX_AGE + 2);
						TSfree(ptr);
					}
				} else if (strncmp(value, HTTP_VALUE_STALE_IF_ERROR, strlen(HTTP_VALUE_STALE_IF_ERROR)) == 0) {
					ptr += strlen(HTTP_VALUE_STALE_IF_ERROR);
					if (*ptr == '=') {
						ptr++;
						chi->stale_on_error = atol(ptr);
					}
				}
			}

			cr_cache_control_dup_loc = TSMimeHdrFieldNextDup(cr_buf, cr_hdr_loc, cr_cache_control_loc);
			TSHandleMLocRelease(cr_buf, cr_hdr_loc, cr_cache_control_loc);
			cr_cache_control_loc = cr_cache_control_dup_loc;
		}
		TSHandleMLocRelease(cr_buf, TS_NULL_MLOC, cr_hdr_loc);
	}
}
