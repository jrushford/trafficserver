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
#include <stdlib.h>
#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

#include "ts/ts.h"

int read_config(const char *arg, struct RemapThrottle *r, char *err, size_t err_sz) {
	int read_config_recurse(const char *arg, struct RemapThrottle *r, char *err, size_t err_sz, int patience);
	return read_config_recurse(arg, r, err, err_sz, 1024); /* Hard limit of 1024 recursive file lookups should be more than enough for anyone. */
}
int read_config_recurse(const char *arg, struct RemapThrottle *r, char *err, size_t err_sz, int patience)
{
	char const * const max_str = "max";
	char const * const stale_str = "stale";
	char const * const statfreq_str = "statfreq";
	char const * const file_str = "file";
	char const * const id_str = "id";

	const char *max_ck = max_str;
	const char *stale_ck = stale_str;
	const char *statfreq_ck = statfreq_str;
	const char *file_ck = file_str;
	const char *id_ck = id_str;
	PluginDebug("Processing config arg: %s", arg);

	if (patience < 0) {
		snprintf(err, err_sz, "Too many nested files (do you have a loop?)");
		return 0;
	}

	while (*arg) {
		PluginDebug("Processing: %s", arg);
		if (isalpha(*arg)) {
			if (*max_ck == *arg) ++max_ck;
			else max_ck = max_str;

			if (*stale_ck == *arg) ++stale_ck;
			else stale_ck = stale_str;

			if (*statfreq_ck == *arg) ++statfreq_ck;
			else statfreq_ck = statfreq_str;

			if (*file_ck == *arg) ++file_ck;
			else file_ck = file_str;

			if (*id_ck == *arg) ++id_ck;
			else id_ck = id_str;

			++arg;
			continue;
		}
		if (isdigit(*arg) || *arg == '+' || *arg == '-') {
			if (!*max_ck) {
				char *next;
				r->max = strtoul(arg, &next, 0);
				if (next == arg) ++arg;
				else arg = next;
				max_ck = max_str;
				continue;
			}
			if (!*stale_ck) {
				char *next;
				r->staletime = strtol(arg, &next, 0);
				if (next == arg) ++arg;
				else arg = next;
				stale_ck = stale_str;
				continue;
			}
			if (!*statfreq_ck) {
				char *next;
				r->statfreq = strtoul(arg, &next, 0);
				if (next == arg) ++arg;
				else arg = next;
				statfreq_ck = statfreq_str;
				continue;
			}
		}
		if (!*file_ck) {
			char *fname = NULL,
			     *path = NULL,
			     *content = NULL;
			size_t fname_sz, content_sz;
			int ret = 1;
			PluginDebug("Parsing file arg: %s", arg);

			PluginDebug("Skip whitespace.");
			/* Skip initial break char and any whitespace */
			{
				++arg;
				while (*arg && isspace(*arg))
					++arg;
			}

			PluginDebug("Parse fname.");
			/* Parse out the filename, allowing backslashes to escape spaces. */
			{
				const char *begin = arg;
				while (*arg && !isspace(*arg)) {
					if (*arg == '\\') {
						++arg;
						if (*arg) ++arg;
					} else {
						++arg;
					}
				}
				fname_sz = arg-begin;
				fname = malloc(fname_sz+1);
				memcpy(fname, begin, fname_sz);
				fname[fname_sz] = '\0';
			}

			PluginDebug("Remove escapes.");
			/* Remove the escapes. */
			{
				char *src = fname, *dst = fname;
				while (*src) {
					if (*src == '\\') ++src;
					*dst++ = *src++;
				}
			}

			PluginDebug("Prep path: %s", fname);
			/* Prepare the path. */
			{
				const char *config_dir;
				if (*fname == '/')
					path = fname;
				else {
					size_t config_dir_sz;
					config_dir = TSConfigDirGet();
					config_dir_sz = strlen(config_dir);
					path = malloc(config_dir_sz+fname_sz+2);
					memcpy(path, config_dir, config_dir_sz);
					path[config_dir_sz] = '/';
					memcpy(path+config_dir_sz+1, fname, fname_sz);
					path[config_dir_sz+fname_sz+1] = '\0';
				}
			}

			PluginDebug("Read file.");
			/* Read the file. */
			{
				FILE *f = fopen(path, "rb");
				if (!f) {
					snprintf(err, err_sz, "Cannot open %s: %s", path, strerror(errno));
					ret = 0;
					goto cleanup;
				}
				fseek(f, 0, SEEK_END);
				content_sz = ftell(f);
				fseek(f, 0, SEEK_SET);
				if (content_sz > 1<<20) {
					snprintf(err, err_sz, "File too large to read %s.", path);
					ret = 0;
					goto cleanup;
				}
				content = malloc(content_sz+1);
				content[fread(content, 1, content_sz, f)] = '\0';
			}

			ret = read_config_recurse(content, r, err, err_sz, patience-1);

cleanup:
			/* Clean up. */
			if (fname && path != fname)
				free(fname);
			if (path)
				free(path);
			if (content)
				free(content);
			if (!ret)
				return 0;
			file_ck = file_str;
			continue;
		}
		if (!*id_ck) {
			char *id = r->id;
			size_t left = MAX_ID_LEN-1;
			PluginDebug("Parsing id.");
			do ++arg;
			while (*arg && isspace(*arg));
			while (*arg && !isspace(*arg) && left) {
				--left;
				*id++ = *arg++;
			}
			*id = '\0';
			PluginDebug("Found id %s.", r->id);
			id_ck = id_str;
			continue;
		}
		++arg;
	}
	return 1;
}
