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

#include <stdlib.h>
#include <stdbool.h>

struct _cjose_jws_int;

struct strip_state {
  char *strip_uri;
  size_t strip_uri_ct;
  int index;
  char reserved;
  char term;
};

struct _cjose_jws_int *get_jws_from_uri(const char *uri, size_t uri_ct, const char *paramName, size_t buff_ct,
                                        struct strip_state *strp);
struct _cjose_jws_int *get_jws_from_cookie(const char **cookie, size_t *cookie_ct, const char *paramName);
void get_redirect_renew_url(struct strip_state *strp, const char *new_token, char *new_url, size_t buffer_ct);

struct config;
struct jwt;
struct jwt *validate_jws(struct _cjose_jws_int *jws, struct config *cfg, const char *uri, size_t uri_ct, int *rc);
struct strip_state *strip_state_new(size_t buffer_ct);
void strip_state_delete(struct strip_state *strp);
