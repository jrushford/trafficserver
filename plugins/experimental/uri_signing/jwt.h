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

#include <stdbool.h>
#include <jansson.h>

struct jwt {
  json_t *raw;
  const char *iss;
  const char *sub;
  json_t *aud;
  double exp;
  double nbf;
  double iat;
  const char *jti;
  int cdniv;
  const char *cdnicrit;
  const char *cdniip;
  const char *cdniuc;
  int cdniets;
  int cdnistt;
  int cdnistd;
  double x1rt;
  double x1rts;
  const char *x1err;
  const char *x1ctx;
};

struct redir_jwt {
  int x1ec;
  double iat;
  const char *x1err;
  const char *x1ctx;
  const char *x1uri;
};

struct jwt *parse_jwt(json_t *raw);
struct redir_jwt *parse_redir_jwt(struct jwt *jwt, int ec, const char *x1uri);
void jwt_delete(struct jwt *jwt);
void redir_jwt_delete(struct redir_jwt *redir_jwt);
int jwt_validate(struct jwt *jwt);
bool jwt_check_aud(json_t *aud, const char *id);
bool jwt_check_uri(const char *cdniuc, const char *uri);

struct _cjose_jwk_int;
char *renew(struct jwt *jwt, const char *iss, struct _cjose_jwk_int *jwk, const char *alg, const char *package);
char *redirect_token_url_get(const char *x1ctx, const char *x1err, const char *iss, struct _cjose_jwk_int *jwk, const char *alg,
                             double add_nbf, double add_exp, const char *x1uri, const char *x1ec);
