/*
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

/*
 * These are misc unit tests for uri signing
 */

#define CATCH_CONFIG_MAIN
#include "catch.hpp"

extern "C" {
#include <jansson.h>
#include <cjose/cjose.h>
#include "../jwt.h"
#include "../normalize.h"
#include "../parse.h"
#include "../match.h"
#include "../config.h"
}

bool
jwt_parsing_helper(const char *jwt_string, int exp_rc)
{
  fprintf(stderr, "Parsing JWT from string: %s\n", jwt_string);
  int resp;
  json_error_t jerr = {};
  size_t pt_ct      = strlen(jwt_string);
  struct jwt *jwt   = parse_jwt(json_loadb(jwt_string, pt_ct, 0, &jerr));

  if (jwt) {
    resp = jwt_validate(jwt);
  } else {
    return false;
  }
  jwt_delete(jwt);
  if (resp == exp_rc) {
    return true;
  } else {
    return false;
  }
}

TEST_CASE("1", "[JWSParsingTest]")
{
  INFO("TEST 1, Test JWT Parsing From Token Strings");

  SECTION("Standard JWT Parsing")
  {
    fprintf(stderr, "Test 1: JWT Parsing from Token Strings\n");
    fprintf(stderr, "========================================\n");
    REQUIRE(jwt_parsing_helper(
      R"({"cdniets":30,"cdnistt":1,"exp":7284188499,"iss":"Content Access Manager","cdniuc":"uri-regex:http://foobar.local/testDir/*"})",
      200));
  }

  SECTION("JWT Parsing With Unknown Claim")
  {
    REQUIRE(jwt_parsing_helper(
      R"({"cdniets":30,"cdnistt":1,"exp":7284188499,"iss":"Content Access Manager","cdniuc":"uri-regex:http://foobar.local/testDir/*","jamesBond":"Something,Something_else"})",
      200));
  }

  SECTION("JWT Parsing with unsupported crit claim passed")
  {
    REQUIRE(jwt_parsing_helper(
      R"({"cdniets":30,"cdnistt":1,"exp":7284188499,"iss":"Content Access Manager","cdniuc":"uri-regex:http://foobar.local/testDir/*","cdnicrit":"Something,Something_else"})",
      0));
  }

  SECTION("JWT Parsing with empty exp claim")
  {
    REQUIRE(jwt_parsing_helper(
      R"({"cdniets":30,"cdnistt":1,"iss":"Content Access Manager","cdniuc":"uri-regex:http://foobar.local/testDir/*"})", 200));
  }

  SECTION("JWT Parsing with unsupported cdniip claim")
  {
    REQUIRE(jwt_parsing_helper(
      R"({"cdniets":30,"cdnistt":1,"cdniip":"123.123.123.123","iss":"Content Access Manager","cdniuc":"uri-regex:http://foobar.local/testDir/*"})",
      0));
  }

  SECTION("JWT Parsing with unsupported value for cdnistd claim")
  {
    REQUIRE(jwt_parsing_helper(
      R"({"cdniets":30,"cdnistt":1,"cdnistd":4,"iss":"Content Access Manager","cdniuc":"uri-regex:http://foobar.local/testDir/*"})",
      0));
  }

  SECTION("JWT Parsing with expired claim")
  {
    REQUIRE(jwt_parsing_helper(
      R"({"cdniets":30,"cdnistt":1,"exp":1521683627,"iss":"Content Access Manager","cdniuc":"uri-regex:http://foobar.local/testDir/*"})",
      401));
  }

  SECTION("JWT Parsing with invalid nbf")
  {
    REQUIRE(jwt_parsing_helper(
      R"({"cdniets":30,"cdnistt":1,"nbf":32510598827,"iss":"Content Access Manager","cdniuc":"uri-regex:http://foobar.local/testDir/*"})",
      405));
  }

  SECTION("JWT Parsing with invalid version")
  {
    REQUIRE(jwt_parsing_helper(
      R"({"cdniets":30,"cdnistt":1,"cdniv":4,"nbf":32510598827,"iss":"Content Access Manager","cdniuc":"uri-regex:http://foobar.local/testDir/*"})",
      409));
  }

  fprintf(stderr, "\n");
}

bool
jws_parsing_helper(const char *uri, const char *paramName, const char *expected_strip, int expected_index, char expected_res,
                   char expected_term)
{
  bool resp;
  size_t uri_ct            = strlen(uri);
  struct strip_state *strp = strip_state_new(uri_ct + 1);

  cjose_jws_t *jws = get_jws_from_uri(uri, uri_ct, paramName, uri_ct, strp);
  if (jws) {
    resp = true;
    if (strcmp(strp->strip_uri, expected_strip) != 0 || expected_index != strp->index || strp->reserved != expected_res ||
        strp->term != expected_term) {
      resp = false;
    }
  } else {
    resp = false;
  }
  cjose_jws_release(jws);
  strip_state_delete(strp);
  return resp;
}

TEST_CASE("2", "[JWSFromURLTest]")
{
  INFO("TEST 2, Test JWT Parsing and Stripping From URLs");

  SECTION("Token at end of URI")
  {
    fprintf(stderr, "Test 2: JWT Parsing and Stripping from URL strings\n");
    fprintf(stderr, "========================================\n");
    REQUIRE(jws_parsing_helper(
      "www.foo.com/hellothere/"
      "URISigningPackage=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
      "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
      "URISigningPackage", "www.foo.com/hellothere", 22, '/', 0));
  }

  SECTION("No Token in URL")
  {
    REQUIRE(!jws_parsing_helper(
      "www.foo.com/hellothere/"
      "URISigningPackag=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
      "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
      "URISigningPackage", NULL, 0, 0, 0));
  }

  SECTION("Token in middle of the URL")
  {
    REQUIRE(jws_parsing_helper("www.foo.com/hellothere/"
                               "URISigningPackage=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
                               "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ."
                               "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c/Something/Else",
                               "URISigningPackage", "www.foo.com/hellothere/Something/Else", 22, '/', '/'));
  }

  SECTION("Token at the start of the URL")
  {
    REQUIRE(jws_parsing_helper(":URISigningPackage=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
                               "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ."
                               "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c/www.foo.com/hellothere/Something/Else",
                               "URISigningPackage", "/www.foo.com/hellothere/Something/Else", 0, ':', '/'));
  }

  SECTION("Pass empty path parameter at end")
  {
    REQUIRE(!jws_parsing_helper("www.foobar.com/hellothere/URISigningPackage=", "URISigningPackage", NULL, 0, 0, 0));
  }

  SECTION("Pass empty path parameter in the middle of URL")
  {
    REQUIRE(!jws_parsing_helper("www.foobar.com/hellothere/URISigningPackage=/Something/Else", "URISigningPackage", NULL, 0, 0, 0));
  }

  SECTION("Partial package name in previous path parameter")
  {
    REQUIRE(jws_parsing_helper("www.foobar.com/URISig/"
                               "URISigningPackage=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
                               "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ."
                               "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c/Something/Else",
                               "URISigningPackage", "www.foobar.com/URISig/Something/Else", 21, '/', '/'));
  }

  SECTION("Package comes directly after two reserved characters")
  {
    REQUIRE(jws_parsing_helper("www.foobar.com/"
                               ":URISigningPackage=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
                               "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ."
                               "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c/Something/Else",
                               "URISigningPackage", "www.foobar.com//Something/Else", 15, ':', '/'));
  }

  SECTION("Package comes directly after string of reserved characters")
  {
    REQUIRE(jws_parsing_helper("www.foobar.com/?!/"
                               ":URISigningPackage=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
                               "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ."
                               "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c/Something/Else",
                               "URISigningPackage", "www.foobar.com/?!//Something/Else", 18, ':', '/'));
  }

  SECTION("Invalid token passed before a valid token")
  {
    REQUIRE(!jws_parsing_helper("www.foobar.com/URISigningPackage=/"
                                "URISigningPackage=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
                                "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ."
                                "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c/Something/Else",
                                "URISigningPackage", NULL, 0, '/', '/'));
  }

  SECTION("Empty string as URL") { REQUIRE(!jws_parsing_helper("", "URISigningPackage", NULL, 0, 0, 0)); }

  SECTION("Empty package name to parser")
  {
    REQUIRE(!jws_parsing_helper(
      "www.foobar.com/"
      "URISigningPackage=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
      "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
      "", NULL, 0, 0, 0));
  }

  SECTION("Custom package name with a reserved character - at the end of the URI")
  {
    REQUIRE(jws_parsing_helper(
      "www.foobar.com/CustomPackage/"
      "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ."
      "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
      "CustomPackage/", "www.foobar.com", 14, '/', 0));
  }

  SECTION("Custom package name with a reserved character - in the middle of the URI")
  {
    REQUIRE(jws_parsing_helper(
      "www.foobar.com/CustomPackage/"
      "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ."
      "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c/Something/Else",
      "CustomPackage/", "www.foobar.com/Something/Else", 14, '/', '/'));
  }

  SECTION("URI signing package passed as the only a query parameter")
  {
    REQUIRE(jws_parsing_helper(
      "www.foobar.com/Something/"
      "Here?URISigningPackage=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
      "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
      "URISigningPackage", "www.foobar.com/Something/Here", 29, '?', 0));
  }

  SECTION("URI signing package passed as first of many query parameters")
  {
    REQUIRE(jws_parsing_helper("www.foobar.com/Something/"
                               "Here?URISigningPackage=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
                               "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ."
                               "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c&query3=foobar&query1=foo&query2=bar",
                               "URISigningPackage", "www.foobar.com/Something/Here?query3=foobar&query1=foo&query2=bar", 30, '?',
                               '&'));
  }

  SECTION("URI signing package passed as one of many query parameters - passed in middle")
  {
    REQUIRE(jws_parsing_helper("www.foobar.com/Something/"
                               "Here?query1=foo&query2=bar&URISigningPackage=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
                               "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ."
                               "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c&query3=foobar",
                               "URISigningPackage", "www.foobar.com/Something/Here?query1=foo&query2=bar&query3=foobar", 52, '&',
                               '&'));
  }

  SECTION("URI signing package passed as last of many query parameters")
  {
    REQUIRE(jws_parsing_helper("www.foobar.com/Something/"
                               "Here?query1=foo&query2=bar&URISigningPackage=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
                               "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ."
                               "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
                               "URISigningPackage", "www.foobar.com/Something/Here?query1=foo&query2=bar", 51, '&', 0));
  }

  fprintf(stderr, "\n");
}

bool
remove_dot_helper(const char *path, const char *expected_path)
{
  fprintf(stderr, "Removing Dot Segments from Path: %s\n", path);
  size_t path_ct = strlen(path);
  path_ct++;
  int new_ct;
  char path_buffer[path_ct];
  memset(path_buffer, 0, path_ct);

  new_ct = remove_dot_segments(path, path_ct, path_buffer, path_ct);

  if (new_ct < 0) {
    return false;
  } else if (strcmp(expected_path, path_buffer) == 0) {
    return true;
  } else {
    return false;
  }
}

TEST_CASE("3", "[RemoveDotSegmentsTest]")
{
  INFO("TEST 3, Test Removal of Dot Segments From Paths");

  SECTION("../bar test")
  {
    fprintf(stderr, "Test 3: Removal of Dot Segments From Paths\n");
    fprintf(stderr, "========================================\n");
    REQUIRE(remove_dot_helper("../bar", "bar"));
  }

  SECTION("./bar test") { REQUIRE(remove_dot_helper("./bar", "bar")); }

  SECTION(".././bar test") { REQUIRE(remove_dot_helper(".././bar", "bar")); }

  SECTION("./../bar test") { REQUIRE(remove_dot_helper("./../bar", "bar")); }

  SECTION("/foo/./bar test") { REQUIRE(remove_dot_helper("/foo/./bar", "/foo/bar")); }

  SECTION("/bar/./ test") { REQUIRE(remove_dot_helper("/bar/./", "/bar/")); }

  SECTION("/. test") { REQUIRE(remove_dot_helper("/.", "/")); }

  SECTION("/bar/. test") { REQUIRE(remove_dot_helper("/bar/.", "/bar/")); }

  SECTION("/foo/../bar test") { REQUIRE(remove_dot_helper("/foo/../bar", "/bar")); }

  SECTION("/bar/../ test") { REQUIRE(remove_dot_helper("/bar/../", "/")); }

  SECTION("/.. test") { REQUIRE(remove_dot_helper("/..", "/")); }

  SECTION("/bar/.. test") { REQUIRE(remove_dot_helper("/bar/..", "/")); }

  SECTION("/foo/bar/.. test") { REQUIRE(remove_dot_helper("/foo/bar/..", "/foo/")); }

  SECTION("Single . test") { REQUIRE(remove_dot_helper(".", "")); }

  SECTION("Single .. test") { REQUIRE(remove_dot_helper("..", "")); }

  SECTION("Test foo/bar/.. test") { REQUIRE(remove_dot_helper("foo/bar/..", "foo/")); }

  SECTION("Test Empty Path Segment") { REQUIRE(remove_dot_helper("", "")); }

  SECTION("Test mixed operations") { REQUIRE(remove_dot_helper("/foo/bar/././something/../foobar", "/foo/bar/foobar")); }
  fprintf(stderr, "\n");
}

bool
normalize_uri_helper(const char *uri, const char *expected_normal)
{
  size_t uri_ct = strlen(uri);
  int buff_size = uri_ct + 2;
  int err;
  char *uri_normal = (char *)malloc(buff_size);
  memset(uri_normal, 0, buff_size);

  err = normalize_uri(uri, uri_ct, uri_normal, buff_size);

  if (err) {
    free(uri_normal);
    return false;
  }

  if (expected_normal && strcmp(expected_normal, uri_normal) == 0) {
    free(uri_normal);
    return true;
  }

  free(uri_normal);
  return false;
}

TEST_CASE("4", "[NormalizeTest]")
{
  INFO("TEST 4, Test Normalization of URIs");

  SECTION("Testing passing too small of a URI to normalize")
  {
    fprintf(stderr, "Test 4: Normalization Tests\n");
    fprintf(stderr, "========================================\n");
    REQUIRE(!normalize_uri_helper("ht", NULL));
  }

  SECTION("Testing passing non http/https protocol") { REQUIRE(!normalize_uri_helper("ht:", NULL)); }

  SECTION("Passing a uri with half encoded value at end") { REQUIRE(!normalize_uri_helper("http://www.foobar.co%4", NULL)); }

  SECTION("Passing a uri with half encoded value in the middle")
  {
    REQUIRE(!normalize_uri_helper("http://www.foobar.co%4psomethin/Path", NULL));
  }

  SECTION("Passing a uri with an empty path parameter")
  {
    REQUIRE(normalize_uri_helper("http://www.foobar.com", "http://www.foobar.com/"));
  }

  SECTION("Passing a uri with an empty path parameter and additional query params")
  {
    REQUIRE(normalize_uri_helper("http://www.foobar.com?query1=foo&query2=bar", "http://www.foobar.com/?query1=foo&query2=bar"));
  }

  SECTION("Empty path parameter with port")
  {
    REQUIRE(normalize_uri_helper("http://www.foobar.com:9301?query1=foo&query2=bar",
                                 "http://www.foobar.com:9301/?query1=foo&query2=bar"));
  }

  SECTION("Passing a uri with a username and password")
  {
    REQUIRE(normalize_uri_helper("http://foo%40:PaSsword@www.Foo%42ar.coM:80/", "http://foo%40:PaSsword@www.foobar.com/"));
  }

  SECTION("Testing Removal of standard http Port")
  {
    REQUIRE(normalize_uri_helper("http://foobar.com:80/Something/Here", "http://foobar.com/Something/Here"));
  }

  SECTION("Testing Removal of standard https Port")
  {
    REQUIRE(normalize_uri_helper("https://foobar.com:443/Something/Here", "https://foobar.com/Something/Here"));
  }

  SECTION("Testing passing of non-standard http Port")
  {
    REQUIRE(normalize_uri_helper("http://foobar.com:443/Something/Here", "http://foobar.com:443/Something/Here"));
  }

  SECTION("Testing passing of non-standard https Port")
  {
    REQUIRE(normalize_uri_helper("https://foobar.com:80/Something/Here", "https://foobar.com:80/Something/Here"));
  }

  SECTION("Testing the removal of . and .. in the path ")
  {
    REQUIRE(
      normalize_uri_helper("https://foobar.com:80/Something/Here/././foobar/../foo", "https://foobar.com:80/Something/Here/foo"));
  }

  SECTION("Testing . and .. segments in non path components")
  {
    REQUIRE(normalize_uri_helper("https://foobar.com:80/Something/Here?query1=/././foo/../bar",
                                 "https://foobar.com:80/Something/Here?query1=/././foo/../bar"));
  }

  SECTION("Testing standard decdoing of multiple characters")
  {
    REQUIRE(normalize_uri_helper("https://kelloggs%54ester.com/%53omething/Here", "https://kelloggstester.com/Something/Here"));
  }

  SECTION("Testing passing encoded reserved characters")
  {
    REQUIRE(
      normalize_uri_helper("https://kelloggs%54ester.com/%53omething/Here%3f", "https://kelloggstester.com/Something/Here%3F"));
  }

  SECTION("Mixed Bag Test case")
  {
    REQUIRE(normalize_uri_helper("https://foo:something@kellogs%54ester.com:443/%53omething/.././here",
                                 "https://foo:something@kellogstester.com/here"));
  }

  SECTION("Testing empty hostname with userinfon") { REQUIRE(!normalize_uri_helper("https://foo:something@", NULL)); }

  SECTION("Testing empty uri after http://") { REQUIRE(!normalize_uri_helper("http://", NULL)); }

  SECTION("Testing http:///////") { REQUIRE(!normalize_uri_helper("http:///////", NULL)); }

  SECTION("Testing empty uri after http://?/") { REQUIRE(!normalize_uri_helper("http://?/", NULL)); }
  fprintf(stderr, "\n");
}

TEST_CASE("5", "[RegexTests]")
{
  INFO("TEST 5, Test Regex Matching");

  SECTION("Standard regex")
  {
    fprintf(stderr, "Test 5: Testing Regex Engine\n");
    fprintf(stderr, "========================================\n");
    REQUIRE(match_regex("http://kelloggsTester.souza.local/KellogsDir/*",
                        "http://kelloggsTester.souza.local/KellogsDir/some_manifest.m3u8"));
  }

  SECTION("Back references are not supported") { REQUIRE(!match_regex("(b*a)\\1$", "bbbbba")); }

  SECTION("Escape a special character") { REQUIRE(match_regex("money\\$", "money$bags")); }

  SECTION("Dollar sign")
  {
    REQUIRE(!match_regex(".+foobar$", "foobarfoofoo"));
    REQUIRE(match_regex(".+foobar$", "foofoofoobar"));
  }

  SECTION("Number Quantifier with Groups")
  {
    REQUIRE(match_regex("(abab){2}", "abababab"));
    REQUIRE(!match_regex("(abab){2}", "abab"));
  }

  SECTION("Alternation") { REQUIRE(match_regex("cat|dog", "dog")); }
  fprintf(stderr, "\n");
}

TEST_CASE("6", "[AudTests]")
{
  INFO("TEST 6, Test Aud Matching");

  json_error_t *err = NULL;
  SECTION("Standard aud string match")
  {
    fprintf(stderr, "Test 6: Aud Matching Tests\n");
    fprintf(stderr, "========================================\n");
    json_t *raw = json_loads(R"({"aud": "tester"})", 0, err);
    json_t *aud = json_object_get(raw, "aud");
    REQUIRE(jwt_check_aud(aud, "tester"));
    json_decref(aud);
    json_decref(raw);
  }

  SECTION("Standard aud array match")
  {
    json_t *raw = json_loads(R"({"aud": [ "foo", "bar",  "tester"]})", 0, err);
    json_t *aud = json_object_get(raw, "aud");
    REQUIRE(jwt_check_aud(aud, "tester"));
    json_decref(aud);
    json_decref(raw);
  }

  SECTION("Standard aud string mismatch")
  {
    json_t *raw = json_loads(R"({"aud": "foo"})", 0, err);
    json_t *aud = json_object_get(raw, "aud");
    REQUIRE(!jwt_check_aud(aud, "tester"));
    json_decref(aud);
    json_decref(raw);
  }

  SECTION("Standard aud array mismatch")
  {
    json_t *raw = json_loads(R"({"aud": ["foo", "bar", "foobar"]})", 0, err);
    json_t *aud = json_object_get(raw, "aud");
    REQUIRE(!jwt_check_aud(aud, "tester"));
    json_decref(aud);
    json_decref(raw);
  }

  SECTION("Integer trying to pass as an aud")
  {
    json_t *raw = json_loads(R"({"aud": 1})", 0, err);
    json_t *aud = json_object_get(raw, "aud");
    REQUIRE(!jwt_check_aud(aud, "tester"));
    json_decref(aud);
    json_decref(raw);
  }

  SECTION("Integer mixed into a passing aud array")
  {
    json_t *raw = json_loads(R"({"aud": [1, "foo", "bar", "tester"]})", 0, err);
    json_t *aud = json_object_get(raw, "aud");
    REQUIRE(jwt_check_aud(aud, "tester"));
    json_decref(aud);
    json_decref(raw);
  }

  SECTION("Case sensitive test for single string")
  {
    json_t *raw = json_loads(R"({"aud": "TESTer"})", 0, err);
    json_t *aud = json_object_get(raw, "aud");
    REQUIRE(!jwt_check_aud(aud, "tester"));
    json_decref(aud);
    json_decref(raw);
  }

  SECTION("Case sensitive test for array")
  {
    json_t *raw = json_loads(R"({"aud": [1, "foo", "bar", "Tester"]})", 0, err);
    json_t *aud = json_object_get(raw, "aud");
    REQUIRE(!jwt_check_aud(aud, "tester"));
    json_decref(aud);
    json_decref(raw);
  }

  fprintf(stderr, "\n");
}

TEST_CASE("7", "[TestsConfig]")
{
  INFO("TEST 7, Config Loading and Config Functions");

  SECTION("Config Loading ID Field")
  {
    fprintf(stderr, "Test 7: Config file loading and Config file tests\n");
    fprintf(stderr, "========================================\n");
    struct config *cfg = read_config("experimental/uri_signing/unit_tests/testConfig.config");
    REQUIRE(cfg != NULL);
    REQUIRE(strcmp(config_get_id(cfg), "tester") == 0);
    config_delete(cfg);
  }
  fprintf(stderr, "\n\n");
}

bool
jws_validation_helper(const char *url, const char *package, struct config *cfg, int exp_rc)
{
  size_t url_ct            = strlen(url);
  struct strip_state *strp = strip_state_new(url_ct + 1);
  int valid;

  cjose_jws_t *jws = get_jws_from_uri(url, url_ct, package, url_ct + 1, strp);
  if (!jws) {
    strip_state_delete(strp);
    return false;
  }

  struct jwt *jwt = validate_jws(jws, cfg, strp->strip_uri, strp->strip_uri_ct, &valid);
  fprintf(stderr, "Return Code: %d\n", valid);
  if (valid == exp_rc) {
    jwt_delete(jwt);
    cjose_jws_release(jws);
    strip_state_delete(strp);
    return true;
  }
  if (jwt) {
    jwt_delete(jwt);
  }
  cjose_jws_release(jws);
  strip_state_delete(strp);
  return false;
}

TEST_CASE("8", "[TestsWithConfig]")
{
  INFO("TEST 8, Tests Involving Validation with Config");

  struct config *cfg = read_config("experimental/uri_signing/unit_tests/testConfig.config");

  SECTION("Validation of Valid Aud String in JWS")
  {
    fprintf(stderr, "Test 8: Top level full validation with a loaded configuration file\n");
    fprintf(stderr, "========================================\n");
    fprintf(stderr, "Test valid aud string in JWS\n");
    REQUIRE(jws_validation_helper("http://www.foobar.com/"
                                  "URISigningPackage=eyJLZXlJREtleSI6IjUiLCJhbGciOiJIUzI1NiJ9."
                                  "eyJjZG5pZXRzIjozMCwiY2RuaXN0dCI6MSwiaXNzIjoiTWFzdGVyIElzc3VlciIsImF1ZCI6InRlc3RlciIsImNkbml1YyI6"
                                  "InJlZ2V4Omh0dHA6Ly93d3cuZm9vYmFyLmNvbS8qIn0.InBxVm6OOAglNqc-U5wAZaRQVebJ9PK7Y9i7VFHWYHU",
                                  "URISigningPackage", cfg, 200));
  }

  SECTION("Validation of Invalid Aud String in JWS")
  {
    fprintf(stderr, "Test invalid aud string in JWS\n");
    REQUIRE(jws_validation_helper("http://www.foobar.com/"
                                  "URISigningPackage=eyJLZXlJREtleSI6IjUiLCJhbGciOiJIUzI1NiJ9."
                                  "eyJjZG5pZXRzIjozMCwiY2RuaXN0dCI6MSwiaXNzIjoiTWFzdGVyIElzc3VlciIsImF1ZCI6ImJhZCIsImNkbml1YyI6InJ"
                                  "lZ2V4Omh0dHA6Ly93d3cuZm9vYmFyLmNvbS8qIn0.aCOo8gOBa5G1RKkkzgWYwc79dPRw_fQUC0k1sWcjkyM",
                                  "URISigningPackage", cfg, 407));
  }

  SECTION("Validation of Valid Aud Array in JWS")
  {
    fprintf(stderr, "Test valid aud array in JWS\n");
    REQUIRE(jws_validation_helper(
      "http://www.foobar.com/"
      "URISigningPackage=eyJLZXlJREtleSI6IjUiLCJhbGciOiJIUzI1NiJ9."
      "eyJjZG5pZXRzIjozMCwiY2RuaXN0dCI6MSwiaXNzIjoiTWFzdGVyIElzc3VlciIsImF1ZCI6WyJiYWQiLCJpbnZhbGlkIiwidGVzdGVyIl0sImNkbml1YyI6InJl"
      "Z2V4Omh0dHA6Ly93d3cuZm9vYmFyLmNvbS8qIn0.7lyepZMzc_odieKvOTN2U-k1gLwRKS8KJIvDFQXDqGs",
      "URISigningPackage", cfg, 200));
  }

  SECTION("Validation of Invalid Aud Array in JWS")
  {
    fprintf(stderr, "Test invalid aud array in JWS\n");
    REQUIRE(jws_validation_helper(
      "http://www.foobar.com/"
      "URISigningPackage=eyJLZXlJREtleSI6IjUiLCJhbGciOiJIUzI1NiJ9."
      "eyJjZG5pZXRzIjozMCwiY2RuaXN0dCI6MSwiaXNzIjoiTWFzdGVyIElzc3VlciIsImF1ZCI6WyJiYWQiLCJpbnZhbGlkIiwiZm9vYmFyIl0sImNkbml1YyI6InJl"
      "Z2V4Omh0dHA6Ly93d3cuZm9vYmFyLmNvbS8qIn0.CU3WMJAPs0uRC7NKXvatVG9uU9SANdZzqO0GdQUatxk",
      "URISigningPackage", cfg, 407));
  }

  SECTION("Validation of Valid Aud Array Mixed types in JWS")
  {
    REQUIRE(jws_validation_helper(
      "http://www.foobar.com/"
      "URISigningPackage=eyJLZXlJREtleSI6IjUiLCJhbGciOiJIUzI1NiJ9."
      "eyJjZG5pZXRzIjozMCwiY2RuaXN0dCI6MSwiaXNzIjoiTWFzdGVyIElzc3VlciIsImF1ZCI6WyJiYWQiLDEsImZvb2JhciIsInRlc3RlciJdLCJjZG5pdWMiOiJy"
      "ZWdleDpodHRwOi8vd3d3LmZvb2Jhci5jb20vKiJ9._vlXsA3r7RPje2ZdMnpaGTwIsdNMjuQWPEHRkGKTVL8",
      "URISigningPackage", cfg, 200));
  }

  SECTION("Validation of ivalid signature")
  {
    REQUIRE(jws_validation_helper("http://www.foobar.com/"
                                  "URISigningPackage=eyJLZXlJREtleSI6IjUiLCJhbGciOiJIUzI1NiJ9."
                                  "eyJjZG5pZXRzIjozMCwiY2RuaXN0dCI6MSwiaXNzIjoiTWFzdGVyIElzc3VlciIsImF1ZCI6WyJiYWQiLDEsImZvb2JhciIs"
                                  "InRlc3RlciJdLCJjZG5pdWMiOiJpbnZhbGlkIn0.ZaAhDIuXaTthQd5tL7f6ggnp9jXppaXF-SqXTsKY_sgpQQ",
                                  "URISigningPackage", cfg, 400));
  }

  SECTION("Validation of ivalid cdniuc claim")
  {
    REQUIRE(jws_validation_helper("http://www.foobar.com/"
                                  "URISigningPackage=eyJLZXlJREtleSI6IjUiLCJhbGciOiJIUzI1NiJ9."
                                  "eyJjZG5pZXRzIjozMCwiY2RuaXN0dCI6MSwiaXNzIjoiTWFzdGVyIElzc3VlciIsImF1ZCI6WyJiYWQiLDEsImZvb2JhciIs"
                                  "InRlc3RlciJdLCJjZG5pdWMiOiJpbnZhbGlkIn0.ZaAhDIuXaTthQd5tL7f6ggnp9jXXF-SqXTsKY_sgpQQ",
                                  "URISigningPackage", cfg, 403));
  }

  config_delete(cfg);
  fprintf(stderr, "\n");
}

bool
renew_helper(const char *token_string)
{
  fprintf(stderr, "Parsing JWT from string: %s\n", token_string);
  bool resp;
  json_error_t jerr = {};
  size_t pt_ct      = strlen(token_string);
  struct jwt *jwt   = parse_jwt(json_loadb(token_string, pt_ct, 0, &jerr));
  char *renew_token = NULL;

  if (jwt) {
    cjose_err *err = {0};
    cjose_jwk_t *jwk =
      cjose_jwk_import(R"({"alg":"HS256","k":"nxb7fyO5Z2hGz9E3oKm1357ptvC2su5QwQUb4YaIaIc","kid":"0","kty":"oct"})", 87, err);

    renew_token = renew(jwt, "Master Issuer", jwk, "HS256", "URISigningPackage");
    cjose_jwk_release(jwk);
    if (!renew_token) {
      resp = false;
    } else {
      fprintf(stderr, "Renewed Token is: %s\n", renew_token);
      resp = true;
    }
  } else {
    resp = false;
  }
  jwt_delete(jwt);
  if (renew_token) {
    free(renew_token);
  }
  return resp;
}

/* These tests are currently only testing the logic of when tokens should be renewed based
 * on the various jwt values that can be set. It does not test the correctness of the tokens being
 * generated if it does indeed renew. */
TEST_CASE("9", "[TestTokenRenewal]")
{
  INFO("TEST 9, Token version renewal logic test");

  SECTION("Standard Cookie Renewal")
  {
    fprintf(stderr, "Test 9: Token version renewal logic tests\n");
    fprintf(stderr, "========================================\n");
    REQUIRE(renew_helper(
      R"({"cdniets":30,"cdnistt":1,"iss":"Content Access Manager","cdniuc":"uri-regex:http://foobar.local/testDir/*"})"));
  }

  SECTION("Cookie Renewal with no iets")
  {
    REQUIRE(!renew_helper(R"({"cdnistt":1,"iss":"Content Access Manager","cdniuc":"uri-regex:http://foobar.local/testDir/*"})"));
  }

  SECTION("Standard Redirect Renwal")
  {
    REQUIRE(renew_helper(
      R"({"cdniv":-1,"cdniets":30,"cdnistt":-1,"x1rt":1551388494,"x1rts":30,"iss":"Content Access Manager","cdniuc":"uri-regex:http://foobar.local/testDir/*"})"));
  }

  SECTION("Redirect Renewal x1rt not satisfied")
  {
    REQUIRE(!renew_helper(
      R"({"cdniv":-1,"cdniets":30,"cdnistt":-1,"x1rt":32508767694,"x1rts":30,"iss":"Content Access Manager","cdniuc":"uri-regex:http://foobar.local/testDir/*"})"));
  }

  SECTION("Cdniv 1 but attempting to use redirect renewal")
  {
    REQUIRE(!renew_helper(
      R"({"cdniv":1,"cdniets":30,"cdnistt":-1,"x1rt":1551388494,"x1rts":30,"iss":"Content Access Manager","cdniuc":"uri-regex:http://foobar.local/testDir/*"})"));
  }

  SECTION("Cdniv -1 using cookie renewal")
  {
    REQUIRE(renew_helper(
      R"({"cdniv":-1,"cdniets":30,"cdnistt":1,"x1rt":1551388494,"x1rts":30,"iss":"Content Access Manager","cdniuc":"uri-regex:http://foobar.local/testDir/*"})"));
  }
  fprintf(stderr, "\n");
}

bool
renew_url_helper(struct strip_state *strp, char *new_token, const char *expected_url)
{
  char *renew = (char *)malloc(1500);
  get_redirect_renew_url(strp, new_token, renew, 1500);
  fprintf(stderr, "New Redirect url: %s\n", renew);
  if (strcmp(renew, expected_url) == 0) {
    free(renew);
    return true;
  }
  free(renew);
  return false;
}

TEST_CASE("10", "[TestRedirectRenwalUrlBuilder]")
{
  INFO("TEST 10, Redirect Renewal URL builder tests");

  char new_token[]         = "URISigningPackage=NewToken";
  struct strip_state *strp = strip_state_new(1000);

  SECTION("Insert a token as the last query param")
  {
    fprintf(stderr, "Test 10: Redirect Renewal URL builder tests\n");
    fprintf(stderr, "========================================\n");
    strcpy(strp->strip_uri, "http://foobar.com/some/path?query1=foo&query2=bar");
    strp->term     = 0;
    strp->reserved = '&';
    strp->index    = 49;
    REQUIRE(renew_url_helper(strp, new_token, "http://foobar.com/some/path?query1=foo&query2=bar&URISigningPackage=NewToken"));
  }

  SECTION("Insert a token as a middle query param")
  {
    strcpy(strp->strip_uri, "http://foobar.com/some/path?query1=foo&query2=bar");
    strp->term     = '&';
    strp->reserved = '&';
    strp->index    = 39;
    REQUIRE(renew_url_helper(strp, new_token, "http://foobar.com/some/path?query1=foo&URISigningPackage=NewToken&query2=bar"));
  }

  SECTION("Insert a token as the first query param")
  {
    strcpy(strp->strip_uri, "http://foobar.com/some/path?query1=foo&query2=bar");
    strp->term     = '&';
    strp->reserved = '?';
    strp->index    = 28;
    REQUIRE(renew_url_helper(strp, new_token, "http://foobar.com/some/path?URISigningPackage=NewToken&query1=foo&query2=bar"));
  }

  SECTION("Insert a token as the last path param of many")
  {
    strcpy(strp->strip_uri, "http://foobar.com/some/path?query1=foo&query2=bar");
    strp->term     = '?';
    strp->reserved = '/';
    strp->index    = 27;
    REQUIRE(renew_url_helper(strp, new_token, "http://foobar.com/some/path/URISigningPackage=NewToken?query1=foo&query2=bar"));
  }

  SECTION("Insert a token as a middle path param of many")
  {
    strcpy(strp->strip_uri, "http://foobar.com/some/path?query1=foo&query2=bar");
    strp->term     = '/';
    strp->reserved = '/';
    strp->index    = 22;
    REQUIRE(renew_url_helper(strp, new_token, "http://foobar.com/some/URISigningPackage=NewToken/path?query1=foo&query2=bar"));
  }

  SECTION("Insert a token as the first path param of many")
  {
    strcpy(strp->strip_uri, "http://foobar.com/some/path?query1=foo&query2=bar");
    strp->term     = '/';
    strp->reserved = '/';
    strp->index    = 17;
    REQUIRE(renew_url_helper(strp, new_token, "http://foobar.com/URISigningPackage=NewToken/some/path?query1=foo&query2=bar"));
  }

  strip_state_delete(strp);
  fprintf(stderr, "\n");
}
