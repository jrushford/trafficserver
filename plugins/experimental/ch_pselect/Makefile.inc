#  Licensed to the Apache Software Foundation (ASF) under one
#  or more contributor license agreements.  See the NOTICE file
#  distributed with this work for additional information
#  regarding copyright ownership.  The ASF licenses this file
#  to you under the Apache License, Version 2.0 (the
#  "License"); you may not use this file except in compliance
#  with the License.  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

pkglib_LTLIBRARIES += experimental/ch_pselect/ch_pselect.la

experimental_ch_pselect_ch_pselect_la_SOURCES = \
  experimental/ch_pselect/ch_pselect.cc \
  experimental/ch_pselect/ch_config.cc

experimental_ch_pselect_ch_pselect_la_LDFLAGS = \
  $(AM_LDFLAGS)

AM_CPPFLAGS += @YAMLCPP_INCLUDES@ $(TS_INCLUDES)

check_PROGRAMS += experimental/ch_pselect/test_ch_pselect

experimental_ch_pselect_test_ch_pselect_CPPFLAGS = \
  $(AM_CPPFLAGS) \
  -Iexperimental/ch_pselect \
  -I$(abs_top_srcdir)/tests/include \
  -D_CH_PSELECT_UNIT_TESTS

experimental_ch_pselect_test_ch_pselect_SOURCES = \
  experimental/ch_pselect/unit-tests/ch_pselect_test.cc \
  experimental/ch_pselect/ch_config.cc

experimental_ch_pselect_test_ch_pselect_LDFLAGS = \
  @YAMLCPP_LDFLAGS@

experimental_ch_pselect_test_ch_pselect_LDADD = \
  @AM_LDFLAGS@ \
  @YAMLCPP_LIBS@ \
  $(abs_top_builddir)/src/tscore/libtscore.la

