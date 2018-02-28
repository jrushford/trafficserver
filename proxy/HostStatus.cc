/** @file

  Implementation of Host Proxy routing

  @section license License

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
#include "HostStatus.h"
HostStatus* HostStatus::p_instance = nullptr;

HostStatus::HostStatus()
  : next_hops(ink_hash_table_create(InkHashTableKeyType_String))
{
  ink_mutex_init(&next_hop_mutex);
}

HostStatus::~HostStatus()
{
  InkHashTableIteratorState ht_iter;
  InkHashTableEntry *ht_entry = nullptr;
  ht_entry                    = ink_hash_table_iterator_first(next_hops, &ht_iter);

  while (ht_entry != nullptr) {
    char *value = static_cast<char *>(ink_hash_table_entry_value(next_hops, ht_entry));
    ats_free(value);
    ht_entry = ink_hash_table_iterator_next(next_hops, &ht_iter);
  }
  ink_hash_table_destroy(next_hops);

  ink_mutex_destroy(&next_hop_mutex);
}

HostStatus *
HostStatus::instance() 
{
  return p_instance;
}

HostStatus *
HostStatus::init()
{
  if (!p_instance) {
    p_instance = new HostStatus();
  }
  return p_instance;
}

void 
HostStatus::setHostStatus(const char *key, const HostStatus_t& status)
{
  HostStatus_t *_status;

  ink_mutex_acquire(&next_hop_mutex);
  if (ink_hash_table_lookup(next_hops, key, (void **)&_status)) {
    *_status = status;
  } else {
    Debug("parent_select", "In HostConfigParams::setHostStatus(): key: %s, status: %d", key, status);
    _status = new HostStatus_t();
    *_status  = status;
    ink_hash_table_insert(next_hops, key, _status);
  }
  ink_mutex_release(&next_hop_mutex);
}

HostStatus_t
HostStatus::getHostStatus(const char *key)
{
  HostStatus_t *status;
  if (ink_hash_table_lookup(next_hops, key, (void **)&status)) {
    Debug("parent_select", "In HostConfigParams::getHostStatus(): key: %s, status: %d", key, *status);
    return *status;
  }
  return HOST_STATUS_INIT;
}
