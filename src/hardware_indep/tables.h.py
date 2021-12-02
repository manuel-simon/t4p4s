# SPDX-License-Identifier: Apache-2.0
# Copyright 2018 Eotvos Lorand University, Budapest, Hungary

#[ #ifndef __TABLES_H__
#[ #define __TABLES_H__

#[ #include "stateful_memory.h"
#[ #include "actions.h"

#[ typedef bool entry_validity_t;

for table in hlir.tables:
    #{ typedef struct table_entry_${table.name}_s {
    #[     struct ${table.name}_action  action;
    if (table.used_writable and table.synced):
        #[     lock_t                   lock;
    #[     entry_validity_t         is_entry_valid;
    #} } table_entry_${table.name}_t;


#[ #define NB_TABLES ${len(hlir.tables)}

#{ enum table_names {
for table in hlir.tables:
    #[ TABLE_${table.name},
#[ TABLE_,
#} };

#[ #endif
