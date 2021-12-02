# SPDX-License-Identifier: Apache-2.0
# Copyright 2016 Eotvos Lorand University, Budapest, Hungary

from utils.codegen import format_expr, make_const
import utils.codegen
from compiler_log_warnings_errors import addError, addWarning
from compiler_common import generate_var_name, prepend_statement

#[ #include "dataplane.h"
#[ #include "actions.h"
#[ #include "tables.h"
#[ #include "stateful_memory.h"
#[ #include "dpdk_lib.h"
#[ #include "util_debug.h"
#[

#[ extern void exact_add_promote(int tableid, uint8_t* key, uint8_t* value, bool should_print);

#[ lookup_table_t table_config[NB_TABLES] = {
for table in hlir.tables:
    tmt = table.matchType.name
    ks  = table.key_length_bytes
    ts = table.table_size if hasattr(table, 'size') else 512
    lk = "true" if table.used_writable and table.synced else "false"
    hr = "false" if table.impl == "dpdk" else "true"

    #[ {
    #[  .name= "${table.name}",
    #[  .id = TABLE_${table.name},
    #[  .type = LOOKUP_$tmt,

    #[  .default_val = NULL,

    #[  .is_hidden = ${"true" if table.is_hidden else "false"},

    #[  .entry = {
    #[      .entry_count = 0,

    #[      .key_size = $ks,

    if table.used_writable and table.synced:
        #[      .entry_size = RTE_ALIGN(sizeof(struct ${table.name}_action) + sizeof(entry_validity_t) + sizeof(lock_t), 16),
        #[      .lock_size = sizeof(lock_t),
    else:
        #[      .entry_size = sizeof(struct ${table.name}_action) + sizeof(entry_validity_t),
        #[      .lock_size = 0,
    #[      .action_size   = sizeof(struct ${table.name}_action),
    #[      .validity_size = sizeof(entry_validity_t),
    #[  },

    #[  .min_size = 0,
    #[  .max_size = $ts,
    #[  .access_locked = $lk,
    #[  .has_replicas = $hr,
    #[ },
#[ };


#[ extern struct socket_state state[NB_SOCKETS];
#[ extern void table_setdefault_promote  (int tableid, uint8_t* value);
#[ extern int master_socket_id;

#{ void init_table_default_actions() {
#[     debug(" :::: Init table default actions\n");

for table in hlir.tables:
    #[ int current_replica_${table.name} = state[master_socket_id].active_replica[TABLE_${table.name}];
    #{ if (state[master_socket_id].tables[TABLE_${table.name}][current_replica_${table.name}]->default_val == NULL) {
    #{     table_entry_${table.name}_t initial_default = {
    #[          .action = { action_${table.default_action.expression.method.action_ref.name} },
    #[          .is_entry_valid = VALID_TABLE_ENTRY,
    #}     };
    #[     table_setdefault_promote(TABLE_${table.name}, (uint8_t *)&initial_default);
    #} }
#} }

#{ void init_table_const_entries() {
for table in hlir.tables:
    if 'entries' not in table:
        #[ // table ${table.name} does not have const entries
        continue

    for entry in table.entries.entries:
        if any((component.urtype.node_type == 'Type_Dontcare' for component in entry.keys.components)):
            addWarning("adding const entry", f"Underscore entry for const entry for table {table.name} not supported yet")
            continue

        utils.codegen.pre_statement_buffer = ""

        action_id = entry.action.method.path.name

        key_total_size = (sum((key.urtype.size for key in entry.keys.components))+7) // 8

        key_var = generate_var_name("key", f"{table.name}__{action_id}")
        action_var = generate_var_name("action", f"{table.name}__{action_id}")

        params = entry.action.method.type.parameters.parameters
        args = entry.action.arguments

        #[ ${utils.codegen.pre_statement_buffer}

        #[ uint8_t ${key_var}[${key_total_size}];

        def make_var(key, ksize):
            name, hex_content = make_const(key)
            const_var = generate_var_name(f"const{ksize}", name)
            return const_var, hex_content

        keys = entry.keys.components
        key_sizes = [key.urtype.size for key in keys]
        offsets = ["+".join(["0"] + [f'{ksize}' for ksize in key_sizes[0:idx]]) for idx, ksize in enumerate(key_sizes)]
        varinfos = [make_var(key, ksize) for key, ksize in zip(keys, key_sizes)]

        for key, ksize in zip(keys, key_sizes):
            if ksize % 8 != 0:
                addError("determining const entry key size", f"Key size for {key.name} is not a multiple of 8 bits")

        for key, ksize, (const_var, hex_content) in zip(keys, key_sizes, varinfos):
            #[ uint8_t ${const_var}[] = {$hex_content};

        for key, ksize, offset, (const_var, hex_content) in zip(keys, key_sizes, offsets, varinfos):
            #[ memcpy(${key_var} + ((${offset} +7)/8), &${const_var}, ${(ksize+7)//8});

        #{ struct ${table.name}_action ${action_var} = {
        #[     .action_id = action_${action_id},
        #{     .${action_id}_params = {
        for param, value_expr in zip(params, args):
            _, hex_content = make_const(value_expr.expression)
            #[ .${param.name} = { ${hex_content} }, // ${value_expr.expression.value}
        #}     },
        #} };

        #[ exact_add_promote(TABLE_${table.name}, ${key_var}, (uint8_t*)&${action_var}, false);

        def make_value(value):
            is_hex = value.base == 16
            split_places = 4 if is_hex else 3

            prefix = '0x' if is_hex else ''
            val = f'{value.value:x}' if is_hex else f'{value.value}'
            val = '_'.join(val[::-1][i:i+split_places] for i in range(0, len(val), split_places))[::-1]
            return f'{prefix}{val}'

        def make_key(key, value):
            return f'" T4LIT({key.header_name},header) "." T4LIT({key.field_name},field) "=" T4LIT({make_value(value)}) "'

        def make_param(param, value_expr):
            return f'" T4LIT({param.name},field) "=" T4LIT({make_value(value_expr.expression)}) "'

        key_str = ", ".join((make_key(key, value) for key, value in zip(table.key.keyElements, entry.keys.components)))
        params_str = ", ".join((make_param(param, value_expr) for param, value_expr in zip(params, args)))
        if params_str != "":
            params_str = f'({params_str})'

        #[ debug("   :: Table $$[table]{table.name}: const entry (${key_str}) -> $$[action]{action_id}${params_str}\n");

        utils.codegen.pre_statement_buffer = ""
#} }

for table in hlir.tables:
    #{ void ${table.name}_setdefault(uint8_t action_id) {
    #[     struct ${table.name}_action action;
    #[     action.action_id = action_id;
    #[     table_setdefault_promote(TABLE_${table.name}, (uint8_t*)&action);
    #} }
