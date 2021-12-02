# SPDX-License-Identifier: Apache-2.0
# Copyright 2016 Eotvos Lorand University, Budapest, Hungary

from utils.codegen import format_type
from compiler_common import unique_everseen

#[ #ifndef __ACTIONS_H__
#[ #define __ACTIONS_H__

#[ #include "dataplane.h"
#[ #include "common.h"

#[ #include "util_packet.h"

# Note: this is for Digest_t
#[ #include "ctrl_plane_backend.h"

# TODO this should not be here in the indep section
#[ #include "dpdk_smem.h"

#[ #define WIDEFIELD(name, length) uint8_t name[(length + 7) / 8];


#{ enum actions {
for table in hlir.tables:
    for action in unique_everseen(table.actions):
        #[     action_${action.action_object.name},
#[      action_,
#} };

for ctl in hlir.controls:
    for act in ctl.actions:
        #{ typedef struct action_${act.name}_params_s {
        for param in act.parameters.parameters:
            paramtype = param.urtype
            if paramtype.size in {8, 16, 32}:
                typeString = 'u' if not paramtype.isSigned else ''
                typeString += 'int%s_t' % paramtype.size
                #[ ${typeString} ${param.name};
            else:
                #[ WIDEFIELD(${param.name}, ${paramtype.size});
        if len(act.parameters.parameters) == 0:
            #[ WIDEFIELD(DUMMY_FIELD, 0);
        #} } action_${act.name}_params_t;

for table in hlir.tables:
    #{ struct ${table.name}_action {
    #[     int action_id;
    #{     union {
    for action in table.actions:
        action_method_name = action.expression.method.path.name
        #[         action_${action.action_object.name}_params_t ${action_method_name}_params;
    #}     };
    #} };



for table in hlir.tables:
    #[ void apply_table_${table.name}(SHORT_STDPARAMS);
    for action in table.actions:
        aname = action.action_object.name
        mname = action.expression.method.path.name

        #[ void action_code_$aname(action_${mname}_params_t*, SHORT_STDPARAMS);

non_ctr_locals = ('counter', 'direct_counter', 'meter')

for ctl in hlir.controls:
    #{ typedef struct control_locals_${ctl.name}_s {
    for local_var_decl in ctl.controlLocals.filter('node_type', ('Declaration_Variable', 'Declaration_Instance')).filterfalse('urtype.name', non_ctr_locals):
        #[ ${format_type(local_var_decl.type, varname = local_var_decl.name, resolve_names = False)};

    # TODO is there a more appropriate way to store registers?
    for reg in hlir.registers:
        #[ ${format_type(reg.type, resolve_names = False)} ${reg.name};

    #} } control_locals_${ctl.name}_t;

#[ #endif
