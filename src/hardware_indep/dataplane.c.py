# SPDX-License-Identifier: Apache-2.0
# Copyright 2016 Eotvos Lorand University, Budapest, Hungary

from utils.codegen import format_declaration, format_statement, format_expr, format_type, gen_format_type, get_method_call_env
from compiler_log_warnings_errors import addError, addWarning
from compiler_common import types

#[ #include <stdlib.h>
#[ #include <string.h>
#[ #include <stdbool.h>
#[ #include "dpdk_lib.h"
#[ #include "actions.h"
#[ #include "backend.h"
#[ #include "util_debug.h"
#[ #include "tables.h"
#[ #include "gen_include.h"

#[ //uint8_t* emit_addr;
#[ //uint32_t ingress_pkt_len;

#[ extern ctrl_plane_backend bg;
#[ extern char* action_names[];

#[ extern void parse_packet(STDPARAMS);
#[ extern void increase_counter(int counterid, int index);
#[ extern void set_handle_packet_metadata(packet_descriptor_t* pd, uint32_t portid);

# note: 0 is for the special case where there are no tables
max_key_length = max([t.key_length_bytes for t in hlir.tables] + [0])
#[ uint8_t reverse_buffer[${max_key_length}];


################################################################################

packet_name = hlir.news.main.type.baseType.type_ref.name
pipeline_elements = hlir.news.main.arguments

#{ struct apply_result_s {
#[     bool hit;
#[     enum actions action_run;
#} };

for ctl in hlir.controls:
    #[ void control_${ctl.name}(STDPARAMS);
    for t in ctl.controlLocals['P4Table']:
        #[ struct apply_result_s ${t.name}_apply(STDPARAMS);

################################################################################
# Table key calculation

for table in hlir.tables:
    #{ void table_${table.name}_key(packet_descriptor_t* pd, uint8_t* key) {
    sortedfields = sorted(table.key.keyElements, key=lambda k: k.match_order)
    #TODO variable length fields
    #TODO field masks
    for f in sortedfields:
        if 'header' in f:
            hi_name = "all_metadatas" if f.header.urtype.is_metadata else f.header.name

            #{ #ifdef T4P4S_DEBUG
            #{     if (unlikely(pd->headers[HDR(${hi_name})].pointer == NULL)) {
            #[         debug(" " T4LIT(!!!!,error) " " T4LIT(Lookup on invalid header,error) " " T4LIT(${hi_name},header) "." T4LIT(${f.field_name},field) "\n");
            #}     }
            #} #endif
            if f.size <= 32:
                #[ EXTRACT_INT32_BITS_PACKET(pd, HDR(${hi_name}), FLD(${f.header.name},${f.field_name}), *(uint32_t*)key)
                #[ key += sizeof(uint32_t);
            elif f.size > 32 and f.size % 8 == 0:
                byte_width = (f.size+7)//8
                #[ EXTRACT_BYTEBUF_PACKET(pd, HDR(${hi_name}), FLD(${f.header.name},${f.field_name}), key)
                #[ key += ${byte_width};
            else:
                addWarning("table key computation", f"Skipping unsupported field {f.id} ({f.size} bits): it is over 32 bits long and not byte aligned")
        else:
            # f is a control local
            if f.size <= 32 or f.size % 8 == 0:
                byte_width = (f.size+7)//8
                fld_name = f.expression.path.name
                #[ memcpy(key, ((control_locals_${table.control.name}_t*) pd->control_locals)->${fld_name}, ${byte_width});
                #[ key += ${byte_width};
            else:
                addWarning("table key computation", f"Skipping unsupported key component {f.expression.path.name} ({f.size} bits): it is over 32 bits long and not byte aligned")


    if table.matchType.name == "lpm":
        #[ key -= ${table.key_length_bytes};
        #[ for(int c = ${table.key_length_bytes-1}, d = 0; c >= 0; c--, d++) *(reverse_buffer+d) = *(key+c);
        #[ for(int c = 0; c < ${table.key_length_bytes}; c++) *(key+c) = *(reverse_buffer+c);
    #} }

################################################################################
# Table application

def unique_stable(items):
    """Returns only the first occurrence of the items in a list.
    Equivalent to unique_everseen from Python 3."""
    from collections import OrderedDict
    return list(OrderedDict.fromkeys(items))


def lockAction(action, table):
    return action.has_write_table_parameter and table.synced


for type in unique_stable([comp['type'] for table in hlir.tables for smem in table.direct_meters + table.direct_counters for comp in smem.components]):
    #[ void apply_direct_smem_$type(register_uint32_t* smem, uint32_t value, char* table_name, char* smem_type_name, char* smem_name) {
    #[    debug("     : applying apply_direct_smem_$type(register_uint32_t (*smem)[1], uint32_t value, char* table_name, char* smem_type_name, char* smem_name)");
    #[ }



for table in hlir.tables:
    table_info = table.name + ("/hidden" if table.is_hidden else "")

    #[ struct apply_result_s ${table.name}_apply(STDPARAMS)
    #{ {
    if 'key' in table:
        #[     uint8_t* key[${table.key_length_bytes}];
        #[     table_${table.name}_key(pd, (uint8_t*)key);

        if table.key_length_bits == 0:
            #[     table_entry_${table.name}_t* entry = (table_entry_${table.name}_t*)tables[TABLE_${table.name}]->default_val;
            #[     bool hit = false;

            #[     debug(" " T4LIT(XXXX,status) " Lookup on keyless table $$[table]{table_info}/" T4LIT(${table.matchType.name}) ": $$[action]{}{%s} (default)\n",
            #[               action_names[entry->action.action_id]
            #[               );
        else:
            #[     dbg_bytes(key, table_config[TABLE_${table.name}].entry.key_size,
            #[               " " T4LIT(????,table) " Table lookup $$[table]{table_info}/" T4LIT(${table.matchType.name}) "/" T4LIT(%dB) ": %s",
            #[               ${table.key_length_bytes},
            #[               ${table.key_length_bytes} == 0 ? "$$[bytes]{}{(empty key)}" : "");

            #[     table_entry_${table.name}_t* entry = (table_entry_${table.name}_t*)${table.matchType.name.split('_')[0]}_lookup(tables[TABLE_${table.name}], (uint8_t*)key);
            #[     bool hit = entry != NULL && entry->is_entry_valid != INVALID_TABLE_ENTRY;
            #{     if (unlikely(!hit)) {
            #[         entry = (table_entry_${table.name}_t*)tables[TABLE_${table.name}]->default_val;
            #}     }

            #[     debug("   %s Lookup %s: $$[action]{}{%s}%s\n",
            #[               hit ? T4LIT(++,success) : T4LIT(XX,status),
            #[               hit ? T4LIT(hit,success) : T4LIT(miss,status),
            #[               entry == NULL ? "(no default action)" : action_names[entry->action.action_id],
            #[               hit ? "" : " (default)"
            #[               );

            if len(table.direct_meters + table.direct_counters) > 0:
                #{     if (likely(hit)) {
                #[         // applying direct counters and meters
                for smem in table.direct_meters + table.direct_counters:
                    for comp in smem.components:
                        value = "pd->parsed_length" if comp['for'] == 'bytes' else "1"
                        type = comp['type']
                        name  = comp['name']
                        #[ extern void apply_${smem.smem_type}(${smem.smem_type}_t*, int, const char*, const char*, const char*);
                        #[ apply_${smem.smem_type}(&(global_smem.${name}_${table.name}), $value, "${table.name}", "${smem.smem_type}", "$name");
                #}    }
    else:
        action = table.default_action.expression.method.ref.name if 'default_action' in table else None

        if action:
            #[    table_entry_${table.name}_t* entry = (table_entry_${table.name}_t*)tables[TABLE_${table.name}][rte_lcore_id()].default_val;
            #[    debug(" :::: Lookup on keyless table " T4LIT(${table_info},table) ", default action is " T4LIT(%s,action) "\n", action_names[entry->action.action_id]);
            #[    bool hit = true;
            #[    bool is_default = false;
        else:
            #[    debug(" :::: Lookup on keyless table " T4LIT(${table_info},table) ", " T4LIT(no default action,action) "\n");
            #[    table_entry_${table.name}_t* entry = (struct ${table.name}_action*)0;
            #[    bool hit = false;
            #[    bool is_default = false;


    # ACTIONS
    #[     if (likely(entry != 0)) {
    #{       switch (entry->action.action_id) {
    for action in table.actions:
        action_name = action.action_object.name
        #{         case action_${action_name}:
        if lockAction(action.action_object, table):
            #[           LOCK(&entry->lock);
        #[           action_code_${action_name}(&(entry->action.${action_name}_params), SHORT_STDPARAMS_IN);
        if lockAction(action.action_object, table):
            #[           UNLOCK(&entry->lock);
        #}           break;
    #[       }
    #}     }

    #[     struct apply_result_s apply_result = { hit, hit ? entry->action.action_id : -1 };
    #[     return apply_result;
    #} }


################################################################################

#{ void reset_headers(SHORT_STDPARAMS) {
for hdr in hlir.header_instances.filter('urtype.is_metadata', False):
    #[ pd->headers[HDR(${hdr.name})].pointer = NULL;

#[     // reset metadatas
#[     memset(pd->headers[HDR(all_metadatas)].pointer, 0, hdr_infos[HDR(all_metadatas)].byte_width * sizeof(uint8_t));
#} }

#{ void init_headers(SHORT_STDPARAMS) {
for hdr in hlir.header_instances.filter('urtype.is_metadata', False):
    #[ pd->headers[HDR(${hdr.name})] = (header_descriptor_t)
    #{ {
    #[     .type = HDR(${hdr.name}),
    #[     .length = hdr_infos[HDR(${hdr.name})].byte_width,
    #[     .pointer = NULL,
    #[     .var_width_field_bitwidth = 0,
    #[ #ifdef T4P4S_DEBUG
    #[     .name = "${hdr.name}",
    #[ #endif
    #} };

#[     // init metadatas
#[     pd->headers[HDR(all_metadatas)] = (header_descriptor_t)
#{     {
#[         .type = HDR(all_metadatas),
#[         .length = hdr_infos[HDR(all_metadatas)].byte_width,
#[         .pointer = rte_malloc("all_metadatas_t", hdr_infos[HDR(all_metadatas)].byte_width * sizeof(uint8_t), 0),
#[         .var_width_field_bitwidth = 0
#}     };
#} }

################################################################################

def is_keyless_single_action_table(table):
    return table.key_length_bytes == 0 and len(table.actions) == 2 and table.actions[1].action_object.name.startswith('NoAction')

################################################################################

#{ void init_dataplane(SHORT_STDPARAMS) {
#[     init_headers(SHORT_STDPARAMS_IN);
#[     reset_headers(SHORT_STDPARAMS_IN);

#[     uint32_t res32;
#[     MODIFY_INT32_INT32_BITS_PACKET(pd, HDR(all_metadatas), EGRESS_META_FLD, EGRESS_INIT_VALUE);
#} }

#{ void update_packet(packet_descriptor_t* pd) {
#[     uint32_t value32, res32;
#[     (void)value32, (void)res32;
for hdr in hlir.header_instances:
    #[
    #[ // updating header instance ${hdr.name}
    for fld in hdr.urtype.fields:
        if fld.preparsed or fld.urtype.size > 32:
            continue
        #{ if(pd->fields.FLD_ATTR(${hdr.name},${fld.name}) == MODIFIED) {
        #[     value32 = pd->fields.FLD(${hdr.name},${fld.name});
        #[     MODIFY_INT32_INT32_AUTO_PACKET(pd, HDR(all_metadatas), FLD(${hdr.name},${fld.name}), value32);
        #[     // set_field((fldT[]){{pd, HDR(${hdr.name}), FLD(${hdr.name},${fld.name})}}, 0, value32, ${fld.urtype.size});
        #} }
#} }

################################################################################
# Pipeline


for ctl in hlir.controls:
    #[ void control_${ctl.name}(STDPARAMS)
    #{ {
    #[     debug("Entering control $$[control]{ctl.name}...\n");
    #[     uint32_t value32, res32;
    #[     (void)value32, (void)res32;
    #[     control_locals_${ctl.name}_t local_vars_struct;
    #[     control_locals_${ctl.name}_t* local_vars = &local_vars_struct;
    #[     pd->control_locals = (void*) local_vars;
    #= format_statement(ctl.body, ctl)
    #} }

#[ void process_packet(STDPARAMS)
#{ {
it=0
for ctl in hlir.controls:
    #[ control_${ctl.name}(STDPARAMS_IN);
    if hlir.news.model == 'V1Switch' and it==1:
        #[ transfer_to_egress(pd);
    it = it+1
    if ctl.name == 'egress':
        #[ // TODO temporarily disabled
        #[ // update_packet(pd); // we need to update the packet prior to calculating the new checksum
#} }

################################################################################

longest_hdr_name_len = max({len(h.name) for h in hlir.header_instances if not h.urtype.is_metadata})

pkt_name_indent = " " * longest_hdr_name_len

#[ void store_headers_for_emit(STDPARAMS)
#{ {
#[     debug("   :: Preparing $${}{%d} header instances for storage...\n", pd->emit_hdrinst_count);

#[     pd->emit_headers_length = 0;
#{     for (int i = 0; i < pd->emit_hdrinst_count; ++i) {
#[         header_descriptor_t hdr = pd->headers[pd->header_reorder[i]];

#[
#{         #if T4P4S_EMIT != 1
#{             if (unlikely(hdr.pointer == NULL)) {
#[                 debug("        : " T4LIT(#%d) " $$[header][%]{longest_hdr_name_len}{s}/$${}{%02dB} = " T4LIT(skipping invalid header,warning) "\n", pd->header_reorder[i] + 1, hdr.name, hdr.length);
#[                 continue;
#}             }
#}         #endif

#{         if (likely(hdr.was_enabled_at_initial_parse)) {
#[             dbg_bytes(hdr.pointer, hdr.length, "        : " T4LIT(#%d) " $$[header][%]{longest_hdr_name_len}{s}/$${}{%02dB} = %s", pd->header_reorder[i] + 1, hdr.name, hdr.length, hdr.pointer == NULL ? T4LIT((invalid),warning) " " : "");
#[             memcpy(pd->header_tmp_storage + hdr_infos[hdr.type].byte_offset, hdr.pointer, hdr.length);
#[         } else {
#[             debug("        : " T4LIT(#%d) " $$[header][%]{longest_hdr_name_len}{s}/$${}{%02dB} was created in-place (not present at ingress)\n", pd->header_reorder[i] + 1, hdr.name, hdr.length);
#}         }
#[
#[         pd->emit_headers_length += hdr.length;
#}     }
#} }

#[ void resize_packet_on_emit(STDPARAMS)
#{ {
#{     if (likely(pd->emit_headers_length == pd->parsed_length)) {
#[         debug(" " T4LIT(::::,status) " Skipping packet resizing: no change in total packet header length\n");
#[         return;
#}     }
#[
#{     if (likely(pd->emit_headers_length > pd->parsed_length)) {
#[         int len_change = pd->emit_headers_length - pd->parsed_length;
#[         debug("   " T4LIT(::,status) " Adding   $${}{%02d} bytes %${longest_hdr_name_len}{s}, header length: $${}{%dB} to $${}{%dB}\n", len_change, "to packet", pd->parsed_length, pd->emit_headers_length);
#[         char* new_ptr = rte_pktmbuf_prepend(pd->wrapper, len_change);
#[         if (unlikely(new_ptr == 0)) {
#[             rte_exit(1, "Could not reserve necessary headroom ($${}{%d} additional bytes)", len_change);
#[         }
#[         pd->data = (packet_data_t*)new_ptr;
#[     } else {
#[         int len_change = pd->parsed_length - pd->emit_headers_length;
#[         debug("   " T4LIT(::,status) " Removing $${}{%02d} bytes %${longest_hdr_name_len}{s}, header length: $${}{%dB} to $${}{%dB}\n", len_change, "from packet", pd->parsed_length, pd->emit_headers_length);
#[         char* new_ptr = rte_pktmbuf_adj(pd->wrapper, len_change);
#[         pd->data = (packet_data_t*)new_ptr;
#}     }
#[     pd->wrapper->pkt_len = pd->emit_headers_length + pd->payload_length;
#} }

#[ // if (some of) the emitted headers are one after another, this function copies them in one go
#[ void copy_emit_contents(STDPARAMS)
#{ {
#[     debug("   :: Putting together packet\n");
#[     uint8_t* dst_start = rte_pktmbuf_mtod(pd->wrapper, uint8_t*);
#[     uint8_t* dst = dst_start;
#{     for (int idx = 0; idx < pd->emit_hdrinst_count; ) {
#[         #ifdef T4P4S_DEBUG
#[             char header_names_txt[1024];
#[             char* header_names_ptr = header_names_txt;
#[         #endif
#[         header_descriptor_t hdr = pd->headers[pd->header_reorder[idx]];
#[         uint8_t* copy_start     = hdr.pointer;
#[         int copy_start_idx      = idx;
#[         int copy_length         = hdr.length;
#[         int count               = 1;
#[         #ifdef T4P4S_DEBUG
#[             header_names_ptr += sprintf(header_names_ptr, T4LIT(%s,header) "/" T4LIT(%dB), hdr.name, copy_length);
#[         #endif
#[         ++idx;
#{         while (idx < pd->emit_hdrinst_count && pd->headers[pd->header_reorder[idx]].pointer == hdr.pointer + hdr.length) {
#[             ++count;
#[             hdr = pd->headers[pd->header_reorder[idx]];
#[             copy_length += hdr.length;
#[             ++idx;
#[             #ifdef T4P4S_DEBUG
#[                 header_names_ptr += sprintf(header_names_ptr, " " T4LIT(%s,header), hdr.name);
#[             #endif
#}         }
#[         dbg_bytes(copy_start, copy_length, "    : Copying " T4LIT(%d) " %s to byte " T4LIT(#%2ld) " of egress header %s ", count, count == 1 ? "header" : "adjacent headers", dst - dst_start, header_names_txt);
#[         memcpy(dst, copy_start, copy_length);
#[         dst += copy_length;
#}     }
#} }

#{ bool is_packet_dropped(STDPARAMS) {
#[      return GET_INT32_AUTO_PACKET(pd, HDR(all_metadatas), EGRESS_META_FLD) == EGRESS_DROP_VALUE;
#} }


#[ void emit_packet(STDPARAMS)
#{ {
#{     if (unlikely(pd->is_emit_reordering)) {
#{         if (unlikely(is_packet_dropped(STDPARAMS_IN))) {
#[             debug(" " T4LIT(::::,status) " Skipping pre-emit processing: packet is " T4LIT(dropped,status) "\n");
#[             return;
#}         }
#[         debug(" :::: Pre-emit reordering\n");
#[         store_headers_for_emit(STDPARAMS_IN);
#[         resize_packet_on_emit(STDPARAMS_IN);
#[         copy_emit_contents(STDPARAMS_IN);
#[     } else {
#[         debug(" " T4LIT(::::,status) " Skipping pre-emit processing: no change in packet header structure\n");
#}     }
#} }

#[ void handle_packet(uint32_t portid, STDPARAMS)
#{ {
#[     int value32;
#[     int res32;
#[
#[     reset_headers(SHORT_STDPARAMS_IN);
#[     set_handle_packet_metadata(pd, portid);
#[
#[     dbg_bytes(pd->data, packet_length(pd), "Handling packet (port " T4LIT(%d,port) ", $${}{%02d} bytes)  : ", extract_ingress_port(pd), packet_length(pd));
#[
#[     pd->parsed_length = 0;
#[     parse_packet(STDPARAMS_IN);
#[
#[     //emit_addr = pd->data;
#[     pd->emit_hdrinst_count = 0;
#[     pd->is_emit_reordering = false;
#[
#[     process_packet(STDPARAMS_IN);
#[
#[     emit_packet(STDPARAMS_IN);
#} }
