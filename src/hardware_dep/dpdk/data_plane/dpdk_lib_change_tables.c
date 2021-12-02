// SPDX-License-Identifier: Apache-2.0
// Copyright 2018 Eotvos Lorand University, Budapest, Hungary

// This file is included directly from `dpdk_lib.c`.

void change_replica(int socketid, int tid, int replica) {
    for (unsigned lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) {
        if (rte_lcore_is_enabled(lcore_id) == 0) continue;

        int core_socketid = rte_lcore_to_socket_id(lcore_id);
        if (core_socketid != socketid) continue;

        struct lcore_conf* qconf = &lcore_conf[lcore_id];
        qconf->state.tables[tid] = state[socketid].tables[tid][replica]; // TODO should this be atomic?
        state[socketid].active_replica[tid] = replica;

        // debug("    : " T4LIT(%d,core) "@" T4LIT(%d,socket) " uses table replica " T4LIT(%s,table) "#" T4LIT(%d) "\n", lcore_id, socketid, state[socketid].tables[tid][replica]->name, replica);
    }
}

#define HAS_REPLICAS(socketid, tableid) state[socketid].tables[tableid][0]->has_replicas

#define CHANGE_TABLE(fun, par...) \
{ \
    {                             \
        if (HAS_REPLICAS(socketid, tableid)) { \
            int current_replica = state[socketid].active_replica[tableid]; \
            int next_replica = (current_replica+1)%NB_REPLICA; \
            fun(state[socketid].tables[tableid][next_replica], par); \
            change_replica(socketid, tableid, next_replica); \
            usleep(TABCHANGE_SLEEP_MICROS); \
            for (int current_replica = 0; current_replica < NB_REPLICA; current_replica++) { \
                if (current_replica != next_replica) { \
                    fun(state[socketid].tables[tableid][current_replica], par); \
                }                 \
            }                  \
        } else { \
            fun(state[socketid].tables[tableid][0], par); \
        }    \
    }   \
}

extern char* get_entry_action_name(void* entry);

#ifdef T4P4S_DEBUG
#define FORALL_PRINTOUT(txt1, txt2, b, should_print) \
    ++state[socketid].tables[tableid][0]->init_entry_count; \
    if (should_print) { \
        dbg_bytes(key, state[socketid].tables[tableid][0]->entry.key_size, " " T4LIT(ctl>,incoming) " #" T4LIT(txt1,action) " " T4LIT(%s,table) txt2 ": " T4LIT(%s,action) " <- ", table_config[tableid].name, get_entry_action_name(value)); \
    }
#else
#define FORALL_PRINTOUT(txt1, txt2, b, should_print)
#endif

#define CHANGE_TABLE_NOREPLICA(fun, par...) \
{ \
    {   \
        if (HAS_REPLICAS(stateid, tableid)) { \
            int current_replica = state[socketid].active_replica[tableid]; \
            fun(state[socketid].tables[tableid][current_replica], par);    \
        } else {                            \
            fun(state[socketid].tables[tableid][0], par);         \
        }                                    \
    } \
}

#define FORALLNUMANODES(txt1, txt2, b, should_print) \
    for (int socketid = 0; socketid < NB_SOCKETS; socketid++) \
        if (state[socketid].tables[0][0] != NULL) { \
            FORALL_PRINTOUT(txt1, txt2, b, should_print) \
            b \
        }

// TODO show the debug message if the macro T4P4S_SHOW_HIDDEN_TABLES is defined
#define FORALLNUMANODES_NOKEY(txt1, txt2, b) \
    for (int socketid = 0; socketid < NB_SOCKETS; socketid++) \
        if (state[socketid].tables[0][0] != NULL) { \
            if (socketid == 0 && !table_config[tableid].is_hidden) { \
                debug("    : " T4LIT(txt1,action) " " T4LIT(%s,table) txt2 ": " T4LIT(%s,action) "\n", table_config[tableid].name, get_entry_action_name(value)); \
            } \
            b \
        }

void exact_add_promote(int tableid, uint8_t* key, uint8_t* value, bool should_print) {
    FORALLNUMANODES(Add, "/" T4LIT(exact), CHANGE_TABLE(exact_add, key, value), should_print)
}
void exact_change_promote(int tableid, uint8_t* key, uint8_t* value, bool should_print) {
    FORALLNUMANODES(Add, "/" T4LIT(exact), CHANGE_TABLE(exact_change, key, value), should_print)
}
void lpm_add_promote(int tableid, uint8_t* key, uint8_t depth, uint8_t* value, bool should_print) {
    FORALLNUMANODES(Add, "/" T4LIT(LPM), CHANGE_TABLE(lpm_add, key, depth, value), should_print)
}
void ternary_add_promote(int tableid, uint8_t* key, uint8_t* mask, uint8_t* value, bool should_print) {
    FORALLNUMANODES(Add, "/" T4LIT(ternary), CHANGE_TABLE(ternary_add, key, mask, value), should_print)
}
void table_setdefault_promote(int tableid, uint8_t* value) {
    FORALLNUMANODES_NOKEY(Set default action on table, "", CHANGE_TABLE(table_set_default_action, value))
}

#define CHANGE_TABLE_NOREPLICA_SEQ(fun, par...) \
{ \
    {                                           \
        int current_replica = HAS_REPLICAS(socketid, tableid) ? state[socketid].active_replica[tableid] : 0;  \
        for (uint64_t idx = 0; idx < nr_entries; idx++) { \
            fun(state[socketid].tables[tableid][current_replica], par); \
        } \
    } \
}

#define CHANGE_TABLE_SEQ(fun, par...) \
{ \
    { \
        if (HAS_REPLICAS(socketid, tableid))  { \
            int current_replica = state[socketid].active_replica[tableid]; \
            int next_replica = (current_replica+1)%NB_REPLICA; \
            for (uint64_t idx = 0; idx < nr_entries; idx++) { \
                fun(state[socketid].tables[tableid][next_replica], par); \
            } \
            change_replica(socketid, tableid, next_replica); \
            usleep(TABCHANGE_SLEEP_MICROS); \
            for (int current_replica = 0; current_replica < NB_REPLICA; current_replica++) { \
                if (current_replica != next_replica) { \
                    for (uint64_t idx = 0; idx < nr_entries; idx++) { \
                        fun(state[socketid].tables[tableid][current_replica], par); \
                    } \
                } \
            } \
        } else {  \
            for (uint64_t idx = 0; idx < nr_entries; idx++) { \
                fun(state[socketid].tables[tableid][0], par); \
            } \
        } \
    } \
}

//void exact_add_promote_multiple(int tableid, uint8_t** keys, uint8_t* value, uint64_t nr_entries)
//{
//    FORALLNUMANODES(add, to exact table, CHANGE_TABLE_SEQ(exact_add, keys[idx], value))
//}
//
//void ternary_add_promote_multiple(int tableid, uint8_t** keys, uint8_t** masks, uint8_t* value, uint64_t nr_entries)
//{
//    FORALLNUMANODES(add, to ternary table, CHANGE_TABLE_SEQ(ternary_add, keys[idx], masks[idx], value))
//}
//
//void lpm_add_promote_multiple(int tableid, uint8_t** keys, uint8_t* depths, uint8_t* value, uint64_t nr_entries)
//{
//    FORALLNUMANODES(add, to lpm table, CHANGE_TABLE_SEQ(lpm_add, keys[idx], depths[idx], value))
//}
