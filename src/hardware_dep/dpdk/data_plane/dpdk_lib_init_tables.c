// SPDX-License-Identifier: Apache-2.0
// Copyright 2018 Eotvos Lorand University, Budapest, Hungary

// This file is included directly from `dpdk_lib.c`.


extern void create_table(lookup_table_t* t, int socketid);
extern void flush_table(lookup_table_t* t);
extern void init_table_const_entries();

void create_tables_on_socket(int socketid)
{
    for (int i = 0; i < NB_TABLES; i++) {
        lookup_table_t t = table_config[i];

        const int replicas = t.has_replicas ? NB_REPLICA : 1;

        for (int j = 0; j < replicas; j++) {
            state[socketid].tables[i][j] = malloc(sizeof(lookup_table_t));
            memcpy(state[socketid].tables[i][j], &t, sizeof(lookup_table_t));
            state[socketid].tables[i][j]->instance = j;
            create_table(state[socketid].tables[i][j], socketid);
            #ifdef T4P4S_DEBUG
                state[socketid].tables[i][j]->init_entry_count = 0;
            #endif
        }

        state[socketid].active_replica[i] = 0;
    }
}

void create_tables_on_lcore(unsigned lcore_id)
{
    if (rte_lcore_is_enabled(lcore_id) == 0) return;

    int socketid = get_socketid(lcore_id);

    if (state[socketid].tables[0][0] == NULL) {
        create_tables_on_socket(socketid);
    }

    // TODO is it necessary to store the table in two places?
    for (int i = 0; i < NB_TABLES; i++) {
        struct lcore_conf* qconf = &lcore_conf[lcore_id];
        qconf->state.tables[i] = state[socketid].tables[i][0];
    }
}

void init_print_table_info()
{
    char table_names[64*NB_TABLES+256];
    char* nameptr = table_names;
    nameptr += sprintf(nameptr, " :::: Init tables on all cores (" T4LIT(%d) " replicas each): ", NB_REPLICA);
    int hidden_count = 0;
    for (int i = 0; i < NB_TABLES; i++) {
        lookup_table_t t = table_config[i];
        if (t.is_hidden) {
            ++hidden_count;
            continue;
        }
        nameptr += sprintf(nameptr, "%s" T4LIT(%s,table), i == 0 ? "" : ", ", t.name);
    }

    if (hidden_count > 0) {
        nameptr += sprintf(nameptr, " and " T4LIT(%d) " hidden tables", hidden_count);
    }

    debug("%s\n", table_names);
}

void init_tables()
{
#ifdef T4P4S_DEBUG
    init_print_table_info();
#endif

    master_socket_id = get_master_socketid();
    for (unsigned lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) {
        create_tables_on_lcore(lcore_id);
    }

    init_table_const_entries();
}

void flush_tables_on_socket(int socketid)
{
    for (int i = 0; i < NB_TABLES; i++) {
        lookup_table_t t = table_config[i];
        const int replicas = t.has_replicas ? NB_REPLICA : 1;

        for (int j = 0; j < replicas; j++) {
            flush_table(state[socketid].tables[i][j]);
        }

        state[socketid].active_replica[i] = 0;
    }
}

void flush_table_on_lcore(unsigned lcore_id)
{
    if (rte_lcore_is_enabled(lcore_id) == 0) return;

    int socketid = get_socketid(lcore_id);
    if (state[socketid].tables[0][0] == NULL) return;
    flush_tables_on_socket(socketid);
}

void flush_tables()
{
    debug("Flushing tables on all cores\n");
    for (unsigned lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) {
        flush_table_on_lcore(lcore_id);
    }
}
