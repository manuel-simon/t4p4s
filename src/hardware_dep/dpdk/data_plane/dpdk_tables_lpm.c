// SPDX-License-Identifier: Apache-2.0
// Copyright 2016 Eotvos Lorand University, Budapest, Hungary

// This file is included directly from `dpdk_tables.c`.


#include <rte_errno.h>

struct rte_lpm* lpm4_create(int socketid, const char* name, int max_size)
{
#if RTE_VERSION >= RTE_VERSION_NUM(16,04,0,0)
    struct rte_lpm_config config = {
        .max_rules = max_size,
        .number_tbl8s = (1 << 8), // TODO refine this
        .flags = 0,
    };
    struct rte_lpm *l = rte_lpm_create(name, socketid, &config);
#else
    struct rte_lpm *l = rte_lpm_create(name, socketid, max_size, 0/*flags*/);
#endif
    if (l == NULL)
        rte_exit_with_errno("create lpm4 table", name);
    return l;
}

struct rte_lpm6* lpm6_create(int socketid, const char* name, int max_size)
{
    struct rte_lpm6_config config = {
        .max_rules = max_size,
        .number_tbl8s = (1 << 16),
        .flags = 0,
    };
    struct rte_lpm6 *l = rte_lpm6_create(name, socketid, &config);
    if (l == NULL)
        rte_exit_with_errno("create lpm6 table", name);
    return l;
}


void lpm4_add(lookup_table_t* t, struct rte_lpm* l, uint32_t key, uint8_t depth, table_index_t value)
{
    int ret = rte_lpm_add(l, key, depth, value);
    if (ret < 0)
        rte_exit_with_errno("add entry to lpm4 table", t->name);
}

void lpm6_add(lookup_table_t* t, struct rte_lpm6* l, uint8_t key[16], uint8_t depth, table_index_t value)
{
    int ret = rte_lpm6_add(l, key, depth, value);
    if (ret < 0)
        rte_exit_with_errno("add entry to lpm4 table", t->name);
}


void lpm_create(lookup_table_t* t, int socketid)
{
    char name[64];
    snprintf(name, sizeof(name), "%d_lpm_%d_%d", t->id, socketid, t->instance);
    if(t->entry.key_size <= 4)
        create_ext_table(t, lpm4_create(socketid, name, t->max_size), socketid);
    else if(t->entry.key_size <= 16)
        create_ext_table(t, lpm6_create(socketid, name, t->max_size), socketid);
    else
        rte_exit(EXIT_FAILURE, "LPM: key_size not supported\n");

}


void lpm_add(lookup_table_t* t, uint8_t* key, uint8_t depth, uint8_t* value)
{
    if (t->entry.key_size == 0) return; // don't add lines to keyless tables

    extended_table_t* ext = (extended_table_t*)t->table;
    ext->content.pointer[ext->size] = make_table_entry_on_socket(t, value);
    if (t->entry.key_size <= 4)
    {
        // the rest is zeroed in case of keys smaller than 4 bytes
        uint32_t key32 = 0;
        memcpy(&key32, key, t->entry.key_size);

        lpm4_add(t, ext->rte_table, key32, depth, ext->size++);
    }
    else if (t->entry.key_size <= 16)
    {
        static uint8_t key128[16];
        memset(key128, 0, 16);
        memcpy(key128, key, t->entry.key_size);

        lpm6_add(t, ext->rte_table, key128, depth, ext->size++);
    }
}


uint8_t* lpm_lookup(lookup_table_t* t, uint8_t* key)
{
    if (t->entry.key_size == 0) return t->default_val;
    extended_table_t* ext = (extended_table_t*)t->table;

    if(t->entry.key_size <= 4)
    {
        uint32_t key32 = 0;
        memcpy(&key32, key, t->entry.key_size);

        table_index_t result;
#if RTE_VERSION >= RTE_VERSION_NUM(16,04,0,0)
        uint32_t result32;
        int ret = rte_lpm_lookup(ext->rte_table, key32, &result32);
        result = (table_index_t)result32;
#else
        int ret = rte_lpm_lookup(ext->rte_table, key32, &result);
#endif
        return ret == 0 ? ext->content.pointer[result] : t->default_val;
    }
    else if(t->entry.key_size <= 16)
    {
        static uint8_t key128[16];
        memset(key128, 0, 16);
        memcpy(key128, key, t->entry.key_size);

        table_index_t result;
        int ret = rte_lpm6_lookup(ext->rte_table, key128, &result);
        return ret == 0 ? ext->content.pointer[result] : t->default_val;
    }
    return NULL;
}


void lpm_flush(lookup_table_t* t)
{
    extended_table_t* ext = (extended_table_t*)t->table;
    rte_free(ext->content.pointer[ext->size]);
    if (t->entry.key_size <= 4)
    {
        rte_lpm_delete_all(ext->rte_table);
    }
    else if (t->entry.key_size <= 16)
    {
        rte_lpm6_delete_all(ext->rte_table);
    }
}
