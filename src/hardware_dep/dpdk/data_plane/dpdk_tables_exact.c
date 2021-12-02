// SPDX-License-Identifier: Apache-2.0
// Copyright 2016 Eotvos Lorand University, Budapest, Hungary

// This file is included directly from `dpdk_tables.c`.


struct rte_hash* hash_create(int socketid, const char* name, uint32_t keylen, rte_hash_function hashfunc, const uint32_t size, const bool has_replicas)
{
    struct rte_hash_parameters hash_params = {
        .name = NULL,
        .entries = size >= 8 ? size : 8,
#if RTE_VER_MAJOR == 2 && RTE_VER_MINOR == 0
        .bucket_entries = 4,
#endif
        .key_len = keylen,
        .hash_func = hashfunc,
        .hash_func_init_val = 0,
   };
    if (!has_replicas) {
        hash_params.extra_flag = RTE_HASH_EXTRA_FLAGS_RW_CONCURRENCY_LF;
    }
    hash_params.name = name;
    hash_params.socket_id = socketid;
    struct rte_hash *h = rte_hash_create(&hash_params);
    if (h == NULL)
        rte_exit_with_errno("create exact table", name);
    return h;
}

void exact_create(lookup_table_t* t, int socketid)
{
    char name[64];
    snprintf(name, sizeof(name), "%d_exact_%d_%d", t->id, socketid, t->instance);
    struct rte_hash* h = hash_create(socketid, name, t->entry.key_size, rte_hash_crc, t->max_size, t->has_replicas);
    create_ext_table(t, h, socketid);
}

void exact_add(lookup_table_t* t, uint8_t* key, uint8_t* value)
{
    if (t->entry.key_size == 0) return; // don't add lines to keyless tables

    extended_table_t* ext = (extended_table_t*)t->table;
    int32_t index = -1;
    if (t->type == LOOKUP_exact_inplace) {
        index = rte_hash_add_key(ext->rte_table, (void*) key);

    } else if (t->type == LOOKUP_exact) {
        index = rte_hash_add_key_data(ext->rte_table, (void *) key, (void *) make_table_entry_on_socket(t, value));
    }

    if (unlikely((int32_t)index < 0) || (int32_t) index > t->max_size) {
        fprintf(stderr, "!!!!!!!!! HASH: add failed. hash=%d\n", index);
        rte_exit(EXIT_FAILURE, "HASH: add failed\n");
    }

    if (t->type == LOOKUP_exact_inplace) {
        make_table_entry(ext->content.inplace + index * t->entry.entry_size, value, t);
    }
    // dbg_bytes(key, t->entry.key_size, "   :: Add " T4LIT(exact) " entry to " T4LIT(%s,table) " (hash " T4LIT(%d) "): " T4LIT(%s,action) " <- ", t->name, index, get_entry_action_name(value));
}

void exact_change(lookup_table_t* t, uint8_t* key, uint8_t* value) {
    if (unlikely(t->entry.key_size == 0)) return; // don't add lines to keyless tables

    uint8_t* data = exact_lookup(t, key);
    change_table_entry(data, value, t);
}

void exact_delete(lookup_table_t* t, uint8_t* key)
{
    if (t->entry.key_size == 0) return; // nothing must have been added

    extended_table_t* ext = (extended_table_t*)t->table;
    // pointer to allocated entry
    if (t->type == LOOKUP_exact) {
        int32_t index = rte_hash_lookup(ext->rte_table, key);
        if (index >= 0) {
            rte_free(ext->content.pointer[index]);
        }
    // all entries remains allocated -> overwrite later
    } else if (t->type == LOOKUP_exact_inplace) {
        rte_hash_del_key(ext->rte_table, key);
    }

}

uint8_t* exact_lookup(lookup_table_t* t, uint8_t* key)
{
    if(unlikely(t->entry.key_size == 0)) return t->default_val;
    extended_table_t* ext = (extended_table_t*)t->table;
    uint8_t* data;
    if (t->type == LOOKUP_exact_inplace) {
        int32_t index = rte_hash_lookup(ext->rte_table, key);
        return (index < 0) ? t->default_val : ext->content.inplace + index * t->entry.entry_size;
    } else if (t->type == LOOKUP_exact) {
        int32_t ret = rte_hash_lookup_data(ext->rte_table, key, (void**) &data);
        return (ret < 0)? t->default_val : data;
    }

    return t->default_val;
}

void exact_flush(lookup_table_t* t)
{
    void *data, *next_key;
    uint32_t iter = 0;

    extended_table_t* ext = (extended_table_t*)t->table;
    rte_hash_reset(ext->rte_table);
    while (rte_hash_iterate(ext->rte_table, (const void**)&next_key, &data, &iter) >= 0) {
        exact_delete(ext->rte_table, next_key);
    }
}
