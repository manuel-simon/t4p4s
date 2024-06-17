#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <rte_common.h>
#include <rte_bpf_ethdev.h>
#include "dpdk_lib.h"
#include "ebpf.h"
#include "mac.h"

#include "util_debug.h"

#ifndef EBPF_SEC
#define EBPF_SEC ".text"
#endif

#include "dpdk_ebpf_defs.h" 

enum POSITION {
	PRE,
	POST
};

typedef enum POSITION pos_t;

extern uint16_t nb_lcore_params;
extern struct lcore_params lcore_params[MAX_LCORE_PARAMS];
extern struct lcore_conf lcore_conf[RTE_MAX_LCORE];

extern char key[BLAKE3_KEY_LEN];

// COMMON //

int load_ebpf_prog_all(char *filename, char *section, bool jit, pos_t pre);
int load_ebpf_prog_lcore(uint16_t lcore_id, char *filename, char *section, bool jit, pos_t pos);

// PRE //

// BIN PACKET
void pre_ebpf_load_prog_from_packet(int8_t *ret, uint8_buffer_t data, bool jit);
void pre_ebpf_load_prog_from_packet_auth(int8_t *ret, uint8_buffer_t data, bool jit);
void pre_ebpf_load_prog_from_packet_all(int8_t *ret, uint8_buffer_t data, bool jit);
void pre_ebpf_load_prog_from_packet_all_auth(int8_t *ret, uint8_buffer_t data, bool jit);
// SRC PACKET
void pre_ebpf_load_src_from_packet(int8_t *ret, uint8_buffer_t data, bool jit);
void pre_ebpf_load_src_from_packet_auth(int8_t *ret, uint8_buffer_t data, bool jit);
void pre_ebpf_load_src_from_packet_all(int8_t *ret, uint8_buffer_t data, bool jit);
void pre_ebpf_load_src_from_packet_all_auth(int8_t *ret, uint8_buffer_t data, bool jit);
// MEMORY
void pre_ebpf_load_prog_from_memory(int8_t *ret, char *filename, bool jit);
void pre_ebpf_load_prog_from_memory_auth(int8_t *ret, char *filename, uint8_buffer_t mac, bool jit);
void pre_ebpf_load_prog_from_memory_all(int8_t *ret, char *filename, bool jit);
void pre_ebpf_load_prog_from_memory_all_auth(int8_t *ret, char *filename, uint8_buffer_t mac, bool jit);
// UNLOAD
void pre_ebpf_unload_prog();
void pre_ebpf_unload_prog_all();


// POST //

// BIN PACKET
void post_ebpf_load_prog_from_packet(int8_t *ret, uint8_buffer_t data, bool jit);
void post_ebpf_load_prog_from_packet_auth(int8_t *ret, uint8_buffer_t data, bool jit);
void post_ebpf_load_prog_from_packet_all(int8_t *ret, uint8_buffer_t data, bool jit);
void post_ebpf_load_prog_from_packet_all_auth(int8_t *ret, uint8_buffer_t data, bool jit);
// SRC PACKET
void post_ebpf_load_src_from_packet(int8_t *ret, uint8_buffer_t data, bool jit);
void post_ebpf_load_src_from_packet_auth(int8_t *ret, uint8_buffer_t data, bool jit);
void post_ebpf_load_src_from_packet_all(int8_t *ret, uint8_buffer_t data, bool jit);
void post_ebpf_load_src_from_packet_all_auth(int8_t *ret, uint8_buffer_t data, bool jit);
// MEMORY
void post_ebpf_load_prog_from_memory(int8_t *ret, char *filename, bool jit);
void post_ebpf_load_prog_from_memory_auth(int8_t *ret, char *filename, uint8_buffer_t mac, bool jit);
void post_ebpf_load_prog_from_memory_all(int8_t *ret, char *filename, bool jit);
void post_ebpf_load_prog_from_memory_all_auth(int8_t *ret, char *filename, uint8_buffer_t mac, bool jit);
// UNLOAD
void post_ebpf_unload_prog();
void post_ebpf_unload_prog_all();

// PRE //
// BIN PACKET
void pre_ebpf_load_prog_from_packet(int8_t *ret, uint8_buffer_t data, bool jit)
{
	VARS;
	WRITE_TMP(src, len, BIN_TMP);
	if (ret >= 0) {
		*ret = load_ebpf_prog_lcore(rte_lcore_id(), BIN_TMP, EBPF_SEC, jit, PRE);
	}
}

void pre_ebpf_load_prog_from_packet_auth(int8_t *ret, uint8_buffer_t data, bool jit)
{
	AUTH_VARS;
	VAL_MAC(src, len, key, mac);
	WRITE_TMP(src, len, BIN_TMP);
	if (ret >= 0) {
		*ret = load_ebpf_prog_lcore(rte_lcore_id(), BIN_TMP, EBPF_SEC, jit, PRE);
	}
}

void pre_ebpf_load_prog_from_packet_all(int8_t *ret, uint8_buffer_t data, bool jit)
{
	VARS;
	WRITE_TMP(src, len, BIN_TMP);
	if (ret >= 0) {
		*ret = load_ebpf_prog_all(BIN_TMP, EBPF_SEC, jit, PRE);
	}
}

void pre_ebpf_load_prog_from_packet_all_auth(int8_t *ret, uint8_buffer_t data, bool jit)
{
	AUTH_VARS;
	VAL_MAC(src, len, key, mac);
	WRITE_TMP(src, len, BIN_TMP);
	if (ret >= 0) {
		*ret = load_ebpf_prog_all(BIN_TMP, EBPF_SEC, jit, PRE);
	}
}

// SRC PACKET
void pre_ebpf_load_src_from_packet(int8_t *ret, uint8_buffer_t data, bool jit)
{
	VARS;
	WRITE_TMP(src, len, SRC_TMP);
	COMPILE;
	if (ret >= 0) {
		*ret = load_ebpf_prog_lcore(rte_lcore_id(), BIN_TMP, EBPF_SEC, jit, PRE);
	}
}

void pre_ebpf_load_src_from_packet_auth(int8_t *ret, uint8_buffer_t data, bool jit)
{
	AUTH_VARS;
	VAL_MAC(src, len, key, mac);
	WRITE_TMP(src, len, SRC_TMP);
	COMPILE;
	if (ret >= 0) {
		*ret = load_ebpf_prog_lcore(rte_lcore_id(), BIN_TMP, EBPF_SEC, jit, PRE);
	}
}

// UNLOAD
void pre_ebpf_load_src_from_packet_all(int8_t *ret, uint8_buffer_t data, bool jit)
{
	VARS;
	WRITE_TMP(src, len, SRC_TMP);
	
	COMPILE;
	if (ret >= 0) {
		*ret = load_ebpf_prog_all(BIN_TMP, EBPF_SEC, jit, PRE);
	}
}

void pre_ebpf_load_src_from_packet_all_auth(int8_t *ret, uint8_buffer_t data, bool jit)
{
	AUTH_VARS;
	VAL_MAC(src, len, key, mac);
	WRITE_TMP(src, len, SRC_TMP);
	COMPILE;
	if (ret >= 0) {
		*ret = load_ebpf_prog_all(BIN_TMP, EBPF_SEC, jit, PRE);
	}
}

// MEMORY
void pre_ebpf_load_prog_from_memory(int8_t *ret, char *filename, bool jit)
{
	*ret = load_ebpf_prog_lcore(rte_lcore_id(), filename, EBPF_SEC, jit, PRE);
}

void pre_ebpf_load_prog_from_memory_auth(int8_t *ret, char *filename, uint8_buffer_t mac, bool jit)
{
	VAL_MAC(filename, STRLEN(filename), key, mac.buffer);
	*ret = load_ebpf_prog_lcore(rte_lcore_id(), filename, EBPF_SEC, jit, PRE);
}

void pre_ebpf_load_prog_from_memory_all(int8_t *ret, char *filename, bool jit)
{
	*ret = load_ebpf_prog_all(filename, EBPF_SEC, jit, PRE);
}

void pre_ebpf_load_prog_from_memory_all_auth(int8_t *ret, char *filename, uint8_buffer_t mac, bool jit)
{
	VAL_MAC(filename, STRLEN(filename), key, mac.buffer);
	*ret = load_ebpf_prog_all(filename, EBPF_SEC, jit, PRE);
}

void pre_ebpf_unload_prog()
{
	uint16_t lcore_id = rte_lcore_id();

	for (uint16_t i = 0; i < lcore_conf[lcore_id].hw.n_rx_queue; i++) {
		uint8_t port_id = lcore_conf[lcore_id].hw.rx_queue_list[i].port_id;
		uint8_t queue_id = lcore_conf[lcore_id].hw.rx_queue_list[i].queue_id;
		rte_bpf_eth_rx_unload(port_id, queue_id);
	}
}

void pre_ebpf_unload_prog_all()
{
	for (uint16_t i = 0; i < nb_lcore_params; i++) {
		rte_bpf_eth_rx_unload(lcore_params[i].port_id, lcore_params[i].queue_id);
	}
}


// POST //
// BIN PACKET
void post_ebpf_load_prog_from_packet(int8_t *ret, uint8_buffer_t data, bool jit)
{
	VARS;
	WRITE_TMP(src, len, BIN_TMP);
	if (ret >= 0) {
		*ret = load_ebpf_prog_lcore(rte_lcore_id(), BIN_TMP, EBPF_SEC, jit, POST);
	}
}

void post_ebpf_load_prog_from_packet_auth(int8_t *ret, uint8_buffer_t data, bool jit)
{
	AUTH_VARS;
	VAL_MAC(src, len, key, mac);
	WRITE_TMP(src, len, BIN_TMP);
	if (ret >= 0) {
		*ret = load_ebpf_prog_lcore(rte_lcore_id(), BIN_TMP, EBPF_SEC, jit, POST);
	}
}

void post_ebpf_load_prog_from_packet_all(int8_t *ret, uint8_buffer_t data, bool jit)
{
	VARS;
	WRITE_TMP(src, len, BIN_TMP);
	if (ret >= 0) {
		*ret = load_ebpf_prog_all(BIN_TMP, EBPF_SEC, jit, POST);
	}
}

void post_ebpf_load_prog_from_packet_all_auth(int8_t *ret, uint8_buffer_t data, bool jit)
{
	AUTH_VARS;
	VAL_MAC(src, len, key, mac);
	WRITE_TMP(src, len, BIN_TMP);
	if (ret >= 0) {
		*ret = load_ebpf_prog_all(BIN_TMP, EBPF_SEC, jit, POST);
	}
}

// SRC PACKET
void post_ebpf_load_src_from_packet(int8_t *ret, uint8_buffer_t data, bool jit)
{
	VARS;
	WRITE_TMP(src, len, SRC_TMP);
	COMPILE;
	if (ret >= 0) {
		*ret = load_ebpf_prog_lcore(rte_lcore_id(), BIN_TMP, EBPF_SEC, jit, POST);
	}
}

void post_ebpf_load_src_from_packet_auth(int8_t *ret, uint8_buffer_t data, bool jit)
{
	AUTH_VARS;
	VAL_MAC(src, len, key, mac);
	WRITE_TMP(src, len, SRC_TMP);
	COMPILE;
	if (ret >= 0) {
		*ret = load_ebpf_prog_lcore(rte_lcore_id(), BIN_TMP, EBPF_SEC, jit, POST);
	}
}

void post_ebpf_load_src_from_packet_all(int8_t *ret, uint8_buffer_t data, bool jit)
{
	VARS;
	WRITE_TMP(src, len, SRC_TMP);
	
	COMPILE;
	if (ret >= 0) {
		*ret = load_ebpf_prog_all(BIN_TMP, EBPF_SEC, jit, POST);
	}
}

void post_ebpf_load_src_from_packet_all_auth(int8_t *ret, uint8_buffer_t data, bool jit)
{
	AUTH_VARS;
	VAL_MAC(src, len, key, mac);
	WRITE_TMP(src, len, SRC_TMP);
	COMPILE;
	if (ret >= 0) {
		*ret = load_ebpf_prog_all(BIN_TMP, EBPF_SEC, jit, POST);
	}
}

// MEMORY
void post_ebpf_load_prog_from_memory(int8_t *ret, char *filename, bool jit)
{
	*ret = load_ebpf_prog_lcore(rte_lcore_id(), filename, EBPF_SEC, jit, POST);
}

void post_ebpf_load_prog_from_memory_auth(int8_t *ret, char *filename, uint8_buffer_t mac, bool jit)
{
	VAL_MAC(filename, STRLEN(filename), key, mac.buffer);
	*ret = load_ebpf_prog_lcore(rte_lcore_id(), filename, EBPF_SEC, jit, POST);
}

void post_ebpf_load_prog_from_memory_all(int8_t *ret, char *filename, bool jit)
{
	*ret = load_ebpf_prog_all(filename, EBPF_SEC, jit, POST);
}

void post_ebpf_load_prog_from_memory_all_auth(int8_t *ret, char *filename, uint8_buffer_t mac, bool jit)
{
	VAL_MAC(filename, STRLEN(filename), key, mac.buffer);
	*ret = load_ebpf_prog_all(filename, EBPF_SEC, jit, POST);
}

// UNLOAD
void post_ebpf_unload_prog()
{
	uint16_t lcore_id = rte_lcore_id();

	for (uint16_t i = 0; i < lcore_conf[lcore_id].hw.n_rx_queue; i++) {
		uint8_t port_id = lcore_conf[lcore_id].hw.rx_queue_list[i].port_id;
		uint8_t queue_id = lcore_conf[lcore_id].hw.rx_queue_list[i].queue_id;
		rte_bpf_eth_tx_unload(port_id, queue_id);
	}
}

void post_ebpf_unload_prog_all()
{
	for (uint16_t i = 0; i < nb_lcore_params; i++) {
		rte_bpf_eth_tx_unload(lcore_params[i].port_id, lcore_params[i].queue_id);
	}
}



// COMMON //
int load_ebpf_prog_all(char *filename, char *section, bool jit, pos_t pos)
{
	const struct rte_bpf_xsym *xsym;

	struct rte_bpf_arg prog_arg = {
		.type = RTE_BPF_ARG_PTR,
		.size = 512,
	};

	struct rte_bpf_prm bpf_params =
	{
		.ins = NULL,
		.nb_ins = 0,
		.xsym = xsym,
		.nb_xsym = 0,
		.prog_arg = prog_arg,
	};

	uint32_t flag = jit ? RTE_BPF_ETH_F_JIT : RTE_BPF_ETH_F_NONE;
	int res = 0;
	for (uint16_t i = 0; i < nb_lcore_params; i++) {
		if (pos == PRE) {
			res += rte_bpf_eth_rx_elf_load(lcore_params[i].port_id, lcore_params[i].queue_id, &bpf_params, filename, section, flag);
		} else if (pos == POST) {
			res += rte_bpf_eth_tx_elf_load(lcore_params[i].port_id, lcore_params[i].queue_id, &bpf_params, filename, section, flag);
		}
		if (res == 0)
		{
			debug("Loaded BPF program from %s, %s\n", filename, section);
			debug("BPF progm args: type: %d, value: %zu\n", prog_arg.type, prog_arg.size);
			debug("BPF program is attached to port %d, queue %d\n", lcore_params[i].port_id, lcore_params[i].queue_id);
		}
	}

	if (res != 0)
	{
		debug("Failed to load BPF program (%d)\n", res);
		return res;
	}
	return 0;
}


int load_ebpf_prog_lcore(uint16_t lcore_id, char *filename, char *section, bool jit, pos_t pos)
{
	const struct rte_bpf_xsym *xsym;

	struct rte_bpf_arg prog_arg = {
		.type = RTE_BPF_ARG_PTR,
		.size = 512,
	};

	struct rte_bpf_prm bpf_params =
	{
		.ins = NULL,
		.nb_ins = 0,
		.xsym = xsym,
		.nb_xsym = 0,
		.prog_arg = prog_arg,
	};

	uint32_t flag = jit ? RTE_BPF_ETH_F_JIT : RTE_BPF_ETH_F_NONE;
	int res = 0;
	for (uint16_t i = 0; i < lcore_conf[lcore_id].hw.n_rx_queue; i++) {
		uint8_t port_id = lcore_conf[lcore_id].hw.rx_queue_list[i].port_id;
		uint8_t queue_id = lcore_conf[lcore_id].hw.rx_queue_list[i].queue_id;
		if (pos == PRE) {
			res += rte_bpf_eth_rx_elf_load(port_id, queue_id, &bpf_params, filename, section, flag);
		} else if (pos == POST) {
			res += rte_bpf_eth_tx_elf_load(port_id, queue_id, &bpf_params, filename, section, flag);
		}

		if (res == 0)
		{
			debug("Loaded BPF program from %s, %s\n", filename, section);
			debug("BPF progm args: type: %d, value: %zu\n", prog_arg.type, prog_arg.size);
			debug("BPF program is attached to port %d, queue %d\n", port_id, queue_id);
		}
		else
		{
			debug("Failed to load BPF program (%d)\n", res);
			return res;
		}
	}
}
