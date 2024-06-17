#pragma once
#include "backend.h"
#include "common.h"
#include <rte_common.h>
#include <rte_bpf.h>
#include "mac.h"

typedef struct {
	struct rte_bpf *bpf_prog;
	uint8_t key[BLAKE3_KEY_LEN];
	bool authenticated;
	uint8_t opt;
} ebpf_prog_t;

#define SRC_TMP "/tmp/tmp.c"
#define BIN_TMP "/tmp/tmp.o"

ebpf_prog_t* ebpf_prog(uint8_t opt, bool authenticated, SHORT_STDPARAMS);

void extern_ebpf_prog_get_status(uint8_t declarg, uint8_t declarg2, bool *ret, ebpf_prog_t *ebpf, SHORT_STDPARAMS);
void extern_ebpf_prog_load_prog_from_memory(uint8_t declarg, uint8_t declarg2, int8_t *ret, char* newpath, ebpf_prog_t *ebpf, SHORT_STDPARAMS);
void extern_ebpf_prog_exec_prog(uint8_t declarg, uint8_t declarg2, uint8_buffer_t data, int8_t *ret, ebpf_prog_t *ebpf, SHORT_STDPARAMS);
void extern_ebpf_prog_load_prog_from_packet(uint8_t declarg, uint8_t declarg2, int8_t *ret, uint8_buffer_t data, ebpf_prog_t *ebpf, SHORT_STDPARAMS);
void extern_ebpf_prog_exec_prog_packet(uint8_t declarg, uint8_t declarg2, int8_t *ret, ebpf_prog_t *ebpf, SHORT_STDPARAMS);
void extern_ebpf_prog_load_src_from_packet(uint8_t declarg, uint8_t declarg2, int8_t *ret, uint8_buffer_t data, ebpf_prog_t *ebpf, SHORT_STDPARAMS);
void extern_ebpf_prog_exec_prog__T(uint8_t declarg, uint8_t declarg2, uint8_buffer_t data, int8_t *ret, ebpf_prog_t *ebpf, SHORT_STDPARAMS);

extern int8_t load_bpf_elf(char* newpath, ebpf_prog_t *ebpf);
extern int write_to_temp(uint8_t *data, uint32_t len, char* path);
