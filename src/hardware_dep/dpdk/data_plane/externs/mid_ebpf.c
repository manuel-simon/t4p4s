#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <rte_common.h>
#include <rte_bpf_ethdev.h>
#include "dpdk_lib.h"
#include "ebpf.h"

#include "util_debug.h"
#include "dpdk_ebpf_defs.h"

#define SHORT_STDPARAMS_IN_DUMMY NULL, NULL
#define FAKE_MAC \
		uint8_buffer_t mac; \
		mac.buffer = NULL;\
		mac.buffer_size = 0;\


extern char key[BLAKE3_KEY_LEN];

ebpf_prog_t mid_ebpf = { .opt = 3, .bpf_prog = NULL, .authenticated = false};

// MID //

// BIN PACKET
void mid_ebpf_load_prog_from_packet(int8_t *ret, uint8_buffer_t data, bool jit);
// SRC PACKET
void mid_ebpf_load_src_from_packet(int8_t *ret, uint8_buffer_t data, bool jit);
// MEMORY
void mid_ebpf_load_prog_from_memory(int8_t *ret, char *filename, bool jit);

// UNLOAD
void mid_ebpf_unload_prog();

// BIN PACKET
void mid_ebpf_load_prog_from_packet(int8_t *ret, uint8_buffer_t data, bool jit)
{
        VARS;
        WRITE_TMP(src, len, BIN_TMP);
        if (ret >= 0) {
		extern_ebpf_prog_load_prog_from_packet(0, false, ret, data,&mid_ebpf, SHORT_STDPARAMS_IN_DUMMY);
        }
}

// SRC PACKET
void mid_ebpf_load_src_from_packet(int8_t *ret, uint8_buffer_t data, bool jit)
{
        VARS;
        WRITE_TMP(src, len, SRC_TMP);
        COMPILE;
        if (ret >= 0) {
		extern_ebpf_prog_load_src_from_packet(0, false, ret, data, &mid_ebpf, SHORT_STDPARAMS_IN_DUMMY);
        }
}

// MEMORY
void mid_ebpf_load_prog_from_memory(int8_t *ret, char *filename, bool jit)
{
	extern_ebpf_prog_load_prog_from_memory(jit, false, ret, filename, &mid_ebpf, SHORT_STDPARAMS_IN_DUMMY);
}

// UNLOAD
void mid_ebpf_unload_prog()
{
	rte_bpf_destroy(mid_ebpf.bpf_prog);
	mid_ebpf.bpf_prog == NULL;
}

