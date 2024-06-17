#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <stdlib.h>
#include <rte_common.h>
#include <rte_bpf.h>
#include <rte_malloc.h>
#include "ebpf.h"

#include "util_debug.h"

char key[BLAKE3_KEY_LEN] = {0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7,
	0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf,
	0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7,
	0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf};

#define STRLEN(s) (sizeof(s)/sizeof(s[0])-sizeof(s[0]))

#define AUTH_VARS(auth) \
        uint32_t len;\
        if (auth) {\
		    len = ntohl((uint32_t) *((uint32_t*) data.buffer)) - sizeof(uint8_t)*32;\
		} else {\
		    len = ntohl((uint32_t) *((uint32_t*) data.buffer));\
		}\
		uint8_t *mac = data.buffer+sizeof(uint32_t);\
		uint8_t *src;\
		if (auth) {\
			src = mac+sizeof(uint8_t)*32;\
		} else {\
			src = mac;\
		}\
		debug("    : " T4LIT(Executed eBPF, extern) " len " T4LIT(% lu) "\n", len);\
		debug("    : " T4LIT(Executed eBPF, extern) " bin " T4LIT(% lu) "\n", data.buffer_size);\
		debug("    : " T4LIT(Executed eBPF, extern) " bin " T4LIT(% lu) "\n", data.buffer);\
	

#define VAL_MAC(str, len, key, mac) {\
		*ret = validate_mac(str, len, key, mac);\
		if (*ret == 0) {\
			debug("    : " T4LIT(Executed eBPF, extern) " MAC validated\n");\
		} else {\
			debug("    : " T4LIT(Executed eBPF, extern) " MAC fail\n");\
		}\
	}	

#define AUTH_VAL_MAC(auth, str, len, key, mac) {\
		if (auth) {\
			VAL_MAC(str, len, key, mac)\
		}\
}

ebpf_prog_t* ebpf_prog(uint8_t opt, bool authenticated, SHORT_STDPARAMS)
{
	ebpf_prog_t *ebpf = (ebpf_prog_t*) rte_malloc("ebpf_prog_t", sizeof(ebpf_prog_t), 0);
	ebpf->opt = opt;
	ebpf->bpf_prog = NULL;
	ebpf->authenticated = authenticated;
	rte_memcpy(ebpf->key, key, BLAKE3_KEY_LEN);
	return ebpf;
}

void extern_ebpf_prog_get_status(uint8_t declarg, uint8_t declarg2, bool *ret, ebpf_prog_t *ebpf, SHORT_STDPARAMS)
{
	*ret = ebpf->bpf_prog != NULL;
}

inline int8_t load_bpf_elf(char* newpath, ebpf_prog_t *ebpf) {
	struct rte_bpf *bpf;
	const struct rte_bpf_xsym *xsym;

	struct rte_bpf_arg prog_arg = {
		.type = RTE_BPF_ARG_PTR,
		.size = 512,
	};

	struct rte_bpf_prm bpf_params = {
		.ins = NULL,
		.nb_ins = 0,
		.xsym = xsym,
		.nb_xsym = 0,
		.prog_arg = prog_arg,
	};

	bpf = rte_bpf_elf_load(&bpf_params, newpath, ".text");

	if (bpf == NULL)
	{
		debug("Failed to load BPF program from memory\n");
		return -1;
	}
	else
	{
		debug("Loaded BPF program from memory\n");
		if (ebpf->bpf_prog != NULL) {
			rte_bpf_destroy(ebpf->bpf_prog);
		}
		ebpf->bpf_prog = bpf;
		return 0;
	}
}

void extern_ebpf_prog_load_prog_from_memory(uint8_t declarg, uint8_t declarg2, int8_t *ret, char* newpath, ebpf_prog_t *ebpf, SHORT_STDPARAMS) {
	*ret = load_bpf_elf(newpath, ebpf);
}

void extern_ebpf_prog_load_src_from_packet(uint8_t declarg, uint8_t declarg2, int8_t *ret, uint8_buffer_t data, ebpf_prog_t *ebpf, SHORT_STDPARAMS) {
	AUTH_VARS(ebpf->authenticated);
	AUTH_VAL_MAC(ebpf->authenticated, src, len, ebpf->key, mac);

	*ret = write_to_temp(src, len, SRC_TMP);
	if (ret >= 0) {
		switch(ebpf->opt) {
			case 1: *ret = system("clang -O1 -target bpf -c \"" SRC_TMP "\" -o \"" BIN_TMP "\""); break;
			case 3: *ret = system("clang -O3 -target bpf -c \"" SRC_TMP "\" -o \"" BIN_TMP "\""); break;
			case 0: *ret = system("clang -O0 -target bpf -c \"" SRC_TMP "\" -o \"" BIN_TMP "\""); break;
			case 2:
			default: *ret = system("clang -O2 -target bpf -c \"" SRC_TMP "\" -o \"" BIN_TMP "\""); break;
		}
	}

	if (ret >= 0) {
		*ret = load_bpf_elf(BIN_TMP, ebpf);
	}
}
void extern_ebpf_prog_exec_prog__T(uint8_t declarg, uint8_t declarg2, uint8_buffer_t data, int8_t *ret, ebpf_prog_t *ebpf, SHORT_STDPARAMS) {
	extern_ebpf_prog_exec_prog(declarg, declarg2, data, ret, ebpf, SHORT_STDPARAMS_IN);
}

void extern_ebpf_prog_exec_prog_packet(uint8_t declarg, uint8_t declarg2, int8_t *ret, ebpf_prog_t *ebpf, SHORT_STDPARAMS) {
	uint8_buffer_t data = {.buffer = pd->headers[0].pointer, .buffer_size = 0};
	extern_ebpf_prog_exec_prog(declarg, declarg2, data, ret, ebpf, SHORT_STDPARAMS_IN);
}

void extern_ebpf_prog_exec_prog(uint8_t declarg, uint8_t declarg2, uint8_buffer_t data, int8_t *ret,  ebpf_prog_t *ebpf, SHORT_STDPARAMS)
{
	dbg_bytes(data.buffer, data.buffer_size, "    : " T4LIT(Executing eBPF, extern) " for " T4LIT(% d) " bytes: ", data.buffer_size);
	uint64_t r;
	r = rte_bpf_exec(ebpf->bpf_prog, data.buffer);
	*ret = (int8_t) r;
	debug("    : " T4LIT(Executed eBPF, extern) " returning " T4LIT(% lu) "\n", *ret);
}

inline int write_to_temp(uint8_t *data, uint32_t len, char* path) {
	FILE *file = fopen(path, "wb");
	if (file == NULL) {
		return -1;
	}
	fwrite(data, len, 1, file);
	fclose(file);
	return 0 ;
}

void extern_ebpf_prog_load_prog_from_packet(uint8_t declarg, uint8_t declarg2, int8_t *ret, uint8_buffer_t data, ebpf_prog_t *ebpf, SHORT_STDPARAMS) {
	AUTH_VARS(ebpf->authenticated);
	AUTH_VAL_MAC(ebpf->authenticated, src, len, ebpf->key, mac);
	
	*ret = write_to_temp(src, len, BIN_TMP);
	if (ret >= 0) {
		*ret = load_bpf_elf(BIN_TMP, ebpf);
	}
}
