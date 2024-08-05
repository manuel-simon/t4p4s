#ifndef _EBPF_P4_
#define _EBPF_P4_
#include <core.p4>

#define MAC_LEN 256

extern ebpf_prog {
	// Constructor
	// authenticated specifies whether an MAC is used to authenticate program changes
    ebpf_prog(bit<8> opt, bool authenticated);

	// return status of processor
    void get_status(out bool ret);

	// load a new program to the processor using its path to the .o file
    void load_prog_from_memory(out int<8> ret, string newpath);

	// execute the loaded eBPF program on specified header fields
    void exec_prog<T>(in T buf, out int<8> ret);

	// execute the loaded eBPF program on the whole packet
    void exec_prog_packet(out int<8> ret);

	// load and bind a new eBPF program from source code
	// first bit<32> parameter of the tuple defines the length of the source code
	// the rest define [MAC_LEN-sized BLAKE3 MAC] (if enabled), followed by the source code
    void load_prog_from_packet(out int<8> ret, in tuple<bit<32>, bit<2048>, bit<2048>, bit<2048>,bit<2048>> binary);

// load and bind a new eBPF program from byte code
	// first bit<32> parameter of the tuple defines the length of the source code
	// the rest define [MAC_LEN-sized BLAKE3 MAC] (if enabled), followed by the byte code
    void load_src_from_packet(out int<8> ret, in tuple<bit<32>, bit<2048>, bit<2048>, bit<2048>,bit<2048>> binary);
}


// Fixed positions
// pre, mid, or post position

// program is loaded using its path for the _memory versions


// program is loaded from the packet using its source or byte code for the _source and _prog versions

// first bit<32> parameter of the tuple defines the length of the source code
// the rest define [MAC_LEN-sized BLAKE3 MAC] (for _auth versions), followed by the code

//_all versions install the processor for all queues/core
// other versions only for current queue/core

// unload unloads the program and deactivates the processor for current queue/core
// unload_all unloads the program and deactivates the processor for all queues/cores

// PRE
// BIN PACKET
extern void pre_ebpf_load_prog_from_packet(out int<8> ret, in tuple<bit<32>, bit<2048>, bit<2048>, bit<2048>, bit<2048>> binary, in bool jit);
extern void pre_ebpf_load_prog_from_packet_auth(out int<8> ret, in tuple<bit<32>, bit<2048>, bit<2048>, bit<2048>, bit<2048>> binary, in bool jit);
extern void pre_ebpf_load_prog_from_packet_all(out int<8> ret, in tuple<bit<32>, bit<2048>, bit<2048>, bit<2048>, bit<2048>> binary, in bool jit);
extern void pre_ebpf_load_prog_from_packet_all_auth(out int<8> ret, in tuple<bit<32>, bit<2048>, bit<2048>, bit<2048>, bit<2048>> binary, in bool jit);
// SRC PACKET
extern void pre_ebpf_load_src_from_packet(out int<8> ret, in tuple<bit<32>, bit<2048>, bit<2048>, bit<2048>, bit<2048>> binary, in bool jit);
extern void pre_ebpf_load_src_from_packet_auth(out int<8> ret, in tuple<bit<32>, bit<2048>, bit<2048>, bit<2048>, bit<2048>> binary, in bool jit);
extern void pre_ebpf_load_src_from_packet_all(out int<8> ret, in tuple<bit<32>,bit<2048>, bit<2048>, bit<2048>, bit<2048>> binary, in bool jit);
extern void pre_ebpf_load_src_from_packet_all_auth(out int<8> ret, in tuple<bit<32>, bit<2048>, bit<2048>, bit<2048>, bit<2048>> binary, in bool jit);
// MEMORY
extern void pre_ebpf_load_prog_from_memory(out int<8> ret, string path, in bool jit);
extern void pre_ebpf_load_prog_from_memory_auth(out int<8> ret, string path, in bit<MAC_LEN> mac, in bool jit);
extern void pre_ebpf_load_prog_from_memory_all(out int<8> ret, string path, in bool jit);
extern void pre_ebpf_load_prog_from_memory_all_auth(out int<8> ret, string path, in bit<MAC_LEN> mac, in bool jit);
// UNLOAD
extern void pre_ebpf_unload_prog();
extern void pre_ebpf_unload_prog_all();

//POST
// BIN PACKET
extern void post_ebpf_load_prog_from_packet(out int<8> ret, in tuple<bit<32>, bit<2048>, bit<2048>, bit<2048>, bit<2048>> binary, in bool jit);
extern void post_ebpf_load_prog_from_packet_auth(out int<8> ret, in tuple<bit<32>, bit<2048>, bit<2048>, bit<2048>, bit<2048>> binary, in bool jit);
extern void post_ebpf_load_prog_from_packet_all(out int<8> ret, in tuple<bit<32>, bit<2048>, bit<2048>, bit<2048>, bit<2048>> binary, in bool jit);
extern void post_ebpf_load_prog_from_packet_all_auth(out int<8> ret, in tuple<bit<32>, bit<2048>, bit<2048>, bit<2048>, bit<2048>> binary, in bool jit);
// SRC PACKET
extern void post_ebpf_load_src_from_packet(out int<8> ret, in tuple<bit<32>, bit<2048>, bit<2048>, bit<2048>, bit<2048>> binary, in bool jit);
extern void post_ebpf_load_src_from_packet_auth(out int<8> ret, in tuple<bit<32>, bit<2048>, bit<2048>, bit<2048>, bit<2048>> binary, in bool jit);
extern void post_ebpf_load_src_from_packet_all(out int<8> ret, in tuple<bit<32>,bit<2048>, bit<2048>, bit<2048>, bit<2048>> binary, in bool jit);
extern void post_ebpf_load_src_from_packet_all_auth(out int<8> ret, in tuple<bit<32>, bit<2048>, bit<2048>, bit<2048>, bit<2048>> binary, in bool jit);
// MEMORY
extern void post_ebpf_load_prog_from_memory(out int<8> ret, string path, in bool jit);
extern void post_ebpf_load_prog_from_memory_auth(out int<8> ret, string path, in bit<MAC_LEN> mac, in bool jit);
extern void post_ebpf_load_prog_from_memory_all(out int<8> ret, string path, in bool jit);
extern void post_ebpf_load_prog_from_memory_all_auth(out int<8> ret, string path, in bit<MAC_LEN> mac, in bool jit);
// UNLOAD
extern void post_ebpf_unload_prog();
extern void post_ebpf_unload_prog_all();

//MID
// BIN PACKET
extern void mid_ebpf_load_prog_from_packet(out int<8> ret, in tuple<bit<32>, bit<2048>, bit<2048>, bit<2048>, bit<2048>> binary, in bool jit);
// SRC PACKET
extern void mid_ebpf_load_src_from_packet(out int<8> ret, in tuple<bit<32>, bit<2048>, bit<2048>, bit<2048>, bit<2048>> binary, in bool jit);
// MEMORY
extern void mid_ebpf_load_prog_from_memory(out int<8> ret, string path, in bool jit);

// UNLOAD
extern void mid_ebpf_unload_prog();


#endif //_EBPF_P4_

