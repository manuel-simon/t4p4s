#include "mac.h"

void create_mac(uint8_t *str, size_t len, uint8_t *key, uint8_t *output) {
	blake3_hasher hasher;
	blake3_hasher_init_keyed(&hasher, key);
	blake3_hasher_update(&hasher, str, len);
	blake3_hasher_finalize(&hasher, output, BLAKE3_OUT_LEN);
}

int validate_mac(uint8_t *str, size_t len, uint8_t *key, uint8_t *mac) {
	uint8_t comp[BLAKE3_OUT_LEN];
	create_mac(str, len, key, comp);
	return memcmp(comp, mac, BLAKE3_OUT_LEN);
}
