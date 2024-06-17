#ifndef DYNAMICLOAD_MAC_H
#define DYNAMICLOAD_MAC_H

#include <blake3.h>

void create_mac(uint8_t *str, size_t len, uint8_t *key, uint8_t *output);
int validate_mac(uint8_t *str, size_t len, uint8_t *key, uint8_t *mac);

#endif //DYNAMICLOAD_MAC_H
