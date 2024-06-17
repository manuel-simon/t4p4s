#pragma one

#define STRLEN(s) (sizeof(s)/sizeof(s[0])-sizeof(s[0]))

#define VARS \
        uint32_t len = ntohl((uint32_t) *((uint32_t*) data.buffer));\
        uint8_t *src = data.buffer + sizeof(uint32_t);\
        debug("Executed eBPF, extern len %lu\n", len);\
        debug("Executed eBPF, extern bin %lu\n", data.buffer_size);\
        debug("Executed eBPF, extern bin %lu\n", src);\


#define AUTH_VARS\
        uint32_t len= ntohl((uint32_t) *((uint32_t*) data.buffer)) -sizeof(uint8_t)*32;\
        uint8_t *mac = data.buffer + sizeof(uint32_t);\
        uint8_t *src = mac + 32*sizeof(uint8_t);\
        debug("Executed eBPF, extern  len %lu\n", len);\
        debug("Executed eBPF, extern  bin %lu\n", data.buffer_size);\
        debug("Executed eBPF, extern  bin %lu\n", src);\


#define SRC_TMP "/tmp/tmp.c"
#define BIN_TMP "/tmp/tmp.o"

#define COMPILE_CMD "clang -O2 -target bpf -c \"" SRC_TMP "\" -o \"" BIN_TMP "\""

#define COMPILE \
        if (ret >= 0) {\
                *ret = system(COMPILE_CMD);\
        }\

#define WRITE_TMP(src, len, out) {\
        *ret = write_to_temp(src, len, out);\
	}	

#define VAL_MAC(str, len, key, mac) {\
                *ret = validate_mac(str, len, key, mac);\
                if (*ret == 0) {\
                        debug("Executed eBPF, extern:  MAC validated\n");\
                } else {\
                        debug("T4LIT(Executed eBPF, extern):  MAC fail\n");\
                }\
        }       

#define AUTH_VAL_MAC(auth, str, len, key, mac) {\
                if (auth) {\
                        VAL_MAC(str, len, key, mac)\
                }\
}
