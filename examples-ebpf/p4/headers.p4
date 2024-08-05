header ethernet_t {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> etherType;
}

header ipv4_t {
    bit<8>  versionIhl;
    bit<8>  diffserv;
    bit<16> totalLen;
    bit<16> identification;
    bit<16> fragOffset;
    bit<8>  ttl;
    bit<8>  protocol;
    bit<16> hdrChecksum;
    bit<32> srcAddr;
    bit<32> dstAddr;
}

header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> plength;
    bit<16> checksum;
}

header inc_t {
    bit<32> payload1;
    bit<32> payload2;
}

header program_t {
    bit<32> len;
    bit<2048> binary1;
    bit<2048> binary2;
    bit<2048> binary3;
    bit<2048> binary4;
}

struct metadata {
}

struct headers {
    @name(".ethernet")
    ethernet_t  ethernet;
    @name(".ipv4")
    ipv4_t  ipv4;
    @name(".udp")
    udp_t udp;
    @name(".program")
    program_t program;
    @name(".inc")
    inc_t inc;
}
