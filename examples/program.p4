#include <core.p4>
#include <v1model.p4>


struct metadata {
}

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
    bit<16> len;
    bit<16> chkSum;
    bit<32> reserved;
}

header custom_t {
    // actually payload1 and payload2 are 64 bit -> use only first 32 bits here
    bit<32> payload1;
    bit<32> unused1;
    bit<32> payload2;
    bit<32> unused2;
}

struct headers {
    @name(".ethernet")
    ethernet_t ethernet;
    @name(".ipv4")
    ipv4_t ipv4;
    @name(".udp")
    udp_t udp;
    @name(".custom")
    custom_t custom;
}




// parser
parser ParserImpl(packet_in packet, out headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    @name(".parse_custom") state parse_custom {
    	packet.extract(hdr.custom);
    	transition accept;
        }
    @name(".parse_udp") state parse_udp {
	packet.extract(hdr.udp);
	transition parse_custom;
    }
    @name(".parse_ipv4") state parse_ipv4 {
	packet.extract(hdr.ipv4);
	transition parse_udp;
    }
    @name(".parse_ethernet") state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition parse_ipv4;
    }
    @name(".start") state start {
        transition parse_ethernet;
    }
}// parser parse



// control
control ingress(inout headers hdr, inout metadata data, inout standard_metadata_t standard_metadata) {
    @name("._drop") action _drop() {
        mark_to_drop();
    }

    @name(".forward") action forward(@__ref bit<32> count) {
        standard_metadata.egress_port = 9w3;
        hdr.custom.payload1 = count;
        count = hdr.custom.payload2;
    }

    @name(".table0") @tableconfig(impl="dpdk", store="static", synced=true) table table0 {
        actions = {
            forward;
            _drop;
        }
        key = {
            hdr.custom.payload1: exact;
        }
        size = 256;
        default_action = _drop();
    }

    apply {
        table0.apply();
    }
}

control egress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    apply {
    }
}

control DeparserImpl(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.udp);
        packet.emit(hdr.custom);
    }
}
control verifyChecksum(inout headers hdr, inout metadata meta) {
    apply {
    }
}

control computeChecksum(inout headers hdr, inout metadata meta) {
    apply {
    }
}

V1Switch(ParserImpl(), verifyChecksum(), ingress(), egress(), computeChecksum(), DeparserImpl()) main;