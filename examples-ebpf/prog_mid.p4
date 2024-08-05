#include <core.p4>
#include <v1model.p4>

#include "/root/dyn-ebpf/p4/headers.p4"
#include "/root/dyn-ebpf/p4/parser.p4"
#include "/root/dyn-ebpf/p4/ebpf.p4"


control ingress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {

    action nop() {}
    

    


    apply {
        standard_metadata.egress_port = 9w0;

        # memory
        if (hdr.udp.dstPort == 7004) {
        
        }
        # prog and src
        
        if (hdr.program.isValid()) {
			int<8> ret;
			
            mid_ebpf_load_prog_from_packet(ret, {hdr.program.len, hdr.program.binary1, hdr.program.binary2, hdr.program.binary3, hdr.program.binary4}, true);
		}
        

        // externs
        


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
		if (hdr.udp.dstPort == 7004) {
		    packet.emit(hdr.program);
		} else {
		    packet.emit(hdr.inc);
		}
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
