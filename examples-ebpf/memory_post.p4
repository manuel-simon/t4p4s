#include <core.p4>
#include <v1model.p4>

#include "p4/headers.p4"
#include "p4/parser.p4"
#include "p4/ebpf.p4"


control ingress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {

    action nop() {}
    

    
    
        action post_memory_false_true_program_0() {
            int<8> ret;
            
            
            post_ebpf_load_prog_from_memory_all(ret, "bins/empty.o", false);
            
        }
    
        table post_memory_false_true_0_tab {
		    actions = {
                
    			post_memory_false_true_program_0;
                
    			nop;
    		}

		key = {
			hdr.program.len: exact;
		}
		size = 8;

		const entries = {
            
			(0x1): post_memory_false_true_program_0();
            
		}

		default_action=nop();
	}
    


    apply {
        standard_metadata.egress_port = 9w0;

        # memory
        if (hdr.udp.dstPort == 7004) {
        
            post_memory_false_true_0_tab.apply();
        
        }
        # prog and src
        

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
