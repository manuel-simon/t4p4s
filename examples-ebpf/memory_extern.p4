#include <core.p4>
#include <v1model.p4>

#include "p4/headers.p4"
#include "p4/parser.p4"
#include "p4/ebpf.p4"


control ingress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {

    action nop() {}
    
	
	ebpf_prog(8w3, false) ebpf_prog_0;
    

    
    
        action extern_memory_false_true_program_0() {
            int<8> ret;
            
            ebpf_prog_0.load_prog_from_memory(ret, "bins/empty.o");
            
        }
    
        table extern_memory_false_true_0_tab {
		    actions = {
                
    			extern_memory_false_true_program_0;
                
    			nop;
    		}

		key = {
			hdr.program.len: exact;
		}
		size = 8;

		const entries = {
            
			(0x1): extern_memory_false_true_program_0();
            
		}

		default_action=nop();
	}
    


    apply {
        standard_metadata.egress_port = 9w0;

        # memory
        if (hdr.udp.dstPort == 7004) {
        
            extern_memory_false_true_0_tab.apply();
        
        }
        # prog and src
        

        // externs
        
        // ebpf_prog_0
        bool a_0 = false;
        int<8> ret_0;
        ebpf_prog_0.get_status(a_0);
        if (a_0)  {
            if (hdr.udp.dstPort == 7004) {
                

                
	        } else {
                
                ebpf_prog_0.exec_prog({ hdr.inc.payload1, hdr.inc.payload2 }, ret_0);
                
            }
        } else {
            ebpf_prog_0.load_prog_from_memory(ret_0, "bins/dummy.o");
        }
        


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
