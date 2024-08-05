parser ParserImpl(packet_in packet, out headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    @name(".start") state start {
        transition parse_ethernet;
    }
    @name(".parse_ethernet") state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            16w0x800: parse_ipv4;
            default: accept;
        }
    }
    @name(".parse_ipv4") state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            0x11:       parse_udp;
            default:    accept;
        }
    }
    @name(".parse_udp") state parse_udp {
        packet.extract(hdr.udp);
	transition select(hdr.udp.dstPort) {
	    7004:	parse_program;
	    5678:	parse_inc;
	    default:	accept;
	}
    }
    @name(".parse_inc") state parse_inc {
        packet.extract(hdr.inc);
	transition accept;
    }
    @name(".parse_program") state parse_program {
        packet.extract(hdr.program);
	transition accept;
    }
}

