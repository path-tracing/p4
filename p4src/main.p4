/*
 * Copyright 2019-present Open Networking Foundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <core.p4>
#include <v1model.p4>

#include "include/header.p4"
#include "include/parser.p4"
#include "include/checksum.p4"

#define CPU_CLONE_SESSION_ID 99
#define UN_BLOCK_MASK     0xffffffff000000000000000000000000
#define CTRL_PORT 1
#define MY_IP6_LO_ADDR 0xfcbbbbbb000100000000000000000000


control IngressPipeImpl (inout parsed_headers_t hdr,
                         inout local_metadata_t local_metadata,
                         inout standard_metadata_t standard_metadata) {

    action drop() {
        mark_to_drop(standard_metadata);
    }

    action set_output_port(port_num_t port_num) {
        standard_metadata.egress_spec = port_num;
    }
    action set_multicast_group(group_id_t gid) {
        standard_metadata.mcast_grp = gid;
        local_metadata.is_multicast = true;
    }

    direct_counter(CounterType.packets_and_bytes) unicast_counter; 
    table unicast {
        key = {
            hdr.ethernet.dst_addr: exact; 
        }
        actions = {
            set_output_port;
            drop;
            NoAction;
        }
        counters = unicast_counter;
        default_action = NoAction();
    }

    direct_counter(CounterType.packets_and_bytes) multicast_counter;
    table multicast {
        key = {
            hdr.ethernet.dst_addr: ternary;
        }
        actions = {
            set_multicast_group;
            drop;
        }
        counters = multicast_counter;
        const default_action = drop;
    }

    direct_counter(CounterType.packets_and_bytes) l2_firewall_counter;
    table l2_firewall {
	    key = {
	        hdr.ethernet.dst_addr: exact;
	    }
	    actions = {
	        NoAction;
	    }
    	counters = l2_firewall_counter;
    }

    action set_next_hop(mac_addr_t next_hop) {
	    hdr.ethernet.src_addr = hdr.ethernet.dst_addr;
	    hdr.ethernet.dst_addr = next_hop;
	    hdr.ipv6.hop_limit = hdr.ipv6.hop_limit - 1;
    }

    direct_counter(CounterType.packets_and_bytes) routing_v6_counter;
    table routing_v6 {
	    key = {
	        hdr.ipv6.dst_addr: lpm;
	    }
        actions = {
	        set_next_hop;
        }
        counters = routing_v6_counter;
    }

    action insert_srh_header_1() {
        hdr.outer_srh.setValid();
        hdr.outer_srh.next_hdr = PROTO_IPV6;
        hdr.outer_srh.hdr_ext_len =  4;
        hdr.outer_srh.routing_type = 4;
        hdr.outer_srh.segments_left = 0;
        hdr.outer_srh.last_entry = 0;
        hdr.outer_srh.flags = 0;
        hdr.outer_srh.tag = 0;
    }

    action srv6_pop() {
        hdr.ipv6.next_hdr = hdr.srh.next_hdr;
        bit<16> srh_size = (((bit<16>)hdr.srh.last_entry + 1) << 4) + 8;
        hdr.ipv6.payload_len = hdr.ipv6.payload_len - srh_size;

        hdr.srh.setInvalid();
        hdr.srh_sid_list[0].setInvalid();
        hdr.srh_sid_list[1].setInvalid();
        hdr.srh_sid_list[2].setInvalid();
    }

    action srv6_end() {}

    action srv6_usid_un() {
        hdr.ipv6.dst_addr = (hdr.ipv6.dst_addr & UN_BLOCK_MASK) | ((hdr.ipv6.dst_addr << 16) & ~((bit<128>)UN_BLOCK_MASK));
    }

    direct_counter(CounterType.packets_and_bytes) srv6_localsid_table_counter;
    table srv6_localsid_table {
        key = {
            hdr.ipv6.dst_addr: lpm;
        }
        actions = {
            srv6_end;
            srv6_usid_un;
            NoAction;
        }
        default_action = NoAction;
        counters = srv6_localsid_table_counter;
    }

    action srv6_b6_tef_v6(ipv6_addr_t oip, ipv6_addr_t sid_1) {
        hdr.ipv6_inner.setValid();

        hdr.ipv6_inner.version =        hdr.ipv6.version;
        hdr.ipv6_inner.traffic_class =  hdr.ipv6.traffic_class;
        hdr.ipv6_inner.flow_label =     hdr.ipv6.flow_label;
        hdr.ipv6_inner.payload_len =    hdr.ipv6.payload_len;
        hdr.ipv6_inner.next_hdr =       hdr.ipv6.next_hdr;
        hdr.ipv6_inner.hop_limit =      hdr.ipv6.hop_limit;
        hdr.ipv6_inner.src_addr =       hdr.ipv6.src_addr;
        hdr.ipv6_inner.dst_addr =       hdr.ipv6.dst_addr;

        hdr.ipv6.payload_len = hdr.ipv6.payload_len + 40 + 24 + 16;
        hdr.ipv6.next_hdr = PROTO_SRH;
        hdr.ipv6.src_addr = MY_IP6_LO_ADDR;
        hdr.ipv6.hop_limit = 0x40;
        hdr.ipv6.dst_addr = oip;

        insert_srh_header_1();

        hdr.outer_srh_sid_list[0].setValid();
        hdr.outer_srh_sid_list[0].sid = sid_1;

        hdr.outer_srh_tlv.setValid();
        hdr.outer_srh_tlv.type = SRH_PT_TLV_TYPE;
        hdr.outer_srh_tlv.len = SRH_PT_TLV_LEN;

        hdr.srh_pt_tlv.setValid();

        hdr.srh_pt_tlv.if_id = 12w0; 
        hdr.srh_pt_tlv.if_ld = 4w0; 
        hdr.srh_pt_tlv.t64 = (bit<64>) standard_metadata.ingress_global_timestamp;
        hdr.srh_pt_tlv.session_id = 0;
        hdr.srh_pt_tlv.seq_num = 0;

        local_metadata.is_encap = true;
    }

    direct_counter(CounterType.packets_and_bytes) srv6_encap_v6_counter;
    table srv6_encap_v6 {
        key = {
           hdr.ipv6.dst_addr: lpm;       
        }
        actions = {
            srv6_b6_tef_v6;
            NoAction;
        }
        default_action = NoAction;
        counters = srv6_encap_v6_counter;
    }

    action act_ingress_port_map(bit<12> port_id) {
        local_metadata.mapped_port = port_id;
    }

    direct_counter(CounterType.packets_and_bytes) ingress_port_map_counter;
    table ingress_port_map {
        key = {
           standard_metadata.ingress_port: exact;       
        }
        actions = {
            act_ingress_port_map;
            NoAction;
        }
        default_action = NoAction;
        counters = ingress_port_map_counter;
    }

    apply {
	    if (hdr.ipv6.hop_limit == 0) {
	        drop();
	    }

	    if (l2_firewall.apply().hit) {
            if (!srv6_encap_v6.apply().hit) {
                switch(srv6_localsid_table.apply().action_run) {
                    srv6_end: {
                        if (hdr.srh.segments_left > 0) {
                            hdr.ipv6.dst_addr = local_metadata.next_srv6_sid;
                            hdr.srh.segments_left = hdr.srh.segments_left - 1;
                        } else {
                            hdr.ipv6.dst_addr = hdr.srh_sid_list[0].sid;
                        }
                    }
                }
            }

	        routing_v6.apply();
	    }
        
	    if (!local_metadata.skip_l2) {
            if (!unicast.apply().hit) {
       	      	multicast.apply();
	        }	
	    }

        // Sink function processing
        if (local_metadata.is_encap) {
            ingress_port_map.apply();
            hdr.srh_pt_tlv.if_id = local_metadata.mapped_port;
        }    
    }
}

control EgressPipeImpl (inout parsed_headers_t hdr,
                        inout local_metadata_t local_metadata,
                        inout standard_metadata_t standard_metadata) {

    action act_port_map(bit<12> port_id) {
        local_metadata.mapped_port = port_id;
    }

    direct_counter(CounterType.packets_and_bytes) egress_port_map_counter;
    table egress_port_map {
        key = {
           standard_metadata.egress_port: exact;       
        }
        actions = {
            act_port_map;
            NoAction;
        }
        default_action = NoAction;
        counters = egress_port_map_counter;
    }

    apply {
        if (standard_metadata.egress_port == CTRL_PORT) {
		    hdr.packet_in.setValid();
		    hdr.packet_in.ingress_port = standard_metadata.ingress_port;		
        }

        if (local_metadata.is_multicast == true
             && standard_metadata.ingress_port == standard_metadata.egress_port) {
            mark_to_drop(standard_metadata);
        }

        if (egress_port_map.apply().hit) {
            if (standard_metadata.ingress_port == CTRL_PORT) {
                if (hdr.srh_pt_tlv.isValid()) {
                    hdr.srh_pt_tlv.if_id = local_metadata.mapped_port;
                    hdr.srh_pt_tlv.if_ld = 4w0;
                    hdr.srh_pt_tlv.t64 = (bit<64>) standard_metadata.egress_global_timestamp;
                }
            } else {
                if (local_metadata.num_pt_mcd == PT_MCD_STACK_HOPS) {
                    hdr.ipv6_hbh_pt_stack[11] = hdr.ipv6_hbh_pt_stack[10];
                    hdr.ipv6_hbh_pt_stack[10] = hdr.ipv6_hbh_pt_stack[9];
                    hdr.ipv6_hbh_pt_stack[9]  = hdr.ipv6_hbh_pt_stack[8];
                    hdr.ipv6_hbh_pt_stack[8]  = hdr.ipv6_hbh_pt_stack[7];
                    hdr.ipv6_hbh_pt_stack[7]  = hdr.ipv6_hbh_pt_stack[6];
                    hdr.ipv6_hbh_pt_stack[6]  = hdr.ipv6_hbh_pt_stack[5];
                    hdr.ipv6_hbh_pt_stack[5]  = hdr.ipv6_hbh_pt_stack[4];
                    hdr.ipv6_hbh_pt_stack[4]  = hdr.ipv6_hbh_pt_stack[3];
                    hdr.ipv6_hbh_pt_stack[3]  = hdr.ipv6_hbh_pt_stack[2];
                    hdr.ipv6_hbh_pt_stack[2]  = hdr.ipv6_hbh_pt_stack[1];
                    hdr.ipv6_hbh_pt_stack[1]  = hdr.ipv6_hbh_pt_stack[0];

                    hdr.ipv6_hbh_pt_stack[0].oif = local_metadata.mapped_port;
                    hdr.ipv6_hbh_pt_stack[0].oil = 4w0;
                    hdr.ipv6_hbh_pt_stack[0].tts = (bit<8>) (standard_metadata.egress_global_timestamp >> 18);
                }  
            }
        }
    }
}

V1Switch(
    ParserImpl(),
    VerifyChecksumImpl(),
    IngressPipeImpl(),
    EgressPipeImpl(),
    ComputeChecksumImpl(),
    DeparserImpl()
) main;
