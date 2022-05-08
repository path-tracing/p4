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

#ifndef __PARSER__
#define __PARSER__

#include "define.p4"

parser ParserImpl (packet_in packet,
                   out parsed_headers_t hdr,
                   inout local_metadata_t local_metadata,
                   inout standard_metadata_t standard_metadata)
{
    state start {
        transition select(standard_metadata.ingress_port) {
            CPU_PORT: parse_packet_out;
            default: parse_ethernet;
        }
    }

    state parse_packet_out {
        packet.extract(hdr.packet_out);
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type){
            ETHERTYPE_ARP: parse_arp;
            ETHERTYPE_IPV4: parse_ipv4;
            ETHERTYPE_IPV6: parse_ipv6;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        local_metadata.ip_proto = hdr.ipv4.protocol;
        //Need header verification?
        transition select(hdr.ipv4.protocol) {
            PROTO_TCP: parse_tcp;
            PROTO_UDP: parse_udp;
            PROTO_ICMP: parse_icmp;
            default: accept;
        }
    }

    state parse_ipv6 {
        packet.extract(hdr.ipv6);
        local_metadata.ip_proto = hdr.ipv6.next_hdr;
        transition select(hdr.ipv6.next_hdr) {
            PROTO_HBH: parse_hbh;
            PROTO_IPV6: parse_ipv6_inner;
            PROTO_TCP: parse_tcp;
            PROTO_UDP: parse_udp;
            PROTO_ICMPV6: parse_icmpv6;
            PROTO_SRH: parse_srh;
            default: accept;
        }
    }

    state parse_hbh {
        packet.extract(hdr.ipv6_hbh);

        transition select(hdr.ipv6_hbh.option_type) {
            HBH_OPT_PT: parse_ipv6_hbh_pt_stack;
            default: accept;
        }
    }

    state parse_ipv6_hbh_pt_stack {
        packet.extract(hdr.ipv6_hbh_pt_stack.next);

        bool next_mcd = local_metadata.num_pt_mcd < PT_MCD_STACK_HOPS - 1;
        local_metadata.num_pt_mcd = local_metadata.num_pt_mcd + 1;
        transition select(next_mcd) {
            true: parse_ipv6_hbh_pt_stack;
            false: parse_ipv6_hbh_next_hdr;
        } 
    }

    state parse_ipv6_hbh_next_hdr {
        transition select(hdr.ipv6_hbh.next_hdr) {
            PROTO_IPV6: parse_ipv6_inner;
            PROTO_TCP: parse_tcp;
            PROTO_UDP: parse_udp;
            PROTO_ICMPV6: parse_icmpv6;
            PROTO_SRH: parse_srh;
            default: accept;
        }
    }

    state parse_ipv6_inner {
        packet.extract(hdr.ipv6_inner);
        local_metadata.ip_proto = hdr.ipv6_inner.next_hdr;
        transition select(hdr.ipv6_inner.next_hdr) {
            PROTO_TCP: parse_tcp;
            PROTO_UDP: parse_udp;
            PROTO_ICMPV6: parse_icmpv6;
            PROTO_SRH: parse_srh;
            default: accept;
        }
    }

    state parse_srh {
        packet.extract(hdr.srh);
        transition parse_srh_sid_list;
    }

    state parse_srh_sid_list {
        packet.extract(hdr.srh_sid_list.next);
        bool next_segment = (bit<32>)hdr.srh.segments_left - 1 == (bit<32>)hdr.srh_sid_list.lastIndex;
        transition select(next_segment) {
            true: mark_current_srv6;
            _: check_last_srv6;
        }
    }

    state mark_current_srv6 {
        // current metadata
        local_metadata.next_srv6_sid = hdr.srh_sid_list.last.sid;
        transition check_last_srv6;
    }

    state check_last_srv6 {
        // working with bit<8> and int<32> which cannot be cast directly; using bit<32> as common intermediate type for comparision
        bool last_segment = (bit<32>)hdr.srh.last_entry == (bit<32>)hdr.srh_sid_list.lastIndex;
        transition select(last_segment) {
           true: check_srv6_tlv;
           false: parse_srh_sid_list;
        }
    }

    state check_srv6_tlv {
        bool has_tlv = hdr.srh.hdr_ext_len > ((hdr.srh.last_entry + 1) * 2);
        transition select(has_tlv) {
            true: parse_srh_tlv;
            false: parse_srh_next_hdr;
        }
    }

    state parse_srh_tlv {
        packet.extract(hdr.srh_tlv);

        transition select(hdr.srh_tlv.type) {
            SRH_PT_TLV_TYPE: parse_srh_pt_tlv;
        }
    }

    state parse_srh_pt_tlv {
        packet.extract(hdr.srh_pt_tlv);

        transition parse_srh_next_hdr;
    }

    state parse_srh_next_hdr {
        transition select(hdr.srh.next_hdr) {
            PROTO_TCP: parse_tcp;
            PROTO_UDP: parse_udp;
            PROTO_ICMPV6: parse_icmpv6;
            default: accept;
        }
    }

    state parse_arp {
        packet.extract(hdr.arp);
        transition accept;
    }

    state parse_tcp {
        packet.extract(hdr.tcp);
        local_metadata.l4_src_port = hdr.tcp.src_port;
        local_metadata.l4_dst_port = hdr.tcp.dst_port;
        transition accept;
    }

    state parse_udp {
        packet.extract(hdr.udp);
        local_metadata.l4_src_port = hdr.udp.src_port;
        local_metadata.l4_dst_port = hdr.udp.dst_port;
        transition accept;
    }

    state parse_icmp {
        packet.extract(hdr.icmp);
        local_metadata.icmp_type = hdr.icmp.type;
        transition accept;
    }

    state parse_icmpv6 {
        packet.extract(hdr.icmpv6);
        local_metadata.icmp_type = hdr.icmpv6.type;
        transition select(hdr.icmpv6.type) {
            ICMP6_TYPE_NS: parse_ndp;
            ICMP6_TYPE_NA: parse_ndp;
            default: accept;
        }

    }

    state parse_ndp {
        packet.extract(hdr.ndp);
        transition parse_ndp_option;
    }

    state parse_ndp_option {
        packet.extract(hdr.ndp_option);
        transition accept;
    }
}

control DeparserImpl(packet_out packet, in parsed_headers_t hdr) {
    apply {
        packet.emit(hdr.packet_in);
        packet.emit(hdr.ethernet);
        packet.emit(hdr.arp);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.ipv6);
        packet.emit(hdr.outer_srh);
        packet.emit(hdr.outer_srh_sid_list);
        packet.emit(hdr.outer_srh_tlv);
        packet.emit(hdr.srh_pt_tlv);
        packet.emit(hdr.ipv6_inner);
        packet.emit(hdr.ipv6_hbh);
        packet.emit(hdr.ipv6_hbh_pt_stack);
        packet.emit(hdr.srh);
        packet.emit(hdr.srh_sid_list);
        packet.emit(hdr.srh_tlv);
        packet.emit(hdr.tcp);
        packet.emit(hdr.udp);
        packet.emit(hdr.icmp);
        packet.emit(hdr.icmpv6);
        packet.emit(hdr.ndp);
        packet.emit(hdr.ndp_option);
    }
}

#endif
