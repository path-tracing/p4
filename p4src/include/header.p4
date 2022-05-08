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

#ifndef __HEADER__
#define __HEADER__

#include "define.p4"

#define SRH_MSD 4
#define PT_MCD_STACK_HOPS 12

@controller_header("packet_in")
header packet_in_header_t {
    port_num_t ingress_port;
    bit<7> _pad;
}

@controller_header("packet_out")
header packet_out_header_t {
    port_num_t egress_port;
    bit<7> _pad;
}

header ethernet_t {
    mac_addr_t dst_addr;
    mac_addr_t src_addr;
    bit<16> ether_type;
}

header ipv4_t {
    bit<4> version;
    bit<4> ihl;
    bit<6> dscp;
    bit<2> ecn;
    bit<16> total_len;
    bit<16> identification;
    bit<3> flags;
    bit<13> frag_offset;
    bit<8> ttl;
    bit<8> protocol;
    bit<16> hdr_checksum;
    bit<32> src_addr;
    bit<32> dst_addr;
}

header ipv6_t {
    bit<4> version;
    bit<8> traffic_class;
    bit<20> flow_label;
    bit<16> payload_len;
    bit<8> next_hdr;
    bit<8> hop_limit;
    bit<128> src_addr;
    bit<128> dst_addr;
}

header ipv6_hbh_t {
    bit<8> next_hdr;
    bit<8> hdr_ext_len;
    bit<8> option_type;
    bit<8> option_len;
}

header ipv6_hbh_pt_stack_t {
    bit<12> oif;
    bit<4> oil;
    bit<8> tts;
}

header srh_t {
    bit<8> next_hdr;
    bit<8> hdr_ext_len;
    bit<8> routing_type;
    bit<8> segments_left;
    bit<8> last_entry;
    bit<8> flags;
    bit<16> tag;
}

header srh_sid_list_t {
    bit<128> sid;
}

header srh_tlv_t {
    bit<8> type;
    bit<8> len;
}

header srh_pt_tlv_t {
    bit<12> if_id;
    bit<4> if_ld;
    bit<64> t64;
    bit<16> session_id;
    bit<16> seq_num;
}

header arp_t {
    bit<16> hw_type;
    bit<16> proto_type;
    bit<8> hw_addr_len;
    bit<8> proto_addr_len;
    bit<16> opcode;
}

header tcp_t {
    bit<16> src_port;
    bit<16> dst_port;
    bit<32> seq_no;
    bit<32> ack_no;
    bit<4>  data_offset;
    bit<3>  res;
    bit<3>  ecn;
    bit<6>  ctrl;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgent_ptr;
}

header udp_t {
    bit<16> src_port;
    bit<16> dst_port;
    bit<16> len;
    bit<16> checksum;
}

header icmp_t {
    bit<8> type;
    bit<8> icmp_code;
    bit<16> checksum;
    bit<16> identifier;
    bit<16> sequence_number;
    bit<64> timestamp;
}

header icmpv6_t {
    bit<8> type;
    bit<8> code;
    bit<16> checksum;
}

header ndp_t {
    bit<32> flags;
    bit<128> target_addr;
}

header ndp_option_t {
    bit<8> type;
    bit<8> length;
    bit<48> value;
}

//Custom metadata definition
struct local_metadata_t {
    bool is_multicast;
    bool skip_l2;
    ipv6_addr_t next_srv6_sid;
    bit<8> ip_proto;
    bit<8> icmp_type;
    l4_port_t l4_src_port;
    l4_port_t l4_dst_port;
    bit<12> mapped_port;
    bool is_ingress;
    bool is_encap;
    bit<8> num_pt_mcd;
}

struct parsed_headers_t {
    ethernet_t ethernet;
    ipv4_t ipv4;
    ipv6_t ipv6;
    srh_t outer_srh;
    srh_sid_list_t[SRH_MSD] outer_srh_sid_list;
    srh_tlv_t outer_srh_tlv;
    srh_pt_tlv_t outer_srh_pt_tlv;
    ipv6_t ipv6_inner;
    ipv6_hbh_t ipv6_hbh;
    ipv6_hbh_pt_stack_t[PT_MCD_STACK_HOPS] ipv6_hbh_pt_stack;
    srh_t srh;
    srh_sid_list_t[SRH_MSD] srh_sid_list;
    srh_tlv_t srh_tlv;
    srh_pt_tlv_t srh_pt_tlv;
    arp_t arp;
    tcp_t tcp;
    udp_t udp;
    icmp_t icmp;
    icmpv6_t icmpv6;
    ndp_t ndp;
    ndp_option_t ndp_option;
    packet_out_header_t packet_out;
    packet_in_header_t packet_in;
}

#endif
