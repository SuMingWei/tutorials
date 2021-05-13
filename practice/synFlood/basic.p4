/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;
const bit<8>  PROTO_TCP  = 6;

#define BLOOM_FILTER_ENTRIES 4096
#define BLOOM_FILTER_BIT_WIDTH 3

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

header tcp_t{
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<4>  res;
    bit<8>  flags; // cwr | ece || urg | ack | psh | rst | syn |fin
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

// digest 
struct auth_digest{
    bit<32> IP;
    bit<16> port;
}

struct abnormal_digest{
    bit<32> IP;
    bit<16> port;
}

// metadata for calculate tcp checksum
struct metadata {
    bit<16> tcpLength;
}

struct headers {
    ethernet_t       ethernet;
    ipv4_t           ipv4;
    tcp_t            tcp;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        meta.tcpLength = hdr.ipv4.totalLen - 20;
        transition select(hdr.ipv4.protocol){
            PROTO_TCP: tcp;
            default: accept;
        }
    }

    state tcp {
       packet.extract(hdr.tcp);
       transition accept;
    }

}

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {   
    apply {  }
}

/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control BasicIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
    
    // for CBF
    register<bit<BLOOM_FILTER_BIT_WIDTH>>(BLOOM_FILTER_ENTRIES) bloom_filter_1;
    register<bit<BLOOM_FILTER_BIT_WIDTH>>(BLOOM_FILTER_ENTRIES) bloom_filter_2;
    bit<32> reg_pos_one; bit<32> reg_pos_two;
    bit<3> reg_val_one; bit<3> reg_val_two;
    // for syn cookie
    bit<48> tempMac;
    bit<32> tempIP;
    bit<16> tempPort;
    bit<32> cookie;
    
    // forwarding
    action drop() {
        mark_to_drop(standard_metadata);
    }
    
    action host_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    action tunnel_forward(egressSpec_t port){
        standard_metadata.egress_spec = port;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            host_forward;
            tunnel_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }

    // black list
    table drop_blacklist {
        key = {
            hdr.ipv4.srcAddr: lpm;
            hdr.tcp.srcPort: exact;
        }
        actions = {
            drop;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }

    // authentication
    action transfer(bit<32> key){
        // exchange ethernet address
        tempMac = hdr.ethernet.srcAddr;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = tempMac;
        // exchange ipv4 address
        tempIP = hdr.ipv4.srcAddr;
        hdr.ipv4.srcAddr = hdr.ipv4.dstAddr;
        hdr.ipv4.dstAddr = tempIP;
        // exchange TCP port
        tempPort = hdr.tcp.srcPort;
        hdr.tcp.srcPort = hdr.tcp.dstPort;
        hdr.tcp.dstPort = tempPort;
        // set TCP flag to syn/ack
        hdr.tcp.flags = (hdr.tcp.flags | 0b00010000);
        // calculate ACK num
        hdr.tcp.ackNo = hdr.tcp.seqNo + 1;
        // set cookie as SEQ num
        hdr.tcp.seqNo = key;
    }

    action validate(){
        // exchange ethernet address
        tempMac = hdr.ethernet.srcAddr;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = tempMac;
        // exchange ipv4 address
        tempIP = hdr.ipv4.srcAddr;
        hdr.ipv4.srcAddr = hdr.ipv4.dstAddr;
        hdr.ipv4.dstAddr = tempIP;
        // exchange TCP port
        tempPort = hdr.tcp.srcPort;
        hdr.tcp.srcPort = hdr.tcp.dstPort;
        hdr.tcp.dstPort = tempPort;
        // set TCP flag to syn/ack
        hdr.tcp.flags = 0b00000100;
        // set seq number
        hdr.tcp.seqNo = hdr.tcp.ackNo;
        // src & dst have been change
        digest<auth_digest>((bit<32>)1024,{
            hdr.ipv4.dstAddr,
            hdr.tcp.dstPort
        });
    }

    table authentication {
        key = {
            hdr.ipv4.srcAddr: ternary;
            hdr.tcp.srcPort: ternary;
            hdr.tcp.flags: ternary;
            hdr.tcp.ackNo: ternary;
        }
        actions = {
            transfer;
            validate;
            NoAction;
        }
        size = 2048;
        default_action = NoAction();
    }

    // white list
    action auth_forward(egressSpec_t port){
        standard_metadata.egress_spec = port;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    table pinhole {
        key = {
            hdr.ipv4.srcAddr: exact;
            hdr.tcp.srcPort: exact;
            hdr.ipv4.dstAddr: exact;
            hdr.tcp.dstPort: exact;
        }
        actions = {
            auth_forward;
            NoAction;
        }
        size = 2048;
        support_timeout = true;
        default_action = NoAction();
    }

    // CBF
    action compute_hashes(ip4Addr_t ipAddr1, ip4Addr_t ipAddr2, bit<16> port1, bit<16> port2){
       //Get register position
       hash(reg_pos_one, HashAlgorithm.crc16, (bit<32>)0, {ipAddr1,
                                                           ipAddr2,
                                                           port1,
                                                           port2,
                                                           hdr.ipv4.protocol},
                                                           (bit<32>)BLOOM_FILTER_ENTRIES);

       hash(reg_pos_two, HashAlgorithm.crc32, (bit<32>)0, {ipAddr1,
                                                           ipAddr2,
                                                           port1,
                                                           port2,
                                                           hdr.ipv4.protocol},
                                                           (bit<32>)BLOOM_FILTER_ENTRIES);
    }

    action abnormal(){
        // dst is the client in synack pkt
        digest<abnormal_digest>((bit<32>)1024,{
            hdr.ipv4.dstAddr,
            hdr.tcp.dstPort
        });
    }
    
    apply {
        if(hdr.ipv4.isValid()){
            if(drop_blacklist.apply().hit){
                return;
            }
            if(pinhole.apply().hit){
                // use hping3 will get a rst after a syn/ack,
                // (since hping3 won't reply any response)
                // so drop the rst for the server to resend syn/ack
                if(hdr.tcp.flags == 0b00000100){ 
                    drop();
                }
                // use counting bloom filter to cout the syn & syn/ack
                // syn
                if(hdr.tcp.flags == 0b00000010){
                    compute_hashes(hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.tcp.srcPort, hdr.tcp.dstPort);
                    // initial is 6 (1(first)+5(retransmitt))
                    bloom_filter_1.write(reg_pos_one, 6);
                    bloom_filter_2.write(reg_pos_two, 6);
                }// syn/ack
                else if(hdr.tcp.flags == 0b00010010){
                    compute_hashes(hdr.ipv4.dstAddr, hdr.ipv4.srcAddr, hdr.tcp.dstPort, hdr.tcp.srcPort); 
                    
                    bloom_filter_1.read(reg_val_one, reg_pos_one);
                    bloom_filter_2.read(reg_val_two, reg_pos_two); 
                    
                    if (reg_val_one < 4 && reg_val_two < 4){
                        // abnormal
                        abnormal();
                    }else{
                        bloom_filter_1.write(reg_pos_one, reg_val_one - 1);
                        bloom_filter_2.write(reg_pos_two, reg_val_two - 1);
                    }
                }
                
                return;
            }
            if(hdr.tcp.isValid()){
                // authentication
                authentication.apply();
            }    
            // general forwarding  
            ipv4_lpm.apply();
        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {

    apply{}
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
    apply {
        update_checksum(
            hdr.ipv4.isValid(),
            { 
                hdr.ipv4.version,
                hdr.ipv4.ihl,
                hdr.ipv4.diffserv,
                hdr.ipv4.totalLen,
                hdr.ipv4.identification,
                hdr.ipv4.flags,
                hdr.ipv4.fragOffset,
                hdr.ipv4.ttl,
                hdr.ipv4.protocol,
                hdr.ipv4.srcAddr,
                hdr.ipv4.dstAddr 
            },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
        

        update_checksum_with_payload(
            hdr.tcp.isValid(),
            { 
                hdr.ipv4.srcAddr,
                hdr.ipv4.dstAddr,                
                8w0,
                hdr.ipv4.protocol,
                meta.tcpLength,
                hdr.tcp.srcPort,
                hdr.tcp.dstPort,
                hdr.tcp.seqNo,
                hdr.tcp.ackNo,
                hdr.tcp.dataOffset,
                hdr.tcp.res,
                hdr.tcp.flags,
                hdr.tcp.window,
                hdr.tcp.urgentPtr
            },
            hdr.tcp.checksum,
            HashAlgorithm.csum16);
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
BasicIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
