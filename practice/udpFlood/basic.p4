/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>
// const
#include "./include/const.p4"
// headers
#include "./include/headers.p4"

/********************** P A R S E R  ***********************************/

parser MyParser(
    packet_in packet,
    out headers hdr,
    inout metadata meta,
    inout standard_metadata_t standard_metadata
) {

    state start {
        transition parse_ethernet;
    }
    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            // if ethernet.etherType == 0x0800 -> parse_ipv4 state
            TYPE_IPV4:  parse_ipv4;
            default:    accept;
        }
    }
    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            PROTO_UDP:  parse_udp;
            default:    accept;
        }
    }
    state parse_udp {
        packet.extract(hdr.udp);
        transition accept;
    }
}

/***********   C H E C K S U M    V E R I F I C A T I O N   *************/

control MyVerifyChecksum(
    inout headers hdr, 
    inout metadata meta
) {   
    apply {  }
}


/*************  I N G R E S S   P R O C E S S I N G   *******************/

control MyIngress(
    inout headers hdr, 
    inout metadata meta, 
    inout standard_metadata_t standard_metadata
) {
    // Register
    //      allocates storage for 64 values, each with type bit<32>.
    register<bit<BLOOM_FILTER_BIT_WIDTH>>(BLOOM_FILTER_ENTRIES) bloom_filter_1;
    register<bit<BLOOM_FILTER_BIT_WIDTH>>(BLOOM_FILTER_ENTRIES) bloom_filter_2;
    // Counter
    counter((bit<32>)MAX_PORT+1, CounterType.bytes) ingressPortCounter;
    // Meter
    meter((MAX_PORT+1), MeterType.packets) my_meter;
    
    // action
    action drop() {
        mark_to_drop(standard_metadata);
    }
    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        // Sets the egress port for the next hop
        standard_metadata.egress_spec = port;
        // Updates the ethernet destination address with the address of the next hop
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        // Updates the ethernet source address with the address of the switch
        hdr.ethernet.dstAddr = dstAddr;
        // Decrements the TTL
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }
    action m_action(bit<32> meter_idx) {
        my_meter.execute_meter((bit<32>)meter_idx, meta.meter_tag);
    }      
    action ingress_meter_action(){
        my_meter.execute_meter((bit<32>)standard_metadata.ingress_port, meta.meter_tag);
    }
    action anomaly_traffic_digest(){
        digest<anomaly_digest>((bit<32>)1024,{
            (bit<32>)standard_metadata.ingress_port,
            meta.counter_one,
            meta.counter_two,
            standard_metadata.ingress_global_timestamp
        });
    }
    action update_bloom_filter(){
       //Get register position
       hash(
           meta.output_hash_one, HashAlgorithm.crc16, (bit<16>)0, {standard_metadata.ingress_port}, (bit<32>)BLOOM_FILTER_ENTRIES
        );

       hash(
           meta.output_hash_two, HashAlgorithm.crc32, (bit<16>)0, {standard_metadata.ingress_port}, (bit<32>)BLOOM_FILTER_ENTRIES
        );

        //Read counters
        bloom_filter_1.read(meta.counter_one, meta.output_hash_one);
        bloom_filter_2.read(meta.counter_two, meta.output_hash_two);

        meta.counter_one = meta.counter_one + 1;
        meta.counter_two = meta.counter_two + 1;

        //write counters
        bloom_filter_1.write(meta.output_hash_one, meta.counter_one);
        bloom_filter_2.write(meta.output_hash_two, meta.counter_two);
    }

    // tables
    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
        size = TABLE_SIZE;
        default_action = drop();
    }
    table color_action {
        key = {
            meta.meter_tag                  : exact;
        }
        actions = {
            drop;
            NoAction;
        }
        const entries = {
            METER_GREEN     : NoAction();
            METER_YELLOW    : NoAction();
            METER_RED       : drop();
        }
        // size = TABLE_SIZE;
        const default_action = NoAction();
    }
    table debug {
        key = {
            hdr.ipv4.srcAddr                : exact;
            meta.meter_tag                  : exact;
            standard_metadata.ingress_port  : exact;
        }
        actions = {
            NoAction;
        }
        size = 1 ;
        default_action = NoAction();
    }

    apply {
        // only if the header ipv4 is valid
        if (hdr.ipv4.isValid()) {
            // apply table
            ipv4_lpm.apply();
            // test digest
            if(hdr.udp.isValid()){
                // m_table.apply();
                update_bloom_filter();
                if(meta.counter_one >= MAX_PACKET_THRESHOLD && meta.counter_two >= MAX_PACKET_THRESHOLD){
                    anomaly_traffic_digest();
                }
                ingressPortCounter.count((bit<32>)standard_metadata.ingress_port);
                ingress_meter_action();
                color_action.apply();
            }
            debug.apply();
        }
    }
}

/***************  E G R E S S   P R O C E S S I N G   ******************/

control MyEgress(
    inout headers hdr,
    inout metadata meta,
    inout standard_metadata_t standard_metadata
) {
    // Counter
    counter((bit<32>)MAX_PORT+1, CounterType.bytes) egressPortCounter;
    apply { 
        egressPortCounter.count((bit<32>)standard_metadata.egress_port);
    }
}

/************   C H E C K S U M    C O M P U T A T I O N   *************/

control MyComputeChecksum(
    inout headers  hdr, 
    inout metadata meta
) {
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
            HashAlgorithm.csum16
        );
    }
}

/**********************  D E P A R S E R  *******************************/

control MyDeparser(
    packet_out packet, 
    in headers hdr
) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.udp);
    }
}

/**********************  S W I T C H  ***********************************/

V1Switch(
    MyParser(),
    MyVerifyChecksum(),
    MyIngress(),
    MyEgress(),
    MyComputeChecksum(),
    MyDeparser()
) main;
