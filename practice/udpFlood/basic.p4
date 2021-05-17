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
    bit<1>value;
    bit<5>ActivePorts;
    /* 
        Register for Flow info 
            allocates storage for 64 values, each with type bit<32>.
    */
    register<bit<REGISTER_WIDTH>>(REGISTER_ENTRIES) reg;
    /* 
        Register for record number of active port
    */
    register<bit<1>>(MAX_PORT+1) active_port;
    register<bit<5>>(1) num_active_ports;
    /* 
        Register for time
    */
    register<bit<48>>(1) timestamp_reg;
    // Counter
    counter((bit<32>)MAX_PORT+1, CounterType.bytes) ingressPortCounter;
    // Counter
    counter((bit<32>)1, CounterType.bytes) MonitorCounter;
    // Meter
    meter((MAX_PORT+1), MeterType.packets) my_meter;

    // action
    action anomaly_traffic_digest(){
        num_active_ports.read(ActivePorts, 0);
        digest<anomaly_digest>((bit<32>)1024,{
            (bit<32>)standard_metadata.ingress_port,
            standard_metadata.ingress_global_timestamp
        });
    }
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
    action read_timestamp(){
        meta.cur_timestamp = standard_metadata.ingress_global_timestamp;
        timestamp_reg.read(meta.last_timestamp, 0);
    }
    action update_flow_in_reg(){
        reg.read(meta.reg_data, (bit<32>)standard_metadata.ingress_port);
        meta.reg_data = meta.reg_data + 1;
        reg.write((bit<32>)standard_metadata.ingress_port, meta.reg_data);

        active_port.read(value, (bit<32>)standard_metadata.ingress_port);
        active_port.write((bit<32>)standard_metadata.ingress_port, 1);
    }
    action count_active_port(){
        num_active_ports.read(ActivePorts, 0);
        ActivePorts = ActivePorts + 1;
        num_active_ports.write(0, ActivePorts);
    }
    action write_timestamp(){
        timestamp_reg.write(0, standard_metadata.ingress_global_timestamp);
    }
    action reset_register(){
        // reset registers
        reg.write((bit<32>)standard_metadata.ingress_port, 0);
        active_port.write((bit<32>)0, 0);
        active_port.write((bit<32>)1, 0);
        active_port.write((bit<32>)2, 0);
        active_port.write((bit<32>)3, 0);
        active_port.write((bit<32>)4, 0);
        active_port.write((bit<32>)5, 0);
        active_port.write((bit<32>)6, 0);
        active_port.write((bit<32>)7, 0);
        active_port.write((bit<32>)8, 0);
        active_port.write((bit<32>)9, 0);
        active_port.write((bit<32>)10, 0);
        active_port.write((bit<32>)11, 0);
        active_port.write((bit<32>)12, 0);
        active_port.write((bit<32>)13, 0);
        active_port.write((bit<32>)14, 0);
        active_port.write((bit<32>)15, 0);
        num_active_ports.write(0, 0);
    }
    action ingress_meter_action(){
        my_meter.execute_meter((bit<32>)standard_metadata.ingress_port, meta.meter_tag);
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
            ipv4_lpm.apply();

            if(hdr.udp.isValid()){
                update_flow_in_reg();
                if(value == 0){
                    count_active_port();
                }
                // calculate time
                read_timestamp();

                // if flow traffic is suspected( >=MAX_PACKET_THRESHOLD ), digest to controller
                if(meta.reg_data >= MAX_PACKET_THRESHOLD){
                    anomaly_traffic_digest();
                    reset_register();
                }

                // if time delta >= 1s,  reset register
                if(meta.cur_timestamp - meta.last_timestamp >= 1000000){
                    reset_register();
                }
                write_timestamp();

                // Counter
                ingressPortCounter.count((bit<32>)standard_metadata.ingress_port);
                // Counter for Monitor h2 Traffic on s1
                if(hdr.ipv4.srcAddr != 0x0b030601 && standard_metadata.ingress_port == 2){
                    MonitorCounter.count(0);
                }
                // Meter
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
