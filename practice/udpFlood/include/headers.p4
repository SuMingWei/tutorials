/* Ethernet */
header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

/* Internet Protocol version 4 (IPv4) */
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

/* User Datagram Protocol (UDP) */
header udp_t {
    bit<16> srcPort;                // Source Port Number
    bit<16> dstPort;                // Destination Port Number
    bit<16> len;                    // Length
    bit<16> checksum;               // Checksum
}

// metadata for Meter
struct metadata {
    bit<32>     meter_tag;
    bit<32>     reg_data;
    // bit<32>     output_hash_one;
    // bit<32>     output_hash_two;
    // bit<32>     counter_one;
    // bit<32>     counter_two;
    // time calculation
    bit<48> cur_timestamp;
    bit<48> last_timestamp;
}

// struct for digest
struct anomaly_digest {
    bit<32> Suspected_ingressPort;
    bit<48> timestamp;
}

struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
    udp_t        udp;
}