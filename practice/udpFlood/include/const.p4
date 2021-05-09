// typedef
typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

/* EtherType */
const bit<16> TYPE_IPV4     = 0x0800;   // Internet Protocol version 4 (IPv4)

/* IP protocol number */
const bit<8>  PROTO_ICMP    = 1;        // Internet Control Message Protocol (ICMP)
const bit<8>  PROTO_IPV4    = 4;        // IPv4 Encapsulation
const bit<8>  PROTO_TCP     = 6;        // Transmission Control Protocol (TCP)
const bit<8>  PROTO_UDP     = 17;       // User Datagram Protocol (UDP)
const bit<8>  PROTO_IPV6    = 41;       // IPv6 Encapsulation

/* Meter Color const */
const bit<32> METER_GREEN   = 0;
const bit<32> METER_YELLOW  = 1;
const bit<32> METER_RED     = 2;

/* Meter const */
#define MAX_PORT 1023
#define TABLE_SIZE 1023