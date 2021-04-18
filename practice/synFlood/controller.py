#!/usr/bin/env python2
import argparse
import grpc
import os
import sys
from time import sleep

# Import P4Runtime lib from parent utils dir
# Probably there's a better way of doing this.
sys.path.append(
    os.path.join(os.path.dirname(os.path.abspath(__file__)),'../../utils/'))
import p4runtime_lib.bmv2
from p4runtime_lib.error_utils import printGrpcError
from p4runtime_lib.switch import ShutdownAllSwitchConnections
import p4runtime_lib.helper

SWITCH_TO_HOST_PORT = 1
SWITCH_TO_SWITCH_PORT = 2

# forward from switch to host
def writeHostForwardRules(p4info_helper,ingress_sw,dst_eth_addr,port,dst_ip_addr):
    # ingress rule
    table_entry = p4info_helper.buildTableEntry(
        table_name = "BasicIngress.ipv4_lpm",
        match_fields = {
            "hdr.ipv4.dstAddr":(dst_ip_addr,32)
        },
        action_name = "BasicIngress.host_forward",
        action_params = {
            "dstAddr":dst_eth_addr,
            "port":port
        }
    )
    # write into ingress of target switch
    ingress_sw.WriteTableEntry(table_entry)
    print "Install host ingress tunnel rule on %s" % ingress_sw.name

# forward from switch to switch
def writeTunnelForwardRules(p4info_helper,ingress_sw,port,dst_ip_addr,prefix):
    # ingress rule
    table_entry = p4info_helper.buildTableEntry(
        table_name = "BasicIngress.ipv4_lpm",
        match_fields = {
            "hdr.ipv4.dstAddr":(dst_ip_addr,prefix)
        },
        action_name = "BasicIngress.tunnel_forward",
        action_params = {
            "port":port
        }
    )
    # write into ingress of target switch
    ingress_sw.WriteTableEntry(table_entry)
    print "Install host ingress tunnel rule on %s" % ingress_sw.name

# drop packet
def writeDropForwardRules(p4info_helper,ingress_sw,port):
    table_entry = p4info_helper.buildTableEntry(
        table_name = "BasicIngress.drop_blacklist",
        match_fields = {
            "standard_metadata.ingress_port":port,
            "hdr.ipv4.dstAddr":("10.0.1.1",32)
        },
        action_name = "BasicIngress.drop",
    )
    # write into ingress of target switch
    ingress_sw.WriteTableEntry(table_entry)
    print "Install drop rule on %s port %s" % (ingress_sw.name,port)

# build connection with controller
def SendDigestEntry(p4info_helper,sw,digest_name=None):
    digest_entry = p4info_helper.buildDigestEntry(digest_name=digest_name)
    sw.WriteDigestEntry(digest_entry)
    print "send digestEntry via p4Runtime"

def readTableRules(p4info_helper, sw):
    """
    Reads the table entries from all tables on the switch.

    :param p4info_helper: the P4Info helper
    :param sw: the switch connection
    """
    print '\n----- Reading tables rules for %s -----' % sw.name
    for response in sw.ReadTableEntries():
        for entity in response.entities:
            entry = entity.table_entry
            # TODO For extra credit, you can use the p4info_helper to translate
            #      the IDs in the entry to names
            table_name = p4info_helper.get_tables_name(entry.table_id)
            print '%s: ' % table_name,
            for m in entry.match:
                print p4info_helper.get_match_field_name(table_name, m.field_id),
                print '%r' % (p4info_helper.get_match_field_value(m),),
            action = entry.action.action
            action_name = p4info_helper.get_actions_name(action.action_id)
            print '->', action_name,
            for p in action.params:
                print p4info_helper.get_action_param_name(action_name, p.param_id),
                print '%r' % p.value,
            print

def printCounter(p4info_helper, sw, counter_name, index):
    """
    Reads the specified counter at the specified index from the switch. In our
    program, the index is the tunnel ID. If the index is 0, it will return all
    values from the counter.

    :param p4info_helper: the P4Info helper
    :param sw:  the switch connection
    :param counter_name: the name of the counter from the P4 program
    :param index: the counter index (in our case, the tunnel ID)
    """
    for response in sw.ReadCounters(p4info_helper.get_counters_id(counter_name), index):
        for entity in response.entities:
            counter = entity.counter_entry
            print "%s %s %d: %d packets (%d bytes)" % (
                sw.name, counter_name, index,
                counter.data.packet_count, counter.data.byte_count
            )

def printGrpcError(e):
    print "gRPC Error:", e.details(),
    status_code = e.code()
    print "(%s)" % status_code.name,
    traceback = sys.exc_info()[2]
    print "[%s:%d]" % (traceback.tb_frame.f_code.co_filename, traceback.tb_lineno)

# convert ascii to string
def prettify(IP_string):
    return '.'.join('%d' % ord(b) for b in IP_string)

# convert ascii to integer
def int_prettify(int_string):
    return int(''.join('%d' % ord(b) for b in int_string))

def main(p4info_file_path, bmv2_file_path):
    # Instantiate a P4Runtime helper from the p4info file
    p4info_helper = p4runtime_lib.helper.P4InfoHelper(p4info_file_path)

    try:
        # Create a switch connection object for s1 and s2;
        # this is backed by a P4Runtime gRPC connection.
        # Also, dump all P4Runtime messages sent to switch to given txt files.
        s1 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name='s1',
            address='127.0.0.1:50051',
            device_id=0,
            proto_dump_file='logs/s1-p4runtime-requests.txt')
        s2 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name='s2',
            address='127.0.0.1:50052',
            device_id=1,
            proto_dump_file='logs/s2-p4runtime-requests.txt')
        s3 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name='s3',
            address='127.0.0.1:50053',
            device_id=2,
            proto_dump_file='logs/s3-p4runtime-requests.txt')
        s4 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name='s4',
            address='127.0.0.1:50054',
            device_id=3,
            proto_dump_file='logs/s4-p4runtime-requests.txt')
        s5 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name='s5',
            address='127.0.0.1:50055',
            device_id=4,
            proto_dump_file='logs/s5-p4runtime-requests.txt')
        s6 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name='s6',
            address='127.0.0.1:50056',
            device_id=5,
            proto_dump_file='logs/s6-p4runtime-requests.txt')
        s7 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name='s7',
            address='127.0.0.1:50057',
            device_id=6,
            proto_dump_file='logs/s7-p4runtime-requests.txt')
        s8 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name='s8',
            address='127.0.0.1:50058',
            device_id=7,
            proto_dump_file='logs/s8-p4runtime-requests.txt')
        s9 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name='s9',
            address='127.0.0.1:50059',
            device_id=8,
            proto_dump_file='logs/s9-p4runtime-requests.txt')
        s10 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name='s10',
            address='127.0.0.1:50060',
            device_id=9,
            proto_dump_file='logs/s10-p4runtime-requests.txt')
        s11 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name='s11',
            address='127.0.0.1:50061',
            device_id=10,
            proto_dump_file='logs/s11-p4runtime-requests.txt')
        s12 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name='s12',
            address='127.0.0.1:50062',
            device_id=11,
            proto_dump_file='logs/s12-p4runtime-requests.txt')
        s13 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name='s13',
            address='127.0.0.1:50063',
            device_id=12,
            proto_dump_file='logs/s13-p4runtime-requests.txt')
        s14 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name='s14',
            address='127.0.0.1:50064',
            device_id=13,
            proto_dump_file='logs/s14-p4runtime-requests.txt')
        s15 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name='s15',
            address='127.0.0.1:50065',
            device_id=14,
            proto_dump_file='logs/s15-p4runtime-requests.txt')
        s16 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name='s16',
            address='127.0.0.1:50066',
            device_id=15,
            proto_dump_file='logs/s16-p4runtime-requests.txt')
        s17 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name='s17',
            address='127.0.0.1:50067',
            device_id=16,
            proto_dump_file='logs/s17-p4runtime-requests.txt')

        # Send master arbitration update message to establish this controller as
        # master (required by P4Runtime before performing any other write operation)
        s1.MasterArbitrationUpdate()
        s2.MasterArbitrationUpdate()
        s3.MasterArbitrationUpdate()
        s4.MasterArbitrationUpdate()
        s5.MasterArbitrationUpdate()
        s6.MasterArbitrationUpdate()
        s7.MasterArbitrationUpdate()
        s8.MasterArbitrationUpdate()
        s9.MasterArbitrationUpdate()
        s10.MasterArbitrationUpdate()
        s11.MasterArbitrationUpdate()
        s12.MasterArbitrationUpdate()
        s13.MasterArbitrationUpdate()
        s14.MasterArbitrationUpdate()
        s15.MasterArbitrationUpdate()
        s16.MasterArbitrationUpdate()
        s17.MasterArbitrationUpdate()

        # Install the P4 program on the switches
        s1.SetForwardingPipelineConfig(p4info=p4info_helper.p4info,
                                       bmv2_json_file_path=bmv2_file_path)
        s2.SetForwardingPipelineConfig(p4info=p4info_helper.p4info,
                                       bmv2_json_file_path=bmv2_file_path)
        s3.SetForwardingPipelineConfig(p4info=p4info_helper.p4info,
                                       bmv2_json_file_path=bmv2_file_path)
        s4.SetForwardingPipelineConfig(p4info=p4info_helper.p4info,
                                       bmv2_json_file_path=bmv2_file_path)
        s5.SetForwardingPipelineConfig(p4info=p4info_helper.p4info,
                                       bmv2_json_file_path=bmv2_file_path)
        s6.SetForwardingPipelineConfig(p4info=p4info_helper.p4info,
                                       bmv2_json_file_path=bmv2_file_path)
        s7.SetForwardingPipelineConfig(p4info=p4info_helper.p4info,
                                       bmv2_json_file_path=bmv2_file_path)
        s8.SetForwardingPipelineConfig(p4info=p4info_helper.p4info,
                                       bmv2_json_file_path=bmv2_file_path)
        s9.SetForwardingPipelineConfig(p4info=p4info_helper.p4info,
                                       bmv2_json_file_path=bmv2_file_path)
        s10.SetForwardingPipelineConfig(p4info=p4info_helper.p4info,
                                       bmv2_json_file_path=bmv2_file_path)
        s11.SetForwardingPipelineConfig(p4info=p4info_helper.p4info,
                                       bmv2_json_file_path=bmv2_file_path)
        s12.SetForwardingPipelineConfig(p4info=p4info_helper.p4info,
                                       bmv2_json_file_path=bmv2_file_path)
        s13.SetForwardingPipelineConfig(p4info=p4info_helper.p4info,
                                       bmv2_json_file_path=bmv2_file_path)
        s14.SetForwardingPipelineConfig(p4info=p4info_helper.p4info,
                                       bmv2_json_file_path=bmv2_file_path)
        s15.SetForwardingPipelineConfig(p4info=p4info_helper.p4info,
                                       bmv2_json_file_path=bmv2_file_path)
        s16.SetForwardingPipelineConfig(p4info=p4info_helper.p4info,
                                       bmv2_json_file_path=bmv2_file_path)
        s17.SetForwardingPipelineConfig(p4info=p4info_helper.p4info,
                                       bmv2_json_file_path=bmv2_file_path)
        print "Installed P4 Program using SetForwardingPipelineConfig on s1 - s17"

        # Write the forwarding rules
        # from switch to host
        writeHostForwardRules(p4info_helper, ingress_sw=s1,
                            dst_eth_addr="08:00:00:00:10:01",port=1,dst_ip_addr="10.0.1.1")
        writeHostForwardRules(p4info_helper, ingress_sw=s6,      
                            dst_eth_addr="08:00:00:00:11:00",port=2,dst_ip_addr="11.0.0.1")
        writeHostForwardRules(p4info_helper, ingress_sw=s7,      
                            dst_eth_addr="08:00:00:00:11:01",port=2,dst_ip_addr="11.0.1.1")
        writeHostForwardRules(p4info_helper, ingress_sw=s8,      
                            dst_eth_addr="08:00:00:00:11:02",port=2,dst_ip_addr="11.0.2.1")
        writeHostForwardRules(p4info_helper, ingress_sw=s9,      
                            dst_eth_addr="08:00:00:00:11:10",port=2,dst_ip_addr="11.1.0.1")
        writeHostForwardRules(p4info_helper, ingress_sw=s10,     
                            dst_eth_addr="08:00:00:00:11:11",port=2,dst_ip_addr="11.1.1.1")
        writeHostForwardRules(p4info_helper, ingress_sw=s11,     
                            dst_eth_addr="08:00:00:00:11:12",port=2,dst_ip_addr="11.1.2.1")
        writeHostForwardRules(p4info_helper, ingress_sw=s12,     
                            dst_eth_addr="08:00:00:00:11:20",port=2,dst_ip_addr="11.2.0.1")
        writeHostForwardRules(p4info_helper, ingress_sw=s13,     
                            dst_eth_addr="08:00:00:00:11:21",port=2,dst_ip_addr="11.2.1.1")
        writeHostForwardRules(p4info_helper, ingress_sw=s14,     
                            dst_eth_addr="08:00:00:00:11:22",port=2,dst_ip_addr="11.2.2.1")
        writeHostForwardRules(p4info_helper, ingress_sw=s15,
                            dst_eth_addr="08:00:00:00:11:03",port=2,dst_ip_addr="11.0.3.1")
        # from host to host
        # s1
        writeTunnelForwardRules(p4info_helper,ingress_sw=s1,port=2,dst_ip_addr="11.0.0.0",prefix=8)

        # s2
        writeTunnelForwardRules(p4info_helper,ingress_sw=s2,port=1,dst_ip_addr="10.0.0.0",prefix=8)
        writeTunnelForwardRules(p4info_helper,ingress_sw=s2,port=2,dst_ip_addr="11.0.0.0",prefix=16)
        writeTunnelForwardRules(p4info_helper,ingress_sw=s2,port=3,dst_ip_addr="11.1.0.0",prefix=16)
        writeTunnelForwardRules(p4info_helper,ingress_sw=s2,port=4,dst_ip_addr="11.2.0.0",prefix=16)

        # s3
        writeTunnelForwardRules(p4info_helper,ingress_sw=s3,port=1,dst_ip_addr='10.0.0.0',prefix=8)
        writeTunnelForwardRules(p4info_helper,ingress_sw=s3,port=1,dst_ip_addr='11.1.0.0',prefix=16)
        writeTunnelForwardRules(p4info_helper,ingress_sw=s3,port=1,dst_ip_addr='11.2.0.0',prefix=16)
        writeTunnelForwardRules(p4info_helper,ingress_sw=s3,port=2,dst_ip_addr='11.0.0.0',prefix=24)
        writeTunnelForwardRules(p4info_helper,ingress_sw=s3,port=3,dst_ip_addr='11.0.1.0',prefix=24)
        writeTunnelForwardRules(p4info_helper,ingress_sw=s3,port=4,dst_ip_addr='11.0.2.0',prefix=24)
        writeTunnelForwardRules(p4info_helper,ingress_sw=s3,port=5,dst_ip_addr='11.0.3.0',prefix=24)

        # s4
        writeTunnelForwardRules(p4info_helper,ingress_sw=s4,port=1,dst_ip_addr='10.0.0.0',prefix=8)
        writeTunnelForwardRules(p4info_helper,ingress_sw=s4,port=1,dst_ip_addr='11.0.0.0',prefix=16)
        writeTunnelForwardRules(p4info_helper,ingress_sw=s4,port=1,dst_ip_addr='11.2.0.0',prefix=16)
        writeTunnelForwardRules(p4info_helper,ingress_sw=s4,port=2,dst_ip_addr='11.1.0.0',prefix=24)
        writeTunnelForwardRules(p4info_helper,ingress_sw=s4,port=3,dst_ip_addr='11.1.1.0',prefix=24)
        writeTunnelForwardRules(p4info_helper,ingress_sw=s4,port=4,dst_ip_addr='11.1.2.0',prefix=24)

        # s5
        writeTunnelForwardRules(p4info_helper,ingress_sw=s5,port=1,dst_ip_addr="10.0.0.0",prefix=8)
        writeTunnelForwardRules(p4info_helper,ingress_sw=s5,port=1,dst_ip_addr="11.0.0.0",prefix=16)
        writeTunnelForwardRules(p4info_helper,ingress_sw=s5,port=1,dst_ip_addr="11.1.0.0",prefix=16)
        writeTunnelForwardRules(p4info_helper,ingress_sw=s5,port=2,dst_ip_addr="11.2.0.0",prefix=24)
        writeTunnelForwardRules(p4info_helper,ingress_sw=s5,port=3,dst_ip_addr="11.2.1.0",prefix=24)
        writeTunnelForwardRules(p4info_helper,ingress_sw=s5,port=4,dst_ip_addr="11.2.2.0",prefix=24)

        # s6-s15 only connect to server(target)
        writeTunnelForwardRules(p4info_helper,ingress_sw=s6,port=1,dst_ip_addr="10.0.0.0",prefix=8)
        writeTunnelForwardRules(p4info_helper,ingress_sw=s7,port=1,dst_ip_addr="10.0.0.0",prefix=8)
        writeTunnelForwardRules(p4info_helper,ingress_sw=s8,port=1,dst_ip_addr="10.0.0.0",prefix=8)
        writeTunnelForwardRules(p4info_helper,ingress_sw=s9,port=1,dst_ip_addr="10.0.0.0",prefix=8)
        writeTunnelForwardRules(p4info_helper,ingress_sw=s10,port=1,dst_ip_addr="10.0.0.0",prefix=8)
        writeTunnelForwardRules(p4info_helper,ingress_sw=s11,port=1,dst_ip_addr="10.0.0.0",prefix=8)
        writeTunnelForwardRules(p4info_helper,ingress_sw=s12,port=1,dst_ip_addr="10.0.0.0",prefix=8)
        writeTunnelForwardRules(p4info_helper,ingress_sw=s13,port=1,dst_ip_addr="10.0.0.0",prefix=8)
        writeTunnelForwardRules(p4info_helper,ingress_sw=s14,port=1,dst_ip_addr="10.0.0.0",prefix=8)
        writeTunnelForwardRules(p4info_helper,ingress_sw=s15,port=1,dst_ip_addr="10.0.0.0",prefix=8)

        # s16
        writeTunnelForwardRules(p4info_helper,ingress_sw=s16,port=1,dst_ip_addr="10.0.0.0",prefix=8)
        writeTunnelForwardRules(p4info_helper,ingress_sw=s16,port=2,dst_ip_addr="11.0.0.0",prefix=8)

        # s17
        writeTunnelForwardRules(p4info_helper,ingress_sw=s17,port=1,dst_ip_addr="10.0.0.0",prefix=8)
        writeTunnelForwardRules(p4info_helper,ingress_sw=s17,port=2,dst_ip_addr="11.0.0.0",prefix=8)

        # test digest
        SendDigestEntry(p4info_helper,sw=s1,digest_name="debug_digest")
        SendDigestEntry(p4info_helper,sw=s1,digest_name="check_digest")
        #SendDigestEntry(p4info_helper,sw=s2,digest_name="syn_ack_digest")

        blacklist = []

        while True:
            digests = s1.DigestList()
            print digests
            if digests.WhichOneof("update") == "digest":
                digest = digests.digest
                digest_name = p4info_helper.get_digests_name(digest.digest_id)
                if digest_name == "debug_digest":
                    srcIP = prettify(digest.data[0].struct.members[0].bitstring)
                    dstIP = prettify(digest.data[0].struct.members[1].bitstring)
                    PORT = int_prettify(digest.data[0].struct.members[2].bitstring)
                    TIMESTAMP = int_prettify(digest.data[0].struct.members[3].bitstring)
                    print "digest name: ", digest_name
                    print "get syn digest data: src_IP=",srcIP
                    print "get syn digest data: dst_IP=",dstIP
                    print "get syn digest data: ingress port=",PORT
                    print "get syn digest data: timestamp=",TIMESTAMP
                    print "=========================================="
                    # if "11.0.0.1" not in blacklist:
                    #     blacklist.append("11.0.0.1")
                    #     writeDropForwardRules(p4info_helper,ingress_sw=s6,port=2)
                elif digest_name == "check_digest":
                    dstIP = prettify(digest.data[0].struct.members[0].bitstring)
                    print "digest name: ", digest_name
                    print "get syn digest data: dst_IP=",dstIP
                    print "=========================================="

                
                    
                
            



        # TODO Uncomment the following two lines to read table entries from s1 and s2
        # readTableRules(p4info_helper, s2)
        # readTableRules(p4info_helper, s1)

        # Print the tunnel counters every 2 seconds
        # while True:
        #     sleep(2)
        #     print '\n----- Reading tunnel counters -----'
        #     printCounter(p4info_helper, s1, "MyIngress.ingressTunnelCounter", 100)
        #     printCounter(p4info_helper, s2, "MyIngress.egressTunnelCounter", 100)
        #     printCounter(p4info_helper, s2, "MyIngress.ingressTunnelCounter", 200)
        #     printCounter(p4info_helper, s1, "MyIngress.egressTunnelCounter", 200)

    except KeyboardInterrupt:
        print " Shutting down."
    except grpc.RpcError as e:
        printGrpcError(e)

    ShutdownAllSwitchConnections()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='P4Runtime Controller')
    parser.add_argument('--p4info', help='p4info proto in text format from p4c',
                        type=str, action="store", required=False,
                        default='./build/basic.p4.p4info.txt')
    parser.add_argument('--bmv2-json', help='BMv2 JSON file from p4c',
                        type=str, action="store", required=False,
                        default='./build/basic.json')
    args = parser.parse_args()

    if not os.path.exists(args.p4info):
        parser.print_help()
        print "\np4info file not found: %s\nHave you run 'make'?" % args.p4info
        parser.exit(1)
    if not os.path.exists(args.bmv2_json):
        parser.print_help()
        print "\nBMv2 JSON file not found: %s\nHave you run 'make'?" % args.bmv2_json
        parser.exit(1)
    main(args.p4info, args.bmv2_json)
