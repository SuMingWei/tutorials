#!/usr/bin/env python2
# coding=utf-8
import argparse
import grpc
import os
import sys
from time import sleep
import threading
import subprocess

# Import P4Runtime lib from parent utils dir
# Probably there's a better way of doing this.
sys.path.append(
    os.path.join(os.path.dirname(os.path.abspath(__file__)),
                 '../../utils/'))
import p4runtime_lib.bmv2
from p4runtime_lib.error_utils import printGrpcError
from p4runtime_lib.switch import ShutdownAllSwitchConnections
import p4runtime_lib.helper

SWITCH_TO_HOST_PORT = 1
SWITCH_TO_SWITCH_PORT = 2

class simple_switch_cli:
    def __init__(self, port=None):
        # default s1
        self.port = port if port is not None else 9090
    def console(self, stdout=None):
        # if stdout is not None:
        #     return(subprocess.Popen('simple_switch_CLI --thrift-port 9104', shell=True,  stdin=subprocess.PIPE, stdout=subprocess.PIPE))
        # return(Popen(["bconsole"], stdout=PIPE, stderr=PIPE, stdin=PIPE))
        return(subprocess.Popen('simple_switch_CLI --thrift-port {}'.format(self.port), shell=True,  stdin=subprocess.PIPE, stdout=subprocess.PIPE))
    def show_tables(self):
        run = self.console().communicate("show_tables")
        return(run)
    def set_meter_rate(self, meter_name, meter_id, cir_burst, pir_burst):
        rates = self.console().communicate("meter_set_rates %s %s %s %s"%(meter_name, meter_id, cir_burst, pir_burst))
        return(rates)
    def get_meter_rate(self, meter_name, meter_id):
        rates = self.console().communicate("meter_get_rates %s %s"%(meter_name, meter_id))[0]
        return(rates)
    def read_counter(self, counter_name, counter_id):
        counter = self.console().communicate("counter_read %s %s"%(counter_name, counter_id))[0]
        return(counter)
    def get_register_value(self, register_name, register_index):
        reg = self.console().communicate("register_read %s %s"%(register_name, register_index))[0]
        return(reg)
    def reset_register_value(self, register_name, register_index):
        reg = self.console().communicate("register_reset %s %s"%(register_name, register_index))
        return(reg)


# convert ascii to string
def prettify(IP_string):
    return '.'.join('%d' % ord(b) for b in IP_string)

# convert ascii to integer
def int_prettify(int_string):
    return int(''.join('%d' % ord(b) for b in int_string))

def readTableRules(p4info_helper, sw):
    """
    Reads the table entries from all tables on the switch.

    :param p4info_helper: the P4Info helper
    :param sw: the switch connection
    """
    print('\n----- Reading tables rules for %s -----' % sw.name)
    for response in sw.ReadTableEntries():
        for entity in response.entities:
            entry = entity.table_entry
            # TODO For extra credit, you can use the p4info_helper to translate
            #      the IDs in the entry to names
            table_name = p4info_helper.get_tables_name(entry.table_id)
            print('%s: ' % table_name,)
            # for m in entry.match:
            #     print(p4info_helper.get_match_field_name(table_name, m.field_id), end=' ')
            #     print('%r' % (p4info_helper.get_match_field_value(m),), end=' ')
            action = entry.action.action
            action_name = p4info_helper.get_actions_name(action.action_id)
            # print('->', action_name, end=' ')
            # for p in action.params:
                # print (p4info_helper.get_action_param_name(action_name, p.param_id), end=' ')
                # print ('%r' % p.value, end=' ')
            # print()


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
            print("%s %s %d: %d packets (%d bytes)" % (
                sw.name, counter_name, index,
                counter.data.packet_count, counter.data.byte_count
            ))

def writeMeterTableRules(p4info_helper, sw, ingressPort, meter_index):
    """

    :param p4info_helper: the P4Info helper
    :param sw:  the switch connection
    :param ingressPort: the port of the meter
    :param meter_index: the meter index (in my case, the ingress port)
    """
    matches = {
        "standard_metadata.ingress_port": ingressPort
    }
    table_entry = p4info_helper.buildTableEntry(
        table_name="MyIngress.m_table",
        match_fields=matches,
        action_name="MyIngress.m_action",
        action_params={
            "meter_idx": (meter_index+1),
    })
    sw.WriteTableEntry(table_entry, False)

def readMeterFlowRules(p4info_helper, sw, meter_index, cir, pir, interval):
    meter_id = p4info_helper.get_meters_id("MyIngress.my_meter")
    sw.ReadMeters(meter_id, meter_index)

def writeMeterFlowRules(p4info_helper, sw, meter_index, cir, pir, interval):
    meter_id = p4info_helper.get_meters_id("MyIngress.my_meter")
    sw.WriteMeters(meter_id, meter_index, cir, pir)

def printMeter(p4info_helper, sw, meter_name, index):
    """
    Reads the specified counter at the specified index from the switch. In our
    program, the index is the tunnel ID. If the index is 0, it will return all
    values from the counter.

    :param p4info_helper: the P4Info helper
    :param sw:  the switch connection
    :param meter_name: the name of the meter from the P4 program
    :param index: the meter index
    """
    for response in sw.ReadMeters(p4info_helper.get_meters_id(meter_name), index):
        for entity in response.entities:
            meter = entity.meter_entry
            ''' 
                Meter Content:
                    index {
                        index: 1
                        }
                    config {
                        cir: 1
                        cburst: 1
                        pir: 5
                        pburst: 1
                    }
                
                See:https://github.com/p4lang/p4runtime/blob/main/proto/p4/v1/p4runtime.proto for more info
            '''
            print("%s:%s[%d]: CIR:%f:%d PIR:%f:%d "%(
                sw.name, meter_name, meter.index.index,
                meter.config.cir * 0.000001, meter.config.cburst, meter.config.pir*0.000001, meter.config.pburst
            ))

def SendDigestEntry(p4info_helper,sw,digest_name=None):
    digest_entry = p4info_helper.buildDigestEntry(digest_name=digest_name)
    sw.WriteDigestEntry(digest_entry)
    print("send digestEntry via p4Runtime")

def resetMeterRates():
    print("reset Meter Rate")

def main(p4info_file_path, bmv2_file_path):
    # Instantiate a P4Runtime helper from the p4info file
    p4info_helper = p4runtime_lib.helper.P4InfoHelper(p4info_file_path)
    
    try:
        
        '''
            Create a switch connection object for s1 and s2;
            this is backed by a P4Runtime gRPC connection.
            Also, dump all P4Runtime messages sent to switch to given txt files.
        '''
        s1 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name='s1',
            address='127.0.0.1:50051',
            device_id=0,
            proto_dump_file='logs/s1-p4runtime-requests.txt')
        # s2 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
        #     name='s2',
        #     address='127.0.0.1:50052',
        #     device_id=1,
        #     proto_dump_file='logs/s2-p4runtime-requests.txt')
        s3 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name='s3',
            address='127.0.0.1:50053',
            device_id=2,
            proto_dump_file='logs/s2-p4runtime-requests.txt')
        s15 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name='s15',
            address='127.0.0.1:50065',
            device_id=14,
            proto_dump_file='logs/s15-p4runtime-requests.txt')
        
        '''
            Send master arbitration update message to establish this controller as
            master (required by P4Runtime before performing any other write operation)
        '''
        s1.MasterArbitrationUpdate()
        # s2.MasterArbitrationUpdate()
        s3.MasterArbitrationUpdate()
        s15.MasterArbitrationUpdate()

        '''
            Install the P4 program on the switchesm
            this will rewrite the `sX-runtime.json`, so just use one of them
        '''
        # s1.SetForwardingPipelineConfig(p4info=p4info_helper.p4info,
        #                                bmv2_json_file_path=bmv2_file_path)
        # print("Installed P4 Program using SetForwardingPipelineConfig on s1")
        # s2.SetForwardingPipelineConfig(p4info=p4info_helper.p4info,
        #                                bmv2_json_file_path=bmv2_file_path)
        # print("Installed P4 Program using SetForwardingPipelineConfig on s2")
        # s3.SetForwardingPipelineConfig(p4info=p4info_helper.p4info,
        #                                bmv2_json_file_path=bmv2_file_path)
        # s15.SetForwardingPipelineConfig(p4info=p4info_helper.p4info, 
        #                                bmv2_json_file_path=bmv2_file_path)
        # print("Installed P4 Program using SetForwardingPipelineConfig on s15")

        '''
            read Table Rule
        '''
        # readTableRules(p4info_helper, s1)
        # readTableRules(p4info_helper, s2)

        '''
            write Meter Rate    :   改寫 Meter 的 rate
            p4info_helper       :   p4info_helper file
            sw                  :   switch name
            meter_index         :   meter index
            cir                 :   cir (packets/microsec)
            pir                 :   pir (packets/microsec)
            interval            :   ?
        '''
        writeMeterFlowRules(p4info_helper, s3, 15, 1, 5, 0)

        '''
            Send Digest Entry   :   建立 digest 連線? (第一次執行時需要)
            p4info_helper       :   p4info_helper file
            sw                  :   switch name
            digest_name         :   digest name
        '''
        # SendDigestEntry(p4info_helper, sw=s3, digest_name="anomaly_digest")

        '''
            simple_switch_CLI
        '''
        # s3 
        cli = simple_switch_cli(9092)
        # Main Control
        while True:
            '''
                Digest receive
            '''
            print("----- digests -----")
            digests = s3.DigestList()
            for digest in digests:
                if digest.WhichOneof('update')=='digest':
                    digest = digest.digest
                    digest_name = p4info_helper.get_digests_name(digest.digest_id)
                    # print(digest)
                    '''
                        [DigestList message的定義]
                        message DigestList {
                            uint32 digest_id = 1;  // identifies the digest extern instance
                            uint64 list_id = 2;  // identifies a list of entries, used by receiver to ack
                            // List of entries: each call to the Digest<T>::pack() method corresponds to
                            // one entry and we can have as little as one entry.
                            repeated P4Data data = 3;
                            // Timestamp at which the server generated the message (in nanoseconds since
                            // Epoch)
                            int64 timestamp = 4;
                        }
                        [Digest例子]
                        digest example
                            digest_id: 385927609
                            list_id: 12824
                            data {
                                struct {
                                    members {
                                        bitstring: "\000\000\000\001"
                                    }
                                }
                            }
                            timestamp: 15620122603112
                    '''
                    print("digest name: {}".format(digest_name))
                    print("digest list_id: {}".format(digest.list_id))
                    print("get anomaly_digest data: Ingress Port = {}".format(int_prettify(digest.data[0].struct.members[0].bitstring)))
                    print("anomaly_digest register index in bf1: {}".format(int(digest.data[0].struct.members[1].bitstring.encode('hex'),16)))
                    print("anomaly_digest register index in bf2: {}".format(int(digest.data[0].struct.members[2].bitstring.encode('hex'),16)))
                    # print("anomaly_digest timestamp : {}".format(int_prettify(digest.data[0].struct.members[3].bitstring)))
                    break
            print("----- digests End -----")
            
            '''
                read Counter
            '''
            print('\n----- Reading counters -----')
            printCounter(p4info_helper, s3, "MyIngress.ingressPortCounter", 15)
            '''
                read Meter
            '''
            print('\n----- Reading meters -----')
            printMeter(p4info_helper, s3, "MyIngress.my_meter", 15)
            print("============  End ==============")
            # '''
            #     read register by simple_switch_CLI
            # '''
            # reg = cli.get_register_value("bloom_filter_2", 15).split()
            # value = int(reg[14])
            # print(value)
            '''
                reset Meter rate
            '''
            #TODO: 
            # 1. get port number from digest 
            # 2. get current output BW from digest
            # 3. get numbers of `active port` on switch 
            # 4. fair share the BW
            reg = cli.set_meter_rate("my_meter", 15).split()
            value = int(reg[14])
            print(value)
            '''
                reset Register
            '''
            #TODO:
            # 1. get port number in BF index from digest 
            reg = cli.reset_register_value("bloom_filter_1", 15)
            reg = cli.reset_register_value("bloom_filter_2", 15)
            sleep(0.25)

    except KeyboardInterrupt:
        print(" Shutting down.")
    except grpc.RpcError as e:
        printGrpcError(e)

    # ShutdownAllSwitchConnections()

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
        print("\np4info file not found: %s\nHave you run 'make'?" % args.p4info)
        parser.exit(1)
    if not os.path.exists(args.bmv2_json):
        parser.print_help()
        print("\nBMv2 JSON file not found: %s\nHave you run 'make'?" % args.bmv2_json)
        parser.exit(1)
    main(args.p4info, args.bmv2_json)
