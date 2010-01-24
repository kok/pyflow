from xdrlib import Unpacker
from socket import socket, AF_INET, SOCK_DGRAM, ntohl, htonl
from math import floor



def ipToString(ip):

    ip = htonl(ip)              # network byte order is big-endian
    return '%d.%d.%d.%d' % (ip & 0xff, (ip >> 8) & 0xff, (ip >> 16) & 0xff, (ip >> 24) & 0xff)


def decode_sflow_data_source(sflow_data_source):

    # source type should be one of
    #   0 = ifIndex
    #   1 = smonVlanDataSource
    #   2 = entPhysicalEntry

    source_type = sflow_data_source >> 24
    value = sflow_data_source & 0xfff

    return (source_type, value)






def read_sflow_stream(addr, data):

    # Create unpacker
    up = Unpacker(data)

    # Get version version of sflow packet
    version = up.unpack_int()
    print('\n\nread_sflow_stream:version = %d' % version)

    # Reset to beginning
    up.set_position(0)
    if version == 5:
        read_sample_datagram(up)
    else:
        raise Exception()

    # Check if whole stream was read
    up.done()

def read_sample_datagram(up):

    sf = SFlow()

    # Unpack sample_datagram union
    #     uint version
    #     sample_datagram_v5 datagram
    version = up.unpack_int()
    assert(version == 5)

    # Unpack sample_datagram_v5 structure
    #    address agent_address          IP address of sampling agent, sFlowAgentAddress.
    #    unsigned int sub_agent_id;     Used to distinguishing between datagram streams
    #    unsigned int sequence_number;  Incremented with each sample datagram
    #    unsigned int uptime;           Current time (in milliseconds since device last booted).
    #    sample_record samples<>;       An array of sample records
    af = up.unpack_int()
    if af == 1:                 # IPv4
        agent_address = up.unpack_uint()
    else:
        raise Exception()

    sub_agent_id = up.unpack_uint()
    sequence_number = up.unpack_uint()
    uptime = up.unpack_uint()
    nb_sample_records = up.unpack_uint()

    
    # Print debug information
    print('read_sample_datagram:agent_address = %d' % agent_address)
    print('read_sample_datagram:af = %d' % af)
    print('read_sample_datagram:sub_agent_id = %d' % sub_agent_id)
    print('read_sample_datagram:sequence_number = %d' % sequence_number)
    print('read_sample_datagram:uptime = %d' % uptime)
    print('read_sample_datagram:nb_sample_records = %d' % nb_sample_records)

    # Iterating over sample records
    for i in range(nb_sample_records):
        print("read_sample_datagram:Reading sample record",i)
        read_sample_record(up, sf)


def read_sample_record(up, sample_datagram):

    # Unpack sample_record structure
    #    data_format sample_type;      Specifies the type of sample data
    #    opaque sample_data<>;          A structure corresponding to the sample_type

    # Decode sample type
    sample_type = up.unpack_uint()
    enterprise = sample_type >> 12
    format = sample_type & 0xfff
    print('read_sample_record:sample_type == %d (%d, %d)' % (sample_type, enterprise, format))

    # Unpack sample data
    sample_data = up.unpack_opaque()
    up_sample_data = Unpacker(sample_data)
    
    if sample_type == 1:    # enterprise = 0, format = 1 --> flow_record
        read_flow_sample(up_sample_data, sample_datagram)
    elif sample_type == 2: # enterprise = 0, format = 2 --> counter_record
        print("read_sample_record: PARSING OF SAMPLE TYPE 2 NOT IMPLEMENTED")
        return
#        sample = readCounterSample(up_sample_data)
#        samples.append(sample)
    else:
        raise Exception()

    # Check if whole data block was unpacked
    up_sample_data.done()


def read_flow_sample(up, sample_datagram):
    
    # Unpack flow_sample structure
    #    unsigned int sequence_number;   Incremented with each flow sample
    #    sflow_data_source source_id;    sFlowDataSource
    #    unsigned int sampling_rate;     sFlowPacketSamplingRate
    #    unsigned int sample_pool;       Total number of packets that could have been sampled
    #    unsigned int drops;             Number of times that the sFlow agent detected 
    #                                    that a packet marked to be sampled was dropped
    #    interface input;                Interface packet was received on.
    #    interface output;               Interface packet was sent on.
    #    flow_record flow_records<>;     Information about a sampled packet

    sequence_number = up.unpack_uint()
    source_id = up.unpack_uint()
    sampling_rate = up.unpack_uint()
    sample_pool = up.unpack_uint()
    drops = up.unpack_uint()
    input_if = up.unpack_uint()
    output_if = up.unpack_uint()
    nb_flow_records = up.unpack_uint()

    (source_id_index, source_id_value) = decode_sflow_data_source(source_id)

    # Some debug output
    print("read_flow_sample:sequence_number = %d" % sequence_number)
    print("read_flow_sample:source_id = %d (%d, %d)" % (source_id,source_id_index, source_id_value))
    print("read_flow_sample:sampling_rate = %d" % sampling_rate)
    print("read_flow_sample:sample_pool = %d" % sample_pool)
    print("read_flow_sample:drops = %d" % drops)
    print("read_flow_sample:input_if = %d" % (input_if))
    print("read_flow_sample:output_if = %d" % (output_if))
    print("read_flow_sample:nb_flow_records = %d" % nb_flow_records)
    
    # Iterating over flow records
    for i in range(nb_flow_records):
        read_flow_record(up, sample_datagram)


def read_flow_record(up, sample_datagram):

    # Unpack flow_record structure
    #     data_format flow_format;      The format of sflow_data
    #     opaque flow_data<>;           Flow data uniquely defined by the flow_format.

    # Unpack data format
    flow_format = up.unpack_uint()
    enterprise = flow_format >> 12
    format = flow_format & 0xfff
    print('read_flow_record:flow_format == %d (%d, %d)' % (flow_format, enterprise, format))

    # Uppack whole data block
    flow_data = up.unpack_opaque()
    up_flow_data = Unpacker(flow_data)
    
    # Raw Packet Header
    if format == 1:
        read_sampled_header(up_flow_data, sample_datagram)
    elif format == 2:
        read_sampled_ethernet(up_flow_data, sample_datagram)
    elif format == 3:
        read_sampled_ipv4(up_flow_data, sample_datagram)
    else:
        print('read_flow_record:Unknown data_format (%d)' % format)

    # Check if everything was unpacked
    up_flow_data.done()



def read_sampled_header(up, sample_datagram):

    # Unpack sampled raw header
    #     header_protocol protocol;      Format of sampled header
    #     unsigned int frame_length;     Original length of packet before sampling.
    #     unsigned int stripped;         The number of octets removed from the packet before 
    #                                    extracting the header<> octets.
    #     opaque header<>;               Header bytes

    header_protocol = up.unpack_int()
    frame_length = up.unpack_uint()
    stripped = up.unpack_uint()
    header = up.unpack_opaque()

    # Decode header data
    up_header = Unpacker(header)
    header_first_byte = up_header.unpack_uint()
    header_version = header_first_byte >> 28
    header_second_byte = up_header.unpack_uint()
    header_third_byte = up_header.unpack_uint()
    header_source_ip = up_header.unpack_uint()
    header_dst_ip = up_header.unpack_uint()
    
    print("read_sampled_header:header_protocol = %d" % header_protocol)
    print("read_sampled_header:frame_length = %d" % frame_length)
    print("read_sampled_header:stripped = %d" % stripped)
    print("read_sampled_header:header",header)
    print("read_sampled_header:header_source_ip = %d (%s)" % (header_source_ip, ipToString(header_source_ip)))
    print("read_sampled_header:header_dst_ip = %d (%s)" % (header_dst_ip, ipToString(header_dst_ip)))


def read_sampled_ethernet(up, sample_datagram):

    # Unpack Ethernet Frame Data
    #     unsigned int length;   The length of the MAC packet received on the network
    #     mac src_mac;           Source MAC address
    #     mac dst_mac;           Destination MAC address
    #     unsigned int type;     Ethernet packet type

    length = up.unpack_uint()
    src_mac = up.unpack_fopaque(6)
    dst_mac = up.unpack_fopaque(6)
    eth_type = up.unpack_uint()

    print("read_sampled_ethernet:length = %d" % length)
    print("read_sampled_ethernet:src_mac = %d" % src_mac)
    print("read_sampled_ethernet:dst_mac = %d" % dst_mac)
    print("read_sampled_ethernet:eth_type = %d" % eth_type)
    

def read_sampled_ipv4(up, sample_datagram):

    # Unpack Packet IP version 4 data
    #     unsigned int length;     The length of the IP packet excluding lower layer encapsulations
    #     unsigned int protocol;   IP Protocol type (for example, TCP = 6, UDP = 17)
    #     ip_v4 src_ip;            Source IP Address
    #     ip_v4 dst_ip;            Destination IP Address
    #     unsigned int src_port;   TCP/UDP source port number or equivalent
    #     unsigned int dst_port;   TCP/UDP destination port number or equivalent
    #     unsigned int tcp_flags;  TCP flags
    #     unsigned int tos;        IP type of service

    # Unpack fields
    length = up.unpack_uint()
    protocol = up.unpack_uint()
    src_ip = up.unpack_fopaque(4)
    dst_ip = up.unpack_fopaque(4)
    src_port = up.unpack_uint()
    dst_port = up.unpack_uint()
    tcp_flags = up.unpack_uint()
    tos = up.unpack_uint()

    # Some debug output
    print("read_sampled_ipv4:length = %d" % length)
    print("read_sampled_ipv4:protocol = %d" % protocol)
    print("read_sampled_ipv4:src_ip = %d (%s)" % (src_ip, ipToString(src_ip)))
    print("read_sampled_ipv4:dst_ip = %d (%s)" % (dst_ip, ipToString(dst_ip)))
    print("read_sampled_ipv4:src_port = %d" % src_port)
    print("read_sampled_ipv4:dst_port = %d" % dst_port)
    print("read_sampled_ipv4:tcp_flags = %d" % tcp_flags)
    print("read_sampled_ipv4:tos = %d" % tos)
    

class SFlow (object):

    def __init__(self):

        self.version = 5
        self.src_addr = 0
        self.src_port = 0
        self.sub_agent_id = 0
        self.sequence_number = 0
        self.uptime = 0
        self.samples = []

    def __repr__(self):
        return '<sflow5,src=%s:%d,agent=%d,seq=%d,up=%dh, samples=%s>' % (self.src_addr, 
                                                                          self.src_port, 
                                                                          self.sub_agent_id, 
                                                                          self.sequence_number, 
                                                                          floor(self.uptime/3600000.0), 
                                                                          str(self.samples))

class FlowSample (object):
    def __init__(self, sflow_info):
        self.sflow_info = sflow_info
        self.flow_records = []

    def __repr__(self):
        return '<flow-sample, %d flow-recs>' % (len(self.flow_records))


class IfCounterRecord (object):
    def __init__(self, counter_sample_info):
        self.counter_sample_info = counter_sample_info
        self.if_index = 0
        self.if_type = 0
        self.if_speed = 0
        self.if_direction = 0
        self.if_status = 0
        self.if_in_octets = 0
        self.if_in_ucast_pkts = 0
        self.if_in_multicast_pkts = 0
        self.if_in_broadcast_pkts = 0
        self.if_in_discards = 0
        self.if_in_errors = 0
        self.if_in_unknown_protos = 0
        self.if_out_octets = 0
        self.if_out_ucast_pkts = 0
        self.if_out_multicast_pkts = 0
        self.if_out_broadcast_pkts = 0
        self.if_out_discards = 0
        self.if_out_errors = 0
        self.if_promiscuous_mode = 0

    def __repr__(self):
        return '%d' % (self.if_index)

class EthernetCounterRecord (object):
    def __init__(self):
        pass

    def __repr__(self):
        pass

class CounterSample (object):
    def __init__(self):
        self.counter_records = []

    def __repr__(self):
        return '<counter-sample, %d counter-recs>' % (len(self.counter_records))


class FlowRecord (object):
    def __init__(self, sample):
        self.sample = sample

    def __repr__(self):
        return 'FlowRecord'


class FlowRecordIPv4 (FlowRecord):
    def __init__(self, sample):
        FlowRecord.__init__(self, sample)

        self.length = None
        self.protocol = None
        self.src_ip = None
        self.dst_ip = None
        self.src_port = None
        self.dst_port = None
        self.tcp_flags = None
        self.tos = None

    def __repr__(self):
        return '<FlowRecordIPv4: src=%x:%d, dst=%x:%d' % (self.src_ip, self.src_port, self.dst_ip, self.dst_port)


class FlowRecordRaw (FlowRecord):
    def __init__(self, sample):
        FlowRecord.__init__(self, sample)

        self.record.header_protocol = None
        self.frame_length = None
        self.stripped = None
        self.header = None

    def __repr__(self):
        return 'FlowRecordRaw'


def readFlowRecord(up, sample):
    data_format = up.unpack_uint()
    print('readFlowRecord:data_format = %d' % data_format)
    data_end = up.unpack_uint() + up.get_position() # order of
                                                    # funcalls is
                                                    # important

    if data_format == 1:        # raw packet header
        print('pos=%d, end=%d' % (up.get_position(), data_end - 1))
        while up.get_position() < data_end - 1:
            record = FlowRecordRaw(sample)

            record.header_protocol = up.unpack_int()
            record.frame_length = up.unpack_uint()
            record.stripped = up.unpack_uint()
            record.header = up.unpack_opaque()

            yield record
    elif data_format == 2:      # sampled ethernet
        while up.get_position() < data_end - 1:
            length = up.unpack_uint()
            src_mac = up.unpack_fopaque(6)
            dst_mac = up.unpack_fopaque(6)
            eth_type = up.unpack_uint()
    elif data_format == 3:      # sampled IPv4
        while up.get_position() < data_end - 1:
            record = FlowRecordIPv4(sample)

            record.length = up.unpack_uint()
            record.protocol = up.unpack_uint()
            record.src_ip = up.unpack_uint()
            record.dst_ip = up.unpack_uint()
            record.src_port = up.unpack_uint()
            record.dst_port = up.unpack_uint()
            record.tcp_flags = up.unpack_uint()
            record.tos = up.unpack_uint()
            
            yield record
    else:
        print('Unknown data_format (%d)' % data_format)
        up.set_position(data_end)
    # elif data_format == 4:      # sampled IPv6
    #     raise Exception()
    # elif data_format == 1001:   # extended switch data
    #     raise Exception()
    # elif data_format == 1002:   # extended router data
    #     raise Exception()
    # elif data_format == 1003:   # extended gateway data
    #     raise Exception()
    # elif data_format == 1004:   # extended user data
    #     raise Exception()
    # elif data_format == 1005:   # extended url data
    #     raise Exception()
    # elif data_format == 1006:   # extended MPLS data
    #     raise Exception()
    # elif data_format == 1007:   # extended NAT data
    #     raise Exception()
    # elif data_format == 1008:   # extended MPLS tunnel
    #     raise Exception()
    # elif data_format == 1009:   # extended MPLS VC
    #     raise Exception()
    # elif data_format == 1010:   # extended MPLS FEC
    #     raise Exception()
    # elif data_format == 1011:   # extended MPLS LVP FEC
    #     raise Exception()
    # elif data_format == 1012:   # extended VLAN tunnel
    #     raise Exception()
    # else:
    #     print('Aiiiieeee! %d' % data_format)
    #     raise Exception()

def readIfCounters(up):
    if_cnt = IfCounterRecord()
    if_cnt.if_index = up.unpack_uint()
    print('if_cnt.if_index = %d' % if_cnt.if_index)
    if_cnt.if_type = up.unpack_uint()
    print('if_cnt.if_type = %d' % if_cnt.if_type)
    if_cnt.if_speed = up.unpack_uhyper()
    print('if_cnt.if_speed = %d' % if_cnt.if_speed)
    if_cnt.if_direction = up.unpack_uint()
    print('if_cnt.if_direction = %d' % if_cnt.if_direction)
    if_cnt.if_status = up.unpack_uint()
    print('if_cnt.if_status = %d' % if_cnt.if_status)
    if_cnt.if_in_octets = up.unpack_uhyper()
    print('if_cnt.if_in_octets = %d' % if_cnt.if_in_octets)
    if_cnt.if_in_ucast_pkts = up.unpack_uint()
    print('if_cnt.if_in_ucast_pkts = %d' % if_cnt.if_in_ucast_pkts)
    if_cnt.if_in_multicast_pkts = up.unpack_uint()
    print('if_cnt.if_in_multicast_pkts = %d' % if_cnt.if_in_multicast_pkts)
    if_cnt.if_in_broadcast_pkts = up.unpack_uint()
    print('if_cnt.if_in_broadcast_pkts = %d' % if_cnt.if_in_broadcast_pkts)
    if_cnt.if_in_discards = up.unpack_uint()
    print('if_cnt.if_in_discards = %d' % if_cnt.if_in_discards)
    if_cnt.if_in_errors = up.unpack_uint()
    print('if_cnt.if_in_errors = %d' % if_cnt.if_in_errors)
    if_cnt.if_in_unknown_protos = up.unpack_uint()
    print('if_cnt.if_in_unknown_protos = %d' % if_cnt.if_in_unknown_protos)
    if_cnt.if_out_octets = up.unpack_uhyper()
    print('if_cnt.if_out_octets = %d' % if_cnt.if_out_octets)
    if_cnt.if_out_ucast_pkts = up.unpack_uint()
    print('if_cnt.if_out_ucast_pkts = %d' % if_cnt.if_out_ucast_pkts)
    if_cnt.if_out_multicast_pkts = up.unpack_uint()
    print('if_cnt.if_out_multicast_pkts = %d' % if_cnt.if_out_multicast_pkts)
    if_cnt.if_out_broadcast_pkts = up.unpack_uint()
    print('if_cnt.if_out_broadcast_pkts = %d' % if_cnt.if_out_broadcast_pkts)
    if_cnt.if_out_discards = up.unpack_uint()
    print('if_cnt.if_out_discards = %d' % if_cnt.if_out_discards)
    if_cnt.if_out_errors = up.unpack_uint()
    print('if_cnt.if_out_errors = %d' % if_cnt.if_out_errors)
    if_cnt.if_promiscuous_mode = up.unpack_uint()
    print('if_cnt.if_promiscuous_mode = %d' % if_cnt.if_promiscuous_mode)
    return if_cnt

def readEthernetCounters(up):
    eth_cnt = EthernetCounterRecord()
    for i in range(13):
        up.unpack_uint()
    return eth_cnt

def readVlanCounters(up):
    vlan_id = up.unpack_uint()
    octets = up.unpack_uhyper()
    ucast_pkts = up.unpack_uint()
    multicast_pkts = up.unpack_uint()
    broadcast_pkts = up.unpack_uint()
    discards = up.unpack_uint()
    print('vlan_id: %d, octets: %d, ucast: %d, mcast: %d, bcast: %d, discards: %d' % (vlan_id, octets, ucast_pkts, multicast_pkts, broadcast_pkts, discards))

def readProcessorInfo(up):
    cpu_5s = up.unpack_int()
    cpu_1m = up.unpack_int()
    cpu_5m = up.unpack_int()
    total_memory = up.unpack_uhyper()
    free_memory = up.unpack_uhyper()

    print('<procinfo cpu (5s/1m/5m): %d %d %d  |mem(free/total): %d/%d' % (cpu_5s, cpu_1m, cpu_5m, free_memory, total_memory))

def readCounterRecord(up):
    data_format = up.unpack_uint()
    data_end = up.unpack_uint() + up.get_position() # order of
                                                    # funcalls is
                                                    # important
    items = []
    if data_format == 1:        # enterprise = 0, format = 1 -> struct if_counters
        print('if_counters')
        while up.get_position() < data_end - 1:
            items.append(readIfCounters(up))
    elif data_format == 2:      # enterprise = 0, format = 2 -> struct ethernet_counters
        print('ethernet_counters')
        while up.get_position() < data_end - 1:
            items.append(readEthernetCounters(up))
    elif data_format == 5:      # enterprise = 0, format = 5 -> struct vlan_counters
        print('vlan_counters')
        while up.get_position() < data_end - 1:
            items.append(readVlanCounters(up))
    elif data_format == 1001:   # enterprise = 0, format = 1001 -> struct processor
        print('processor info')
        while up.get_position() < data_end - 1:
            items.append(readProcessorInfo(up))
    else:
        # We have no idea what we're looking at.  print(a diagnostic)
        # message and forward the file pointer to the next
        # record/sample/whatever.
        
        print('Unknown data_format (%d) in readCounterRecord.' % data_format)
        up.set_position(data_end)
        return None
    return items



def readCounterSample(up):
    sequence_number = up.unpack_uint()
    source_id = up.unpack_uint()
    recs_end = up.unpack_uint() + up.get_position() # the order of
                                                    # these funcalls
                                                    # is important!
    sample = CounterSample()
    while up.get_position() < recs_end - 1:
        rec = readCounterRecord(up)
        sample.counter_records.append(rec)
    return sample


def listenForSFlow(callback, address='0.0.0.0', port=6343):
    listen_on = (address, port)
    sock = socket(AF_INET, SOCK_DGRAM)
    sock.bind(listen_on)
    while True:
        datagram, src_addr = sock.recvfrom(65535)
        sflow_data = readSFlow(src_addr, datagram)
        for sample in sflow_data:
            callback(src_addr, sample)

if __name__=='__main__':
    listen_addr = ("0.0.0.0", 6343)
    sock = socket(AF_INET, SOCK_DGRAM)
    sock.bind(listen_addr)
    while True:
        data, addr = sock.recvfrom(65535)
        read_sflow_stream(addr, data)
