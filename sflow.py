from xdrlib import Unpacker
from socket import socket, AF_INET, SOCK_DGRAM, ntohl, htonl
from math import floor

def ipToString(ip):
    ip = htonl(ip)              # network byte order is big-endian
    return '%d.%d.%d.%d' % (ip & 0xff, (ip >> 8) & 0xff, (ip >> 16) & 0xff, (ip >> 24) & 0xff)

class SFlowV5 (object):
    def __init__(self):
        self.version = 5
        self.src_addr = 0
        self.src_port = 0
        self.sub_agent_id = 0
        self.sequence_number = 0
        self.uptime = 0
        self.samples = []

    def read(self, up):
        version = up.unpack_int()
        assert(version == 5)
        self.version = version

        af = up.unpack_int()
        print 'readSFlowV5:af = %d' % af
        if af == 1:                 # IPv4
            # TODO: should this be unpack_uint?
            self.agent_address = up.unpack_int()
        else:
            raise Exception()

        self.sub_agent_id = up.unpack_uint()
        print 'readSFlowV5:sub_agent_id = %d' % self.sub_agent_id
        self.sequence_number = up.unpack_uint()
        self.uptime = up.unpack_uint()
        samples = []
        samples_end = up.unpack_uint() + up.get_position() # the order of
                                                           # these
                                                           # funcalls is
                                                           # important!
        print 'readSFlowV5:samples_end = %d' % samples_end
        while up.get_position() < samples_end - 1:
            sample_type = up.unpack_uint()
            print 'readSFlowV5:sample_type == %d' % sample_type
            if sample_type == 1:    # enterprise = 0, format = 1 --> flow_record
                for sample in readFlowSampleV5(up, self):
                    yield sample
            elif sample_type == 2: # enterprise = 0, format = 2 --> counter_record
                sample = readCounterSampleV5(up)
                samples.append(sample)

            
    def __repr__(self):
        return '<sflow5,src=%s:%d,agent=%d,seq=%d,up=%dh, samples=%s>' % (self.src_addr, self.src_port, self.sub_agent_id, self.sequence_number, floor(self.uptime/3600000.0), str(self.samples))

class FlowSampleV5 (object):
    def __init__(self, sflow_info):
        self.sflow_info = sflow_info
        self.flow_records = []

    def __repr__(self):
        return '<flow-sample, %d flow-recs>' % (len(self.flow_records))


class IfCounterRecordV5 (object):
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

class EthernetCounterRecordV5 (object):
    def __init__(self):
        pass

    def __repr__(self):
        pass

class CounterSampleV5 (object):
    def __init__(self):
        self.counter_records = []

    def __repr__(self):
        return '<counter-sample, %d counter-recs>' % (len(self.counter_records))


class FlowRecordV5 (object):
    def __init__(self, sample):
        self.sample = sample

    def __repr__(self):
        return 'FlowRecordV5'


class FlowRecordV5IPv4 (FlowRecordV5):
    def __init__(self, sample):
        FlowRecordV5.__init__(self, sample)

        self.length = None
        self.protocol = None
        self.src_ip = None
        self.dst_ip = None
        self.src_port = None
        self.dst_port = None
        self.tcp_flags = None
        self.tos = None

    def __repr__(self):
        return '<FlowRecordV5IPv4: src=%x:%d, dst=%x:%d' % (self.src_ip, self.src_port, self.dst_ip, self.dst_port)


class FlowRecordV5Raw (FlowRecordV5):
    def __init__(self, sample):
        FlowRecordV5.__init__(self, sample)

        self.record.header_protocol = None
        self.frame_length = None
        self.stripped = None
        self.header = None

    def __repr__(self):
        return 'FlowRecordV5Raw'


def readFlowRecordV5(up, sample):
    data_format = up.unpack_uint()
    print 'readFlowRecordV5:data_format = %d' % data_format
    data_end = up.unpack_uint() + up.get_position() # order of
                                                    # funcalls is
                                                    # important

    if data_format == 1:        # raw packet header
        print 'pos=%d, end=%d' % (up.get_position(), data_end - 1)
        while up.get_position() < data_end - 1:
            record = FlowRecordV5Raw(sample)

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
            record = FlowRecordV5IPv4(sample)

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
        print 'Unknown data_format (%d)' % data_format
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
    #     print 'Aiiiieeee! %d' % data_format
    #     raise Exception()

def readIfCountersV5(up):
    if_cnt = IfCounterRecordV5()
    if_cnt.if_index = up.unpack_uint()
    print 'if_cnt.if_index = %d' % if_cnt.if_index
    if_cnt.if_type = up.unpack_uint()
    print 'if_cnt.if_type = %d' % if_cnt.if_type
    if_cnt.if_speed = up.unpack_uhyper()
    print 'if_cnt.if_speed = %d' % if_cnt.if_speed
    if_cnt.if_direction = up.unpack_uint()
    print 'if_cnt.if_direction = %d' % if_cnt.if_direction
    if_cnt.if_status = up.unpack_uint()
    print 'if_cnt.if_status = %d' % if_cnt.if_status
    if_cnt.if_in_octets = up.unpack_uhyper()
    print 'if_cnt.if_in_octets = %d' % if_cnt.if_in_octets
    if_cnt.if_in_ucast_pkts = up.unpack_uint()
    print 'if_cnt.if_in_ucast_pkts = %d' % if_cnt.if_in_ucast_pkts
    if_cnt.if_in_multicast_pkts = up.unpack_uint()
    print 'if_cnt.if_in_multicast_pkts = %d' % if_cnt.if_in_multicast_pkts
    if_cnt.if_in_broadcast_pkts = up.unpack_uint()
    print 'if_cnt.if_in_broadcast_pkts = %d' % if_cnt.if_in_broadcast_pkts
    if_cnt.if_in_discards = up.unpack_uint()
    print 'if_cnt.if_in_discards = %d' % if_cnt.if_in_discards
    if_cnt.if_in_errors = up.unpack_uint()
    print 'if_cnt.if_in_errors = %d' % if_cnt.if_in_errors
    if_cnt.if_in_unknown_protos = up.unpack_uint()
    print 'if_cnt.if_in_unknown_protos = %d' % if_cnt.if_in_unknown_protos
    if_cnt.if_out_octets = up.unpack_uhyper()
    print 'if_cnt.if_out_octets = %d' % if_cnt.if_out_octets
    if_cnt.if_out_ucast_pkts = up.unpack_uint()
    print 'if_cnt.if_out_ucast_pkts = %d' % if_cnt.if_out_ucast_pkts
    if_cnt.if_out_multicast_pkts = up.unpack_uint()
    print 'if_cnt.if_out_multicast_pkts = %d' % if_cnt.if_out_multicast_pkts
    if_cnt.if_out_broadcast_pkts = up.unpack_uint()
    print 'if_cnt.if_out_broadcast_pkts = %d' % if_cnt.if_out_broadcast_pkts
    if_cnt.if_out_discards = up.unpack_uint()
    print 'if_cnt.if_out_discards = %d' % if_cnt.if_out_discards
    if_cnt.if_out_errors = up.unpack_uint()
    print 'if_cnt.if_out_errors = %d' % if_cnt.if_out_errors
    if_cnt.if_promiscuous_mode = up.unpack_uint()
    print 'if_cnt.if_promiscuous_mode = %d' % if_cnt.if_promiscuous_mode
    return if_cnt

def readEthernetCountersV5(up):
    eth_cnt = EthernetCounterRecordV5()
    for i in range(13):
        up.unpack_uint()
    return eth_cnt

def readVlanCountersV5(up):
    vlan_id = up.unpack_uint()
    octets = up.unpack_uhyper()
    ucast_pkts = up.unpack_uint()
    multicast_pkts = up.unpack_uint()
    broadcast_pkts = up.unpack_uint()
    discards = up.unpack_uint()
    print 'vlan_id: %d, octets: %d, ucast: %d, mcast: %d, bcast: %d, discards: %d' % (vlan_id, octets, ucast_pkts, multicast_pkts, broadcast_pkts, discards)

def readProcessorInfoV5(up):
    cpu_5s = up.unpack_int()
    cpu_1m = up.unpack_int()
    cpu_5m = up.unpack_int()
    total_memory = up.unpack_uhyper()
    free_memory = up.unpack_uhyper()

    print '<procinfo cpu (5s/1m/5m): %d %d %d  |mem(free/total): %d/%d' % (cpu_5s, cpu_1m, cpu_5m, free_memory, total_memory)

def readCounterRecordV5(up):
    data_format = up.unpack_uint()
    data_end = up.unpack_uint() + up.get_position() # order of
                                                    # funcalls is
                                                    # important
    items = []
    if data_format == 1:        # enterprise = 0, format = 1 -> struct if_counters
        print 'if_counters'
        while up.get_position() < data_end - 1:
            items.append(readIfCountersV5(up))
    elif data_format == 2:      # enterprise = 0, format = 2 -> struct ethernet_counters
        print 'ethernet_counters'
        while up.get_position() < data_end - 1:
            items.append(readEthernetCountersV5(up))
    elif data_format == 5:      # enterprise = 0, format = 5 -> struct vlan_counters
        print 'vlan_counters'
        while up.get_position() < data_end - 1:
            items.append(readVlanCountersV5(up))
    elif data_format == 1001:   # enterprise = 0, format = 1001 -> struct processor
        print 'processor info'
        while up.get_position() < data_end - 1:
            items.append(readProcessorInfoV5(up))
    else:
        # We have no idea what we're looking at.  Print a diagnostic
        # message and forward the file pointer to the next
        # record/sample/whatever.
        
        print 'Unknown data_format (%d) in readCounterRecordV5.' % data_format
        up.set_position(data_end)
        return None
    return items

def readFlowSampleV5(up, sflow_info):
    sequence_number = up.unpack_uint()
    source_id = up.unpack_uint()
    sampling_rate = up.unpack_uint()
    sample_pool = up.unpack_uint()
    drops = up.unpack_uint()
    input_if = up.unpack_uint()
    output_if = up.unpack_uint()
    flow_recs_end = up.unpack_uint() + up.get_position() # order of
                                                         # funcalls is
                                                         # important
    sample = FlowSampleV5(sflow_info)
    print 'pos=%d, end=%d' %(up.get_position(), flow_recs_end)
    while up.get_position() < flow_recs_end - 1:
        for record in readFlowRecordV5(up, sample):
            yield record


def readCounterSampleV5(up):
    sequence_number = up.unpack_uint()
    source_id = up.unpack_uint()
    recs_end = up.unpack_uint() + up.get_position() # the order of
                                                    # these funcalls
                                                    # is important!
    sample = CounterSampleV5()
    while up.get_position() < recs_end - 1:
        rec = readCounterRecordV5(up)
        sample.counter_records.append(rec)
    return sample

def readSFlowV5(addr, up):
    version = up.unpack_int()
    assert(version == 5)
    af = up.unpack_int()
    print 'readSFlowV5:af = %d' % af
    if af == 1:                 # IPv4
        agent_address = up.unpack_int()
    else:
        raise Exception()
    sub_agent_id = up.unpack_uint()
    print 'readSFlowV5:sub_agent_id = %d' % sub_agent_id
    sequence_number = up.unpack_uint()
    uptime = up.unpack_uint()
    sf = SFlowV5()
    sf.version = 5
    sf.src_addr = addr[0]
    sf.src_port = addr[1]
    sf.sub_agent_id = sub_agent_id
    sf.sequence_number = sequence_number
    sf.uptime = uptime
    sf.samples = []
    samples_end = up.unpack_uint() + up.get_position() # the order of
                                                       # these
                                                       # funcalls is
                                                       # important!
    print 'readSFlowV5:samples_end = %d' % samples_end
    while up.get_position() < samples_end - 1:
        sample_type = up.unpack_uint()
        print 'readSFlowV5:sample_type == %d' % sample_type
        if sample_type == 1:    # enterprise = 0, format = 1 --> flow_record
            sample = readFlowSampleV5(up, sf)
            sf.samples.append(sample)
        elif sample_type == 2: # enterprise = 0, format = 2 --> counter_record
            sample = readCounterSampleV5(up)
            sf.samples.append(sample)
    return sf

def readSFlow(addr, data):
    up = Unpacker(data)
    version = up.unpack_int()
    up.set_position(0)
    print 'readSFlow:version = %d' % version
    if version == 5:
        sf = SFlowV5()
        return sf.read(up)
    else:
        raise Exception()

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
        for record in readSFlow(addr, data):
            print record
