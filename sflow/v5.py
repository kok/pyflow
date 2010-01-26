"""Library for parsing sFlow (v5) datagrams.

sFlow version 5 is described in www.sflow.org/sflow_version_5.txt.

Since the datagram format is specified using XDR the following RFCs
may be useful: 1014, 1832, 4506."""


from xdrlib import Unpacker
from socket import socket, AF_INET, SOCK_DGRAM, ntohl
from math import floor
from util import ip_to_string, hexdump_bytes

DebugMode = True

class LoggingUnpacker(Unpacker):
    """Adds logging functionality to the standard xdrlib.Unpacker."""

    def unpack_hyper(self, description='generic hyper: '):
        global DebugMode
        x = Unpacker.unpack_hyper(self)
        if DebugMode:
            print('%s %d' % (description, x))
        return x

    def unpack_uhyper(self, description='generic uhyper: '):
        global DebugMode
        x = Unpacker.unpack_uhyper(self)
        if DebugMode:
            print('%s %d' % (description, x))
        return x

    def unpack_uint(self, description='generic uint: '):
        global DebugMode
        x = Unpacker.unpack_uint(self)
        if DebugMode:
            print('%s %d' % (description, x))
        return x

    def unpack_int(self, description='generic int: '):
        global DebugMode
        x = Unpacker.unpack_int(self)
        if DebugMode:
            print('%s %d' % (description, x))
        return x

    def unpack_opaque(self, description='generic opaque'):
        global DebugMode
        x = Unpacker.unpack_opaque(self)
        if DebugMode:
            print(description)
            hexdump_bytes(x)
        return x
        
    def unpack_fopaque(self, length, description='generic fixed-length opaque'):
        global DebugMode
        x = Unpacker.unpack_fopaque(self, length)
        if DebugMode:
            print(description)
            hexdump_bytes(x)
        return x


def decode_sflow_data_source(sflow_data_source):
    """Decodes a sflow_data_source as described in the sFlow v5
    spec."""
    # source type should be one of
    #   0 = ifIndex
    #   1 = smonVlanDataSource
    #   2 = entPhysicalEntry

    global DebugMode

    source_type = sflow_data_source >> 24
    value = sflow_data_source & 0xfff

    if DebugMode:
        print('sflow_data_source (source_type, value) = %s' % str((source_type, value)))

    return (source_type, value)


def read_sflow_stream(addr, data):

    # Create unpacker
    up = LoggingUnpacker(data)

    version = up.unpack_int('sflow_version')

    up.set_position(0)
    if version == 5:
        read_sample_datagram(up)
    else:
        raise Exception()

    # Check if whole stream was read
    up.done()


def read_sample_datagram(up):
    """Yield all record (flow and counter records) from the sFlow v5
    datagram given by up, which is expected to be an xdrlib.Unpacker
    object."""

    sf = SFlow()

    # Unpack sample_datagram union
    #     uint version
    #     sample_datagram_v5 datagram
    version = up.unpack_int('sflow_version')
    assert(version == 5)

    # Unpack sample_datagram_v5 structure
    #    address agent_address          
    #         IP address of sampling agent, sFlowAgentAddress.
    #    unsigned int sub_agent_id;
    #         Used to distinguishing between datagram streams
    #    unsigned int sequence_number;
    #         Incremented with each sample datagram
    #    unsigned int uptime;
    #         Current time (in milliseconds since device last booted).
    #    sample_record samples<>;       An array of sample records
    af = up.unpack_int('address family (1=IPv4)')
    if af == 1:                 # IPv4
        agent_address = up.unpack_uint('agent address')
    else:
        raise Exception()

    sub_agent_id = up.unpack_uint('sub_agent_id')
    sequence_number = up.unpack_uint('sequence_number')
    uptime = up.unpack_uint('uptime')
    nb_sample_records = up.unpack_uint('number of records')

    
    # Iterating over sample records
    for i in range(nb_sample_records):
        print("read_sample_datagram:Reading sample record",i)

        try:
            read_sample_record(up, sf)
        except EOFError:
            print("read_sample_datagram: EOFError reading sample_record,", \
                      "Premature end of data stream, Skipping record")
            up.set_position(len(up.get_buffer()))
            break


def read_sample_record(up, sample_datagram):

    # Unpack sample_record structure
    #    data_format sample_type;
    #       Specifies the type of sample data
    #    opaque sample_data<>;
    #       A structure corresponding to the sample_type

    # Decode sample type
    sample_type = up.unpack_uint('sample_type')
    enterprise = sample_type >> 12
    format = sample_type & 0xfff
    print('read_sample_record:sample_type == %d (%d, %d)'
          % (sample_type, enterprise, format))

    # Unpack sample data
    sample_data = up.unpack_opaque()
    up_sample_data = LoggingUnpacker(sample_data)
    
    if sample_type == 1:    # enterprise = 0, format = 1 --> flow_record
        read_flow_sample(up_sample_data, sample_datagram)
    elif sample_type == 2: # enterprise = 0, format = 2 --> counter_record
        read_counter_sample(up_sample_data, sample_datagram)
    else:
        raise Exception()

    # Check if whole data block was unpacked
    up_sample_data.done()


def read_flow_sample(up, sample_datagram):
 
    # Unpack flow_sample structure
    #    unsigned int sequence_number;   Incremented with each flow sample
    #    sflow_data_source source_id;    sFlowDataSource
    #    unsigned int sampling_rate;     sFlowPacketSamplingRate
    #    unsigned int sample_pool;
    #         Total number of packets that could have been sampled
    #    unsigned int drops;             
    #        Number of times that the sFlow agent detected 
    #        that a packet marked to be sampled was dropped
    #
    #    interface input;                Interface packet was received on.
    #    interface output;               Interface packet was sent on.
    #    flow_record flow_records<>;     Information about a sampled packet

    sequence_number = up.unpack_uint('sequence_number')
    source_id = up.unpack_uint('source_id')
    sampling_rate = up.unpack_uint('sampling_rate')
    sample_pool = up.unpack_uint('sample_pool')
    drops = up.unpack_uint('drops')
    input_if = up.unpack_uint('input_if')
    output_if = up.unpack_uint('output_if')
    nb_flow_records = up.unpack_uint('nb_flow_records')

    (source_id_index, source_id_value) = decode_sflow_data_source(source_id)

    # Iterating over flow records
    for i in range(nb_flow_records):
        read_flow_record(up, sample_datagram)


def read_flow_record(up, sample_datagram):

    # Unpack flow_record structure
    #     data_format flow_format;      The format of sflow_data
    #     opaque flow_data<>;
    #         Flow data uniquely defined by the flow_format.

    # Unpack data format
    flow_format = up.unpack_uint('flow_format')
    enterprise = flow_format >> 12
    format = flow_format & 0xfff
    print('read_flow_record:flow_format == %d (%d, %d)'
          % (flow_format, enterprise, format))

    # Uppack whole data block
    flow_data = up.unpack_opaque()
    up_flow_data = LoggingUnpacker(flow_data)
    
    # Further unpacking depending on format
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
    #     unsigned int frame_length;
    #         Original length of packet before sampling.
    #     unsigned int stripped;
    #         The number of octets removed from the packet before 
    #                                    extracting the header<> octets.
    #     opaque header<>;               Header bytes

    header_protocol = up.unpack_int('header_protocol')
    frame_length = up.unpack_uint('frame_length')
    stripped = up.unpack_uint('stripped')
    header = up.unpack_opaque()

    # Decode header data
    decode_sampled_header(header)
    
    print('read_sampled_header:header')
    hexdump_bytes(bytes(header))


def read_sampled_ethernet(up, sample_datagram):

    # Unpack Ethernet Frame Data
    #     unsigned int length;
    #         The length of the MAC packet received on the network
    #     mac src_mac;           Source MAC address
    #     mac dst_mac;           Destination MAC address
    #     unsigned int type;     Ethernet packet type

    length = up.unpack_uint('length')
    src_mac = up.unpack_fopaque(6)
    dst_mac = up.unpack_fopaque(6)
    eth_type = up.unpack_uint('eth_type')


def read_sampled_ipv4(up, sample_datagram):

    # Unpack Packet IP version 4 data
    #     unsigned int length;
    #         The length of the IP packet excluding lower layer encapsulations
    #     unsigned int protocol;
    #         IP Protocol type (for example, TCP = 6, UDP = 17)
    #     ip_v4 src_ip;            Source IP Address
    #     ip_v4 dst_ip;            Destination IP Address
    #     unsigned int src_port;   TCP/UDP source port number or equivalent
    #     unsigned int dst_port;   TCP/UDP destination port number or equivalent
    #     unsigned int tcp_flags;  TCP flags
    #     unsigned int tos;        IP type of service

    # Unpack fields
    length = up.unpack_uint('length')
    protocol = up.unpack_uint('protocol')
    src_ip = up.unpack_fopaque(4)
    dst_ip = up.unpack_fopaque(4)
    src_port = up.unpack_uint('src_port')
    dst_port = up.unpack_uint('dst_port')
    tcp_flags = up.unpack_uint('tcp_flags')
    tos = up.unpack_uint('tos')


def decode_sampled_header(header):

    # TODO: Decoder for sampled header data
    up_header = LoggingUnpacker(header)


def read_counter_sample(up, sample_datagram):

    # Unpack counter_sample structure
    #     unsigned int sequence_number;   Incremented with each counter sample generated by this source_id
    #     sflow_data_source source_id;    sFlowDataSource
    #     counter_record counters<>;      Counters polled for this source
    
    sequence_number = up.unpack_uint('sequence_number')
    source_id = up.unpack_uint('source_id')
    nb_counters = up.unpack_uint('nb_counters')

    (source_id_index, source_id_value) = decode_sflow_data_source(source_id)

    # Iterating over counter records
    for i in range(nb_counters):
        read_counter_record(up, sample_datagram)

def read_counter_record(up, sample_datagram):

    # Unpack counter_record structure
    #     data_format counter_format;     The format of counter_data
    #     opaque counter_data<>;          A block of counters uniquely defined by the counter_format.
    
    # Unpack data format
    counter_format = up.unpack_uint('counter_format')
    enterprise = counter_format >> 12
    format = counter_format & 0xfff
    
    # Uppack whole data block
    counter_data = up.unpack_opaque()
    up_counter_data = LoggingUnpacker(counter_data)
    
    # Further unpacking depending on format
    if format == 1:
        read_if_counters(up_counter_data, sample_datagram)
    elif format == 2:
        read_ethernet_counters(up_flow_data, sample_datagram)  
    elif format == 3:
        read_tokenring_counters(up_flow_data, sample_datagram)  
    elif format == 4:
        read_vg_counters(up_flow_data, sample_datagram)  
    elif format == 5:
        read_vlan_counters(up_flow_data, sample_datagram)  
    else:
        print('read_flow_record:Unknown data_format (%d)' % format)

    # Check if everything was unpacked
    up_counter_data.done()


def read_if_counters(up, sample_datagram):

    # Unpack Generic Interface Counters
    #     unsigned int ifIndex;
    #     unsigned int ifType;
    #     unsigned hyper ifSpeed;
    #     unsigned int ifDirection;      derived from MAU MIB (RFC 2668)
    #                                    0 = unkown, 1=full-duplex, 2=half-duplex,
    #                                    3 = in, 4=out
    #     unsigned int ifStatus;         bit field with the following bits assigned
    #                                    bit 0 = ifAdminStatus (0 = down, 1 = up)
    #                                    bit 1 = ifOperStatus (0 = down, 1 = up)
    #     unsigned hyper ifInOctets;
    #     unsigned int ifInUcastPkts;
    #     unsigned int ifInMulticastPkts;
    #     unsigned int ifInBroadcastPkts;
    #     unsigned int ifInDiscards;
    #     unsigned int ifInErrors;
    #     unsigned int ifInUnknownProtos;
    #     unsigned hyper ifOutOctets;
    #     unsigned int ifOutUcastPkts;
    #     unsigned int ifOutMulticastPkts;
    #     unsigned int ifOutBroadcastPkts;
    #     unsigned int ifOutDiscards;
    #     unsigned int ifOutErrors;
    #     unsigned int ifPromiscuousMode;
    
    ifIndex = up.unpack_uint('if_index')
    ifType = up.unpack_uint('if_type')
    ifSpeed = up.unpack_uhyper('if_speed')
    ifDirection = up.unpack_uint('if_direction')
    ifStatus = up.unpack_uint('if_status')
    ifInOctets = up.unpack_uhyper('if_in_octets')
    ifInUcastPkts = up.unpack_uint('if_in_ucasts')
    ifInMulticastPkts = up.unpack_uint('if_in_mcasts')
    ifInBroadcastPkts = up.unpack_uint('if_in_bcasts')
    ifInDiscards = up.unpack_uint('if_in_discards')
    ifInErrors = up.unpack_uint('if_in_errors')
    ifInUnknownProtos = up.unpack_uint('if_in_unknown')
    ifOutOctets = up.unpack_uhyper('if_out_octets')
    ifOutUcastPkts = up.unpack_uint('if_out_ucasts')
    ifOutMulticastPkts = up.unpack_uint('if_out_mcasts')
    ifOutBroadcastPkts = up.unpack_uint('if_out_bcasts')
    ifOutDiscards = up.unpack_uint('if_out_discards')
    ifOutErrors = up.unpack_uint('if_out_errors')
    ifPromiscuousMode = up.unpack_uint('if_promisc')


def read_ethernet_counters(up, sample_datagram):

    # Unpack ethernet_counters structure
    #      unsigned int dot3StatsAlignmentErrors;
    #      unsigned int dot3StatsFCSErrors;
    #      unsigned int dot3StatsSingleCollisionFrames;
    #      unsigned int dot3StatsMultipleCollisionFrames;
    #      unsigned int dot3StatsSQETestErrors;
    #      unsigned int dot3StatsDeferredTransmissions;
    #      unsigned int dot3StatsLateCollisions;
    #      unsigned int dot3StatsExcessiveCollisions;
    #      unsigned int dot3StatsInternalMacTransmitErrors;
    #      unsigned int dot3StatsCarrierSenseErrors;
    #      unsigned int dot3StatsFrameTooLongs;
    #      unsigned int dot3StatsInternalMacReceiveErrors;
    #      unsigned int dot3StatsSymbolErrors;

    dot3StatsAlignmentErrors = up.unpack_uint()
    dot3StatsFCSErrors = up.unpack_uint()
    dot3StatsSingleCollisionFrames = up.unpack_uint()
    dot3StatsMultipleCollisionFrames = up.unpack_uint()
    dot3StatsSQETestErrors = up.unpack_uint()
    dot3StatsDeferredTransmissions = up.unpack_uint()
    dot3StatsLateCollisions = up.unpack_uint()
    dot3StatsExcessiveCollisions = up.unpack_uint()
    dot3StatsInternalMacTransmitErrors = up.unpack_uint()
    dot3StatsCarrierSenseErrors = up.unpack_uint()
    dot3StatsFrameTooLongs = up.unpack_uint()
    dot3StatsInternalMacReceiveErrors = up.unpack_uint()
    dot3StatsSymbolErrors = up.unpack_uint()


def read_tokenring_counters(up, sample_datagram):

    # Unpack tokenring_counters structure
    #     unsigned int dot5StatsLineErrors;
    #     unsigned int dot5StatsBurstErrors;
    #     unsigned int dot5StatsACErrors;
    #     unsigned int dot5StatsAbortTransErrors;
    #     unsigned int dot5StatsInternalErrors;
    #     unsigned int dot5StatsLostFrameErrors;
    #     unsigned int dot5StatsReceiveCongestions;
    #     unsigned int dot5StatsFrameCopiedErrors;
    #     unsigned int dot5StatsTokenErrors;
    #     unsigned int dot5StatsSoftErrors;
    #     unsigned int dot5StatsHardErrors;
    #     unsigned int dot5StatsSignalLoss;
    #     unsigned int dot5StatsTransmitBeacons;
    #     unsigned int dot5StatsRecoverys;
    #     unsigned int dot5StatsLobeWires;
    #     unsigned int dot5StatsRemoves;
    #     unsigned int dot5StatsSingles;
    #     unsigned int dot5StatsFreqErrors;

    dot5StatsLineErrors = up.unpack_uint()
    dot5StatsBurstErrors = up.unpack_uint()
    dot5StatsACErrors = up.unpack_uint()
    dot5StatsAbortTransErrors = up.unpack_uint()
    dot5StatsInternalErrors = up.unpack_uint()
    dot5StatsLostFrameErrors = up.unpack_uint()
    dot5StatsReceiveCongestions = up.unpack_uint()
    dot5StatsFrameCopiedErrors = up.unpack_uint()
    dot5StatsTokenErrors = up.unpack_uint()
    dot5StatsSoftErrors = up.unpack_uint()
    dot5StatsHardErrors = up.unpack_uint()
    dot5StatsSignalLoss = up.unpack_uint()
    dot5StatsTransmitBeacons = up.unpack_uint()
    dot5StatsRecoverys = up.unpack_uint()
    dot5StatsLobeWires = up.unpack_uint()
    dot5StatsRemoves = up.unpack_uint()
    dot5StatsSingles = up.unpack_uint()
    dot5StatsFreqErrors = up.unpack_uint()


def read_vg_counters(up, sample_datagram):

    # Unpack 100 BaseVG interface counters
    #     unsigned int dot12InHighPriorityFrames;
    #     unsigned hyper dot12InHighPriorityOctets;
    #     unsigned int dot12InNormPriorityFrames;
    #     unsigned hyper dot12InNormPriorityOctets;
    #     unsigned int dot12InIPMErrors;
    #     unsigned int dot12InOversizeFrameErrors;
    #     unsigned int dot12InDataErrors;
    #     unsigned int dot12InNullAddressedFrames;
    #     unsigned int dot12OutHighPriorityFrames;
    #     unsigned hyper dot12OutHighPriorityOctets;
    #     unsigned int dot12TransitionIntoTrainings;
    #     unsigned hyper dot12HCInHighPriorityOctets;
    #     unsigned hyper dot12HCInNormPriorityOctets;
    #     unsigned hyper dot12HCOutHighPriorityOctets;

    dot12InHighPriorityFrames = up.unpack_uint()
    dot12InHighPriorityOctets = up.unpack_uhyper()
    dot12InNormPriorityFrames = up.unpack_uint()
    dot12InNormPriorityOctets = up.unpack_uhyper()
    dot12InIPMErrors = up.unpack_uint()
    dot12InOversizeFrameErrors = up.unpack_uint()
    dot12InDataErrors = up.unpack_uint()
    dot12InNullAddressedFrames = up.unpack_uint()
    dot12OutHighPriorityFrames = up.unpack_uint()
    dot12OutHighPriorityOctets = up.unpack_uhyper()
    dot12TransitionIntoTrainings = up.unpack_uint()
    dot12HCInHighPriorityOctets = up.unpack_uhyper()
    dot12HCInNormPriorityOctets = up.unpack_uhyper()
    dot12HCOutHighPriorityOctets = up.unpack_uhyper()


def read_vlan_counters(up, sample_datagram):

    # Unpack VLAN counters
    #     unsigned int vlan_id;
    #     unsigned hyper octets;
    #     unsigned int ucastPkts;
    #     unsigned int multicastPkts;
    #     unsigned int broadcastPkts;
    #     unsigned int discards;

    vlan_id = up.unpack_uint()
    octets = up.unpack_uhyper()
    ucastPkts = up.unpack_uint()
    multicastPkts = up.unpack_uint()
    broadcastPkts = up.unpack_uint()
    discards = up.unpack_uint()


class SFlow (object):
    """Describes the header data of an sFlow v5 datagram."""
    def __init__(self):

        self.version = 5
        self.src_addr = 0
        self.src_port = 0
        self.sub_agent_id = 0
        self.sequence_number = 0
        self.uptime = 0
        self.samples = []

    def __repr__(self):
        return ('<sflow5,src=%s:%d,agent=%d,seq=%d,up=%dh, samples=%s>'
                % (self.src_addr, 
                   self.src_port, 
                   self.sub_agent_id, 
                   self.sequence_number, 
                   floor(self.uptime/3600000.0), 
                   str(self.samples)))


class FlowSample (object):
    """Describes an sFlow v5 flow sample."""
    def __init__(self, sflow_info):
        self.sflow_info = sflow_info
        self.flow_records = []

    def __repr__(self):
        return '<flow-sample, %d flow-recs>' % (len(self.flow_records))


class IfCounterRecord (object):
    """sFlow v5 interface counters."""

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
    """sFlow v5 ethernet counters."""

    def __init__(self):
        pass

    def __repr__(self):
        pass


class CounterSample (object):
    """Describes an sFlow v5 counter sample."""
    def __init__(self):
        self.counter_records = []

    def __repr__(self):
        return '<counter-sample, %d counter-recs>' % (len(self.counter_records))


class FlowRecord (object):
    """Describes an sFlow v5 flow record."""

    def __init__(self, sample):
        self.sample = sample

    def __repr__(self):
        return 'FlowRecord'


class FlowRecordIPv4 (FlowRecord):
    """Describes an sFlow v5 flow record for IPv4."""

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
        return ('<FlowRecordIPv4: src=%x:%d, dst=%x:%d'
                % (self.src_ip, self.src_port, self.dst_ip, self.dst_port))


class FlowRecordRaw (FlowRecord):
    """Describes an sFlow v5 flow record for raw packets."""

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
    vlan_id = up.unpack_uint('vlan_id')
    octets = up.unpack_uhyper('octets')
    ucast_pkts = up.unpack_uint('ucasts')
    multicast_pkts = up.unpack_uint('mcasts')
    broadcast_pkts = up.unpack_uint('bcasts')
    discards = up.unpack_uint('discards')
    # print('vlan_id: %d, octet: %d, ucast: %d, mcast: %d, bcast: %d, discard: %d'
    #       % (vlan_id, octets, ucast_pkts,
    #          multicast_pkts, broadcast_pkts, discards))


def readProcessorInfo(up):
    cpu_5s = up.unpack_int()
    cpu_1m = up.unpack_int()
    cpu_5m = up.unpack_int()
    total_memory = up.unpack_uhyper()
    free_memory = up.unpack_uhyper()

    print('<procinfo cpu (5s/1m/5m): %d %d %d  |mem(free/total): %d/%d'
          % (cpu_5s, cpu_1m, cpu_5m, free_memory, total_memory))


def readCounterRecord(up):
    data_format = up.unpack_uint()
    data_end = up.unpack_uint() + up.get_position() # order of
                                                    # funcalls is
                                                    # important
    items = []
    if data_format == 1:
        # enterprise = 0, format = 1 -> struct if_counters
        print('if_counters')
        while up.get_position() < data_end - 1:
            items.append(readIfCounters(up))
    elif data_format == 2:
        # enterprise = 0, format = 2 -> struct ethernet_counters
        print('ethernet_counters')
        while up.get_position() < data_end - 1:
            items.append(readEthernetCounters(up))
    elif data_format == 5:      
        # enterprise = 0, format = 5 -> struct vlan_counters
        print('vlan_counters')
        while up.get_position() < data_end - 1:
            items.append(readVlanCounters(up))
    elif data_format == 1001:   
        # enterprise = 0, format = 1001 -> struct processor
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


def main():
    listen_addr = ("0.0.0.0", 6343)
    sock = socket(AF_INET, SOCK_DGRAM)
    sock.bind(listen_addr)
    while True:
        data, addr = sock.recvfrom(65535)
        read_sflow_stream(addr, data)

if __name__ == '__main__':
    main()
