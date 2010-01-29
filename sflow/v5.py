"""Library for parsing sFlow (v5) datagrams.

sFlow version 5 is described in www.sflow.org/sflow_version_5.txt.

Since the datagram format is specified using XDR the following RFCs
may be useful: 1014, 1832, 4506."""


# Standards and Specs
#
# The sFlow v5 format is documented in
# www.sflow.org/sflow_version_5.txt, a copy of which is included in
# the doc/ subdirectory of the pyflow repo.  Page numbers refer to
# this document.
#
#
# The IEEE 802.x / ISO/IEC 8802.x and IPv4 headers are documented at
#
# http://de.wikipedia.org/wiki/IPv4#Header-Format
# http://en.wikipedia.org/wiki/IEEE_802.1Q
# http://en.wikipedia.org/wiki/Ethernet


from xdrlib import Unpacker
from socket import socket, AF_INET, SOCK_DGRAM, ntohl
from math import floor
from util import ip_to_string, hexdump_bytes, mac_to_string, ether_type_to_string, ip_proto_to_string, speed_to_string


# Constants for the sample_data member of 'struct sample_record'
# (p. 32).  See pp. 29-31 for the meaning of these values.
SAMPLE_DATA_FLOW_RECORD = 1
SAMPLE_DATA_COUNTER_RECORD = 2


# Constants for the flow_format member of 'struct flow_record'
# (p. 29).  See pp. 35-41 for the meaning of these values.
FLOW_DATA_RAW_HEADER = 1
FLOW_DATA_ETHERNET_HEADER = 2
FLOW_DATA_IPV4_HEADER = 3
FLOW_DATA_IPV6_HEADER = 4
FLOW_DATA_EXT_SWITCH = 1001
FLOW_DATA_EXT_ROUTER = 1002
FLOW_DATA_EXT_GATEWAY = 1003
FLOW_DATA_EXT_USER = 1004
FLOW_DATA_EXT_URL = 1005
FLOW_DATA_EXT_MPLS = 1006
FLOW_DATA_EXT_NAT = 1007
FLOW_DATA_EXT_MPLS_TUNNEL = 1008
FLOW_DATA_EXT_MPLS_VC = 1009
FLOW_DATA_EXT_MPLS_FEC = 1010
FLOW_DATA_EXT_MPLS_LVP_FEC = 1011
FLOW_DATA_EXT_VLAN_TUNNEL = 1012


COUNTER_DATA_GENERIC = 1
COUNTER_DATA_ETHERNET= 2
COUNTER_DATA_TOKENRING = 3
COUNTER_DATA_VG = 4
COUNTER_DATA_VLAN = 5
COUNTER_DATA_PROCESSOR = 1001

# Constants for 'enum header_protocol'.  See p.35 of the sFlow v5
# spec.
HEADER_PROTO_ETHERNET_ISO88023 = 1
HEADER_PROTO_ISO88024_TOKENBUS = 2
HEADER_PROTO_ISO88025_TOKENRING = 3,
HEADER_PROTO_FDDI = 4
HEADER_PROTO_FRAME_RELAY = 5
HEADER_PROTO_X25 = 6
HEADER_PROTO_PPP = 7
HEADER_PROTO_SMDS = 8
HEADER_PROTO_AAL5 = 9
HEADER_PROTO_AAL5_IP = 10
HEADER_PROTO_IPV4 = 11
HEADER_PROTO_IPV6 = 12
HEADER_PROTO_MPLS = 13
HEADER_PROTO_POS = 14


# Constants decribing the values of the 'type' field of
# IEEE802.3/IEEE802.1Q headers.
ETHER_TYPE_IEEE8021Q = 0x8100


class Datagram (object):
    """Describes the header data of an sFlow v5 datagram."""
    def __init__(self, addr, agent_address):
        self.version = 5
        self.src_addr = addr[0]
        self.src_port = addr[1]
        self.agent_addr = agent_address
        self.sub_agent_id = 0
        self.sequence_number = 0
        self.uptime = 0

    def __repr__(self):
        return ('<Datagram| src: %s: %d, agent: %s(%d), seq: %d, uptime: %dh>'
                % (self.src_addr, 
                   self.src_port, 
                   ip_to_string(self.agent_addr),
                   self.sub_agent_id, 
                   self.sequence_number, 
                   floor(self.uptime/3600000.0)))


class FlowRecord ():
    def __init__(self, flow_sample, data):
        self.flow_sample = flow_sample
        self.data = data

    def __repr__(self):
        return '<FlowRecord>\n  %s\n  %s' % (repr(self.flow_sample), repr(self.data))


class FlowSample ():

    def __init__(self, datagram):
        self.datagram = datagram

    def fromUnpacker(self, up):
        self.sequence_number = up.unpack_uint()
        self.source_id = up.unpack_uint()
        self.sampling_rate = up.unpack_uint()
        self.sample_pool = up.unpack_uint()
        self.drops = up.unpack_uint()
        self.input_if = up.unpack_uint()
        self.output_if = up.unpack_uint()
        
    def __repr__(self):
        return ('<FlowSample| seq: %d, in_if: %d, out_if: %d, rate: %d>\n    %s' %
                (self.sequence_number,
                 self.input_if,
                 self.output_if,
                 self.sampling_rate,
                 repr(self.datagram)))


class EthernetHeader ():
    """Represents an IEEE 802.3 header including its payload."""

    def __init__(self, header):
        self.src = header[0:6]
        self.dst = header[6:12]
        self.ether_type = header[12:14]
        self.payload = None

    def __repr__(self):
        return ('<EthernetHeader| src: %s, dst: %s, type: %s>' %
                (mac_to_string(self.src),
                 mac_to_string(self.dst),
                 ether_type_to_string(self.ether_type)))


class IEEE8021QHeader ():
    """Represents an IEEE 802.1Q header including its payload."""

    def __init__(self, header):
        self.dst = header[0:6]
        self.src = header[6:12]
        # header[12:14] contains the value 0x8100, indicating that
        # this is not a regular Ethernet frame, but a IEEE 802.1q
        # frame.
        self.vlan_id = header[14] * 256 + header[15]
        self.ether_type = header[16] * 256 + header[17]
        self.payload = None

    def __repr__(self):
        repr_ = ('<IEEE8021QHeader| vlan_id: %d, src: %s, dst: %s, type: %s>' %
                 (self.vlan_id,
                  mac_to_string(self.src),
                  mac_to_string(self.dst),
                  ether_type_to_string(self.ether_type)))
        if self.payload:
            repr_ += '\n    ' + repr(self.payload)
        return repr_



class IPv4Header ():
    """Represents an IPv4 header including the (possibly incomplete)
    payload."""

    def __init__(self, header):
        self.version = (header[0] & 0xf0) >> 4
        self.ihl = header[0] & 0x0f
        self.tos = header[1]
        self.length = header[2] * 256 + header[3]
        self.ident = header[4] * 256 + header[5]
        self.flags = header[6] & 0x07
        self.fragment_offset = ((header[6] & 0xf8) >> 3) * 256 + header[7]
        self.ttl = header[8]
        self.protocol = header[9]
        self.chksum = header[10] * 256 + header[11]
        self.src = ((header[15] << 24) +
                    (header[14] << 16) +
                    (header[13] << 8) +
                    header[12])
        self.dst = ((header[19] << 24) +
                    (header[18] << 16) +
                    (header[17] << 8) +
                    header[16])
        if len(header) > 20:
            if self.protocol == 6:
                self.payload = TCPHeader(header[20:])
            elif self.protocol == 17:
                self.payload = UDPHeader(header[20:])
        else:
            self.payload = None

    def __repr__(self):
        repr_ = ('<IPv4Header| src: %s, dst: %s, proto: %s paylen: %d>' %
                 (ip_to_string(self.src),
                  ip_to_string(self.dst),
                  ip_proto_to_string(self.protocol),
                  self.length - self.ihl * 4))
        if self.payload:
            repr_ += '\n      %s' % repr(self.payload)
        return repr_


class TCPHeader ():

    def __init__(self, header):
        self.src_port = header[1] * 256 + header[0]
        self.dst_port = header[3] * 256 + header[2]

    def __repr__(self):
        return ('<TCPHeader| src_port: %d, dst_port: %d>' %
                (self.src_port, self.dst_port))


class UDPHeader ():
    def __init__(self, header):
        self.src_port = header[1] * 256 + header[0]
        self.dst_port = header[3] * 256 + header[2]

    def __repr__(self):
        return ('<UDPHeader| src_port: %d, dst_port: %d>' %
                (self.src_port, self.dst_port))


class CounterRecord ():
    def __init__(self, counter_sample, data):
        self.counter_sample = counter_sample
        self.data = data

    def __repr__(self):
        return ('<CounterRecord>\n  %s\n  %s' %
                (repr(self.counter_sample),
                 repr(self.data)))


class CounterSample ():
    def __init__(self, datagram):
        self.datagram = datagram

    def __repr__(self):
        return '<CounterSample>\n    %s' % repr(self.datagram)


class IfCounters ():
    def __init__(self, up):
        self.index = up.unpack_uint()
        self.if_type = up.unpack_uint()
        self.speed = up.unpack_uhyper()
        self.direction = up.unpack_uint()
        self.status = up.unpack_uint()
        self.in_octets = up.unpack_uhyper()
        self.in_ucasts = up.unpack_uint()
        self.in_mcasts = up.unpack_uint()
        self.in_bcasts = up.unpack_uint()
        self.in_discards = up.unpack_uint()
        self.in_errors = up.unpack_uint()
        self.in_unknown_protos = up.unpack_uint()
        self.out_octets = up.unpack_uhyper()
        self.out_ucasts = up.unpack_uint()
        self.out_mcasts = up.unpack_uint()
        self.out_bcasts = up.unpack_uint()
        self.out_discards = up.unpack_uint()
        self.out_errors = up.unpack_uint()
        self.promiscuous_mode = up.unpack_uint()

    def __repr__(self):
        return ('<IfCounters| idx: %d, speed: %s, in_octets: %d, out_octets: %d>' %
                (self.index,
                 speed_to_string(self.speed),
                 self.in_octets,
                 self.out_octets))


def decode_sflow_data_source(sflow_data_source):
    """Decodes a sflow_data_source as described in the sFlow v5
    spec."""
    # source type should be one of
    #   0 = ifIndex
    #   1 = smonVlanDataSource
    #   2 = entPhysicalEntry

    source_type = sflow_data_source >> 24
    value = sflow_data_source & 0xfff

    return (source_type, value)


def read_datagram(addr, data):
    """Yield all record (flow and counter records) from the sFlow v5
    datagram given by up, which is expected to be an xdrlib.Unpacker
    object."""

    up = Unpacker(data)

    version = up.unpack_int()
    if not version == 5:
        hexdump_bytes(data)
        raise Exception()

    af = up.unpack_int()
    if af == 1:                 # IPv4
        agent_address = up.unpack_uint()
    else:
        raise Exception()

    sf = Datagram(addr, agent_address)

    sub_agent_id = up.unpack_uint()
    sequence_number = up.unpack_uint()
    uptime = up.unpack_uint()
    nb_sample_records = up.unpack_uint()

    # Iterating over sample records
    for i in range(nb_sample_records):
        try:
            return read_sample_record(up, sf)
        except EOFError:
            stderr.write("read_sample_datagram: EOFError reading sample_record,", \
                      "Premature end of data stream, Skipping record\n")
            up.set_position(len(up.get_buffer()))
            break


def read_sample_record(up, sample_datagram):

    # Unpack sample_record structure
    #    data_format sample_type;
    #       Specifies the type of sample data
    #    opaque sample_data<>;
    #       A structure corresponding to the sample_type

    sample_type = up.unpack_uint()

    sample_data = up.unpack_opaque()
    up_sample_data = Unpacker(sample_data)
    
    if sample_type == SAMPLE_DATA_FLOW_RECORD:
        return read_flow_sample(up_sample_data, sample_datagram)
    elif sample_type == SAMPLE_DATA_COUNTER_RECORD:
        return read_counter_sample(up_sample_data, sample_datagram)

    else:
        raise Exception()

    # Check if whole data block was unpacked
    up_sample_data.done()


def read_flow_sample(up, datagram):
    sample = FlowSample(datagram)
    sample.fromUnpacker(up)

    nb_flow_records = up.unpack_uint()

    for i in range(nb_flow_records):
        yield read_flow_record(up, sample)


def read_flow_record(up, sample):
    """Reads a 'struct flow_record' (p. 29)"""

    flow_format = up.unpack_uint()
    flow_data = up.unpack_opaque()
    up_flow_data = Unpacker(flow_data)

    if flow_format == FLOW_DATA_RAW_HEADER:
        res = FlowRecord(sample, read_sampled_header(up_flow_data))
    elif flow_format == FLOW_DATA_ETHERNET_HEADER:
        res = FlowRecord(sample, read_sampled_ethernet(up_flow_data))
    elif flow_format == FLOW_DATA_IPV4_HEADER:
        res = FlowRecord(sample, read_sampled_ipv4(up_flow_data))
    else:
        res = 'read_flow_record:Unknown data_format (%d)' % flow_format

    up_flow_data.done()
    return res


def read_sampled_header(up):

    # Unpack sampled raw header
    #     header_protocol protocol;      Format of sampled header
    #     unsigned int frame_length;
    #         Original length of packet before sampling.
    #     unsigned int stripped;
    #         The number of octets removed from the packet before 
    #                                    extracting the header<> octets.
    #     opaque header<>;               Header bytes

    header_protocol = up.unpack_int()
    frame_length = up.unpack_uint()
    stripped = up.unpack_uint()
    header = up.unpack_opaque()

    if header_protocol == HEADER_PROTO_ETHERNET_ISO88023:
        return decode_iso88023(header)
    else:
        return 'Can''t decode header with header protocol %d' % header_protocol


def decode_iso88023(header):
    # Full ethernet header included?
    if len(header) >= 14:
        ether_type = header[12] * 256 + header[13]        
        if ether_type == ETHER_TYPE_IEEE8021Q:
            h = IEEE8021QHeader(header)
            # 18 + 20 = <bytes read so far> + <minimal IP header length>
            if len(header) >= 18 + 20:
                h.payload = IPv4Header(header[18:])
            return h
        else:
            h = EthernetHeader(header)
            if len(header) >= 14 + 20:
                h.payload = IPv4Header(header[14:])
            return h


def read_sampled_ethernet(up, sample_datagram):

    # Unpack Ethernet Frame Data
    #     unsigned int length;
    #         The length of the MAC packet received on the network
    #     mac src_mac;           Source MAC address
    #     mac dst_mac;           Destination MAC address
    #     unsigned int type;     Ethernet packet type

    length = up.unpack_uint()
    src_mac = up.unpack_fopaque(6)
    dst_mac = up.unpack_fopaque(6)
    eth_type = up.unpack_uint()

    # TODO: len(..) is almost certainly wrong.  Also check the order of dst,src.
    return EthernetHeader(src, dst, ether_type, None, len(up.get_buffer()))
    

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
    length = up.unpack_uint()
    protocol = up.unpack_uint()
    src_ip = up.unpack_fopaque(4)
    dst_ip = up.unpack_fopaque(4)
    src_port = up.unpack_uint()
    dst_port = up.unpack_uint()
    tcp_flags = up.unpack_uint()
    tos = up.unpack_uint()

    return None


def read_counter_sample(up, datagram):

    # Unpack counter_sample structure
    #     unsigned int sequence_number;   Incremented with each counter sample generated by this source_id
    #     sflow_data_source source_id;    sFlowDataSource
    #     counter_record counters<>;      Counters polled for this source
    
    sequence_number = up.unpack_uint()
    source_id = up.unpack_uint()
    nb_counters = up.unpack_uint()

    sample = CounterSample(datagram)

    for i in range(nb_counters):
        yield read_counter_record(up, sample)


def read_counter_record(up, sample):

    # Unpack counter_record structure
    #     data_format counter_format;     The format of counter_data
    #     opaque counter_data<>;          A block of counters uniquely defined by the counter_format.
    
    counter_format = up.unpack_uint()
    counter_data = up.unpack_opaque()
    up_counter_data = Unpacker(counter_data)
    
    if counter_format == COUNTER_DATA_GENERIC:
        return CounterRecord(sample, read_if_counters(up_counter_data))
    elif counter_format == COUNTER_DATA_ETHERNET:
        return CounterRecord(sample, read_ethernet_counters(up_flow_data))
    elif counter_format == COUNTER_DATA_TOKENRING:
        return CounterRecord(sample, read_tokenring_counters(up_flow_data))
    elif counter_format == COUNTER_DATA_VG:
        return CounterRecord(sample, read_vg_counters(up_flow_data))
    elif counter_format == COUNTER_DATA_VLAN:
        return CounterRecord(sample, read_vlan_counters(up_flow_data))
    else:
        return 'read_flow_record:Unknown data_format (%d)' % format


def read_if_counters(up):

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
    
    return IfCounters(up)
    

def read_ethernet_counters(up):

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

    return None
    


def read_tokenring_counters(up):

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

    return None


def read_vg_counters(up):

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

    return None


def read_vlan_counters(up):

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

    return None


def listenForSFlow(callback, address='0.0.0.0', port=6343):
    listen_on = (address, port)
    sock = socket(AF_INET, SOCK_DGRAM)
    sock.bind(listen_on)
    while True:
        datagram, src_addr = sock.recvfrom(65535)
        sflow_data = readSFlow(src_addr, datagram)
        for sample in sflow_data:
            callback(src_addr, sample)


if __name__ == '__main__':
    listen_addr = ("0.0.0.0", 6343)
    sock = socket(AF_INET, SOCK_DGRAM)
    sock.bind(listen_addr)
    while True:
        data, addr = sock.recvfrom(65535)
        for rec in read_datagram(addr, data):
            print(rec)
