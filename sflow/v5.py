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


class EthernetHeader ():
    """Represents an IEEE 802.3 header including its payload."""

    def __init__(self, src, dst, ether_type, payload, length):
        self.src_mac = src
        self.dst_mac = dst
        self.ether_type = ether_type
        self.payload = payload
        self.length = length

    def __repr__(self):
        return ('<EthernetHeader| src: %s, dst: %s, type: %s, length: %d>' %
                (mac_to_string(self.src_mac),
                 mac_to_string(self.dst_mac),
                 ether_type_to_string(self.ether_type),
                 self.length))


class IEEE8021QHeader ():
    """Represents an IEEE 802.1Q header including its payload."""

    def __init__(self, vlan_id, src, dst, ether_type, payload, length):
        self.vlan_id = vlan_id
        self.src_mac = src
        self.dst_mac = dst
        self.ether_type = ether_type
        self.payload = payload
        self.length = length

    def __repr__(self):
        repr_ = ('<IEEE8021QHeader| vlan_id: %d, src: %s, dst: %s, type: %s, length: %d>' %
                 (self.vlan_id,
                  mac_to_string(self.src_mac),
                  mac_to_string(self.dst_mac),
                  ether_type_to_string(self.ether_type),
                  self.length))
        if self.payload:
            repr_ += '\n  ' + repr(self.payload)
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

    def __repr__(self):
        return ('<IPv4Header| src: %s, dst: %s, proto: %s, version: %d, ihl: %d>' %
                (ip_to_string(self.src),
                 ip_to_string(self.dst),
                 ip_proto_to_string(self.protocol),
                 self.version,
                 self.ihl))


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


def read_sflow_stream(addr, data):

    # Create unpacker
    up = Unpacker(data)

    # Get version version of sflow packet
    version = up.unpack_int()

    # Reset to beginning
    up.set_position(0)
    if version == 5:
        return read_sample_datagram(up)
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
    version = up.unpack_int()
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
    af = up.unpack_int()
    if af == 1:                 # IPv4
        agent_address = up.unpack_uint()
    else:
        raise Exception()

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

    sequence_number = up.unpack_uint()
    source_id = up.unpack_uint()
    sampling_rate = up.unpack_uint()
    sample_pool = up.unpack_uint()
    drops = up.unpack_uint()
    input_if = up.unpack_uint()
    output_if = up.unpack_uint()
    nb_flow_records = up.unpack_uint()

    (source_id_index, source_id_value) = decode_sflow_data_source(source_id)

    for i in range(nb_flow_records):
        yield read_flow_record(up, sample_datagram)


def read_flow_record(up, sample_datagram):
    """Reads a 'struct flow_record' (p. 29)"""

    flow_format = up.unpack_uint()
    flow_data = up.unpack_opaque()
    up_flow_data = Unpacker(flow_data)
    
    if flow_format == FLOW_DATA_RAW_HEADER:
        return read_sampled_header(up_flow_data, sample_datagram)
    elif flow_format == FLOW_DATA_ETHERNET_HEADER:
        return read_sampled_ethernet(up_flow_data, sample_datagram)  
    elif flow_format == FLOW_DATA_IPV4_HEADER:
        return read_sampled_ipv4(up_flow_data, sample_datagram)
    else:
        return 'read_flow_record:Unknown data_format (%d)' % flow_format

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
        dst = header[0:6]
        src = header[6:12]
        ether_type = header[12] * 256 + header[13]

        if ether_type == ETHER_TYPE_IEEE8021Q:
            vlan_id = header[14] * 256 + header[15]
            ether_type = header[16] * 256 + header[17]

            h = IEEE8021QHeader(vlan_id, dst, src, ether_type, None, len(header))

            # 18 + 20 = <bytes read so far> + <minimal IP header length>
            if len(header) >= 18 + 20:
                h.payload = decode_ipv4(header[18:])
            return h
        else:
            h = EthernetHeader(dst, src, ether_type, None, len(header))
            if len(header) >= 14 + 20:
                h.payload = decode_ipv4(header[18:])
            return h


def decode_ipv4(header):
    return IPv4Header(header)


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
    return EthernetHeader(dst, src, ether_type, None, len(up.get_buffer()))
    

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


def read_counter_sample(up, sample_datagram):

    # Unpack counter_sample structure
    #     unsigned int sequence_number;   Incremented with each counter sample generated by this source_id
    #     sflow_data_source source_id;    sFlowDataSource
    #     counter_record counters<>;      Counters polled for this source
    
    sequence_number = up.unpack_uint()
    source_id = up.unpack_uint()
    nb_counters = up.unpack_uint()

    (source_id_index, source_id_value) = decode_sflow_data_source(source_id)

    for i in range(nb_counters):
        yield read_counter_record(up, sample_datagram)


def read_counter_record(up, sample_datagram):

    # Unpack counter_record structure
    #     data_format counter_format;     The format of counter_data
    #     opaque counter_data<>;          A block of counters uniquely defined by the counter_format.
    
    counter_format = up.unpack_uint()
    counter_data = up.unpack_opaque()
    up_counter_data = Unpacker(counter_data)
    
    if counter_format == 1:
        return read_if_counters(up_counter_data, sample_datagram)
    elif counter_format == 2:
        return read_ethernet_counters(up_flow_data, sample_datagram)  
    elif counter_format == 3:
        return read_tokenring_counters(up_flow_data, sample_datagram)  
    elif counter_format == 4:
        return read_vg_counters(up_flow_data, sample_datagram)  
    elif counter_format == 5:
        return read_vlan_counters(up_flow_data, sample_datagram)  
    else:
        return 'read_flow_record:Unknown data_format (%d)' % format

    # TODO: This is useless now.  Where can we put this instead?
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
    
    return IfCounters(up)
    

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

    return None
    


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

    return None


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

    return None


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

    return None


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
        for rec in read_sflow_stream(addr, data):
            print(rec)
