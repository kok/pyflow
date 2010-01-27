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
from util import ip_to_string, hexdump_bytes, mac_to_string, ether_type_to_string, ip_proto_to_string


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
        return ('<IEEE8021QHeader| vlan_id: %d, src: %s, dst: %s, type: %s, length: %d>' %
                (self.vlan_id,
                 mac_to_string(self.src_mac),
                 mac_to_string(self.dst_mac),
                 ether_type_to_string(self.ether_type),
                 self.length))



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

    sample_type = up.unpack_uint()

    sample_data = up.unpack_opaque()
    up_sample_data = Unpacker(sample_data)
    
    if sample_type == SAMPLE_DATA_FLOW_RECORD:
        read_flow_sample(up_sample_data, sample_datagram)
    elif sample_type == SAMPLE_DATA_COUNTER_RECORD:
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
    print("read_flow_sample:source_id = %d (%d, %d)"
          % (source_id,source_id_index, source_id_value))
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
    #     opaque flow_data<>;
    #         Flow data uniquely defined by the flow_format.

    # Unpack data format
    flow_format = up.unpack_uint()
    enterprise = flow_format >> 12
    format = flow_format & 0xfff
    print('read_flow_record:flow_format == %d (%d, %d)'
          % (flow_format, enterprise, format))

    # Uppack whole data block
    flow_data = up.unpack_opaque()
    up_flow_data = Unpacker(flow_data)
    
    # Further unpacking depending on format
    if format == FLOW_DATA_RAW_HEADER:
        read_sampled_header(up_flow_data, sample_datagram)
    elif format == FLOW_DATA_ETHERNET_HEADER:
        read_sampled_ethernet(up_flow_data, sample_datagram)  
    elif format == FLOW_DATA_IPV4_HEADER:
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

    header_protocol = up.unpack_int()
    frame_length = up.unpack_uint()
    stripped = up.unpack_uint()
    header = up.unpack_opaque()

    if header_protocol == HEADER_PROTO_ETHERNET_ISO88023:
        decode_iso88023(header)
    else:
        print('Can''t decode header with header protocol %d'
              % header_protocol)

    print("read_sampled_header:header_protocol = %d" % header_protocol)
    print("read_sampled_header:frame_length = %d" % frame_length)
    print("read_sampled_header:stripped = %d" % stripped)

    # print("read_sampled_header:header",header)
    print('read_sampled_header:header')
    hexdump_bytes(bytes(header))


def decode_iso88023(header):
    # Full ethernet header included?
    if len(header) >= 14:
        dst = header[0:6]
        src = header[6:12]
        ether_type = header[12] * 256 + header[13]

        if ether_type == ETHER_TYPE_IEEE8021Q:
            vlan_id = header[14] * 256 + header[15]
            ether_type = header[16] * 256 + header[17]

            print(IEEE8021QHeader(vlan_id, dst, src, ether_type, None, len(header)))
            decode_ipv4(header[18:])
        else:
            print(EthernetHeader(dst, src, ether_type, None, len(header)))

        hexdump_bytes(header)


def decode_ipv4(header):
    print(IPv4Header(header))

# def decode_iso88023(header):
#     # Full ethernet header included?
#     if len(header) >= 14:
#         dst = header[0:6]
#         src = header[6:12]
#         ether_type = header[12] * 256 + header[13]
        
#         print(EthernetHeader(dst, src, ether_type, None, len(header)))
#         hexdump_bytes(header)

#         if ether_type == ETHER_TYPE_IEEE8021Q:
#             print(decode_ieee8021q(header[14:]))


# def decode_ieee8021q(header):
#     vlan_id = header[0] * 256 + header[1]
#     dst = header[2:8]
#     src = header[8:14]
#     ether_type = header[14] * 256 + header[15]
#     print(IEEE8021QHeader(vlan_id, dst, src, ether_type, None, len(header)))


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

    print("read_sampled_ethernet:length = %d" % length)
    print("read_sampled_ethernet:src_mac = %d" % src_mac)
    print("read_sampled_ethernet:dst_mac = %d" % dst_mac)
    print("read_sampled_ethernet:eth_type = %d" % eth_type)
    

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

    # Some debug output
    print("read_sampled_ipv4:length = %d" % length)
    print("read_sampled_ipv4:protocol = %d" % protocol)
    print("read_sampled_ipv4:src_ip = %d (%s)" % (src_ip, ip_to_string(src_ip)))
    print("read_sampled_ipv4:dst_ip = %d (%s)" % (dst_ip, ip_to_string(dst_ip)))
    print("read_sampled_ipv4:src_port = %d" % src_port)
    print("read_sampled_ipv4:dst_port = %d" % dst_port)
    print("read_sampled_ipv4:tcp_flags = %d" % tcp_flags)
    print("read_sampled_ipv4:tos = %d" % tos)
    

def read_counter_sample(up, sample_datagram):

    # Unpack counter_sample structure
    #     unsigned int sequence_number;   Incremented with each counter sample generated by this source_id
    #     sflow_data_source source_id;    sFlowDataSource
    #     counter_record counters<>;      Counters polled for this source
    
    sequence_number = up.unpack_uint()
    source_id = up.unpack_uint()
    nb_counters = up.unpack_uint()

    (source_id_index, source_id_value) = decode_sflow_data_source(source_id)

    # Some debug output
    print("read_counter_sample:sequence_number = %d" % sequence_number)
    print("read_counter_sample:source_id = %d (%d, %d)" % (source_id,source_id_index, source_id_value))

    # Iterating over counter records
    for i in range(nb_counters):
        read_counter_record(up, sample_datagram)

def read_counter_record(up, sample_datagram):

    # Unpack counter_record structure
    #     data_format counter_format;     The format of counter_data
    #     opaque counter_data<>;          A block of counters uniquely defined by the counter_format.
    
    # Unpack data format
    counter_format = up.unpack_uint()
    enterprise = counter_format >> 12
    format = counter_format & 0xfff
    print('read_counter_record:counter_format == %d (%d, %d)' % (counter_format, enterprise, format))
    
    # Uppack whole data block
    counter_data = up.unpack_opaque()
    up_counter_data = Unpacker(counter_data)
    
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
    
    ifIndex = up.unpack_uint()
    ifType = up.unpack_uint()
    ifSpeed = up.unpack_uhyper()
    ifDirection = up.unpack_uint()
    ifStatus = up.unpack_uint()
    ifInOctets = up.unpack_uhyper()
    ifInUcastPkts = up.unpack_uint()
    ifInMulticastPkts = up.unpack_uint()
    ifInBroadcastPkts = up.unpack_uint()
    ifInDiscards = up.unpack_uint()
    ifInErrors = up.unpack_uint()
    ifInUnknownProtos = up.unpack_uint()
    ifOutOctets = up.unpack_uhyper()
    ifOutUcastPkts = up.unpack_uint()
    ifOutMulticastPkts = up.unpack_uint()
    ifOutBroadcastPkts = up.unpack_uint()
    ifOutDiscards = up.unpack_uint()
    ifOutErrors = up.unpack_uint()
    ifPromiscuousMode = up.unpack_uint()

    # Print debug output
    print("read_if_counters:ifIndex = %d" %  ifIndex)
    print("read_if_counters:ifType = %d" %  ifType)
    print("read_if_counters:ifSpeed = %d" %  ifSpeed)
    print("read_if_counters:ifDirection = %d" %  ifDirection)
    print("read_if_counters:ifStatus = %d" %  ifStatus)
    print("read_if_counters:ifInOctets = %d" %  ifInOctets)
    print("read_if_counters:ifInUcastPkts = %d" %  ifInUcastPkts)
    print("read_if_counters:ifInMulticastPkts = %d" %  ifInMulticastPkts)
    print("read_if_counters:ifInBroadcastPkts = %d" %  ifInBroadcastPkts)
    print("read_if_counters:ifInDiscards = %d" %  ifInDiscards)
    print("read_if_counters:ifInErrors = %d" %  ifInErrors)
    print("read_if_counters:ifInUnknownProtos = %d" %  ifInUnknownProtos)
    print("read_if_counters:ifOutOctets = %d" %  ifOutOctets)
    print("read_if_counters:ifOutUcastPkts = %d" %  ifOutUcastPkts)
    print("read_if_counters:ifOutMulticastPkts = %d" %  ifOutMulticastPkts)
    print("read_if_counters:ifOutBroadcastPkts = %d" %  ifOutBroadcastPkts)
    print("read_if_counters:ifOutDiscards = %d" %  ifOutDiscards)
    print("read_if_counters:ifOutErrors = %d" %  ifOutErrors)
    print("read_if_counters:ifPromiscuousMode = %d" %  ifPromiscuousMode)
    

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

    # Print debug output
    print("read_ethernet_counters:dot3StatsAlignmentErrors = %s" %  dot3StatsAlignmentErrors)
    print("read_ethernet_counters:dot3StatsFCSErrors = %s" %  dot3StatsFCSErrors)
    print("read_ethernet_counters:dot3StatsSingleCollisionFrames = %s" %  dot3StatsSingleCollisionFrames)
    print("read_ethernet_counters:dot3StatsMultipleCollisionFrames = %s" %  dot3StatsMultipleCollisionFrames)
    print("read_ethernet_counters:dot3StatsSQETestErrors = %s" %  dot3StatsSQETestErrors)
    print("read_ethernet_counters:dot3StatsDeferredTransmissions = %s" %  dot3StatsDeferredTransmissions)
    print("read_ethernet_counters:dot3StatsLateCollisions = %s" %  dot3StatsLateCollisions)
    print("read_ethernet_counters:dot3StatsExcessiveCollisions = %s" %  dot3StatsExcessiveCollisions)
    print("read_ethernet_counters:dot3StatsInternalMacTransmitErrors = %s" %  dot3StatsInternalMacTransmitErrors)
    print("read_ethernet_counters:dot3StatsCarrierSenseErrors = %s" %  dot3StatsCarrierSenseErrors)
    print("read_ethernet_counters:dot3StatsFrameTooLongs = %s" %  dot3StatsFrameTooLongs)
    print("read_ethernet_counters:dot3StatsInternalMacReceiveErrors = %s" %  dot3StatsInternalMacReceiveErrors)
    print("read_ethernet_counters:dot3StatsSymbolErrors = %s" %  dot3StatsSymbolErrors)
    


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

    # Debug output
    print("read_tokenring_counters:dot5StatsLineErrors = %d" % dot5StatsLineErrors)
    print("read_tokenring_counters:dot5StatsBurstErrors = %d" % dot5StatsBurstErrors)
    print("read_tokenring_counters:dot5StatsACErrors = %d" % dot5StatsACErrors)
    print("read_tokenring_counters:dot5StatsAbortTransErrors = %d" % dot5StatsAbortTransErrors)
    print("read_tokenring_counters:dot5StatsInternalErrors = %d" % dot5StatsInternalErrors)
    print("read_tokenring_counters:dot5StatsLostFrameErrors = %d" % dot5StatsLostFrameErrors)
    print("read_tokenring_counters:dot5StatsReceiveCongestions = %d" % dot5StatsReceiveCongestions)
    print("read_tokenring_counters:dot5StatsFrameCopiedErrors = %d" % dot5StatsFrameCopiedErrors)
    print("read_tokenring_counters:dot5StatsTokenErrors = %d" % dot5StatsTokenErrors)
    print("read_tokenring_counters:dot5StatsSoftErrors = %d" % dot5StatsSoftErrors)
    print("read_tokenring_counters:dot5StatsHardErrors = %d" % dot5StatsHardErrors)
    print("read_tokenring_counters:dot5StatsSignalLoss = %d" % dot5StatsSignalLoss)
    print("read_tokenring_counters:dot5StatsTransmitBeacons = %d" % dot5StatsTransmitBeacons)
    print("read_tokenring_counters:dot5StatsRecoverys = %d" % dot5StatsRecoverys)
    print("read_tokenring_counters:dot5StatsLobeWires = %d" % dot5StatsLobeWires)
    print("read_tokenring_counters:dot5StatsRemoves = %d" % dot5StatsRemoves)
    print("read_tokenring_counters:dot5StatsSingles = %d" % dot5StatsSingles)
    print("read_tokenring_counters:dot5StatsFreqErrors = %d" % dot5StatsFreqErrors)


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

    # Backup output
    print("read_vg_counters:dot12InHighPriorityFrames = %d" % dot12InHighPriorityFrames)
    print("read_vg_counters:dot12InHighPriorityOctets = %d" % dot12InHighPriorityOctets)
    print("read_vg_counters:dot12InNormPriorityFrames = %d" % dot12InNormPriorityFrames)
    print("read_vg_counters:dot12InNormPriorityOctets = %d" % dot12InNormPriorityOctets)
    print("read_vg_counters:dot12InIPMErrors = %d" % dot12InIPMErrors)
    print("read_vg_counters:dot12InOversizeFrameErrors = %d" % dot12InOversizeFrameErrors)
    print("read_vg_counters:dot12InDataErrors = %d" % dot12InDataErrors)
    print("read_vg_counters:dot12InNullAddressedFrames = %d" % dot12InNullAddressedFrames)
    print("read_vg_counters:dot12OutHighPriorityFrames = %d" % dot12OutHighPriorityFrames)
    print("read_vg_counters:dot12OutHighPriorityOctets = %d" % dot12OutHighPriorityOctets)
    print("read_vg_counters:dot12TransitionIntoTrainings = %d" % dot12TransitionIntoTrainings)
    print("read_vg_counters:dot12HCInHighPriorityOctets = %d" % dot12HCInHighPriorityOctets)
    print("read_vg_counters:dot12HCInNormPriorityOctets = %d" % dot12HCInNormPriorityOctets)
    print("read_vg_counters:dot12HCOutHighPriorityOctets = %d" % dot12HCOutHighPriorityOctets)


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

    # Print backup output
    print("read_vg_counters:vlan = %d" % vlan)
    print("read_vg_counters:octets = %d" % octets)
    print("read_vg_counters:ucastPkts = %d" % ucastPkts)
    print("read_vg_counters:multicastPkts = %d" % multicastPkts)
    print("read_vg_counters:broadcastPkts = %d" % broadcastPkts)
    print("read_vg_counters:discards = %d" % discards)


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
    vlan_id = up.unpack_uint()
    octets = up.unpack_uhyper()
    ucast_pkts = up.unpack_uint()
    multicast_pkts = up.unpack_uint()
    broadcast_pkts = up.unpack_uint()
    discards = up.unpack_uint()
    print('vlan_id: %d, octet: %d, ucast: %d, mcast: %d, bcast: %d, discard: %d'
          % (vlan_id, octets, ucast_pkts,
             multicast_pkts, broadcast_pkts, discards))


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


if __name__ == '__main__':
    listen_addr = ("0.0.0.0", 6343)
    sock = socket(AF_INET, SOCK_DGRAM)
    sock.bind(listen_addr)
    while True:
        data, addr = sock.recvfrom(65535)
        read_sflow_stream(addr, data)
