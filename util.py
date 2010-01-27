from sys import stdout
from socket import ntohl
from math import floor, ceil, log

ether_type_description = { 0x0800 : 'IP',
                           0x0806 : 'ARP',
                           0x8100 : '802.1Q(VLAN)',
                           0x86DD : 'IPv6' }

def ether_type_to_string(ether_type):
    if ether_type in ether_type_description:
        return ether_type_description[ether_type]
    else:
        return 'unknown(%04X)' % ether_type


def mac_to_string(mac):
    """Returns an Ethernet MAC address in the form
    XX:XX:XX:XX:XX:XX."""

    return ('%02X:%02X:%02X:%02X:%02X:%02X' %
            (mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]))


def ip_to_string(ip):
    """Returns ip as a string in dotted quad notation."""
#    ip = ntohl(ip)              # network byte order is big-endian
    return '%d.%d.%d.%d' % (ip & 0xff,
                            (ip >> 8) & 0xff,
                            (ip >> 16) & 0xff,
                            (ip >> 24) & 0xff)


def ip_proto_to_string(proto):
    proto_name = { 6 : 'TCP' }
    if proto in proto_name:
        return proto_name[proto]
    else:
        return 'unknown(%d)' % proto


def hexdump_escape(c):
    """Returns c if its ASCII code is in [32,126]."""
    if 32 <= ord(c) <= 126:
        return c
    else:
        return '.'


def hexdump_bytes(buf, stream=stdout):
    """Prints a 'classic' hexdump, ie two blocks of 8 bytes per line,
    to stream."""

    # Various values that determine the formatting of the hexdump.
    # - col_fmt is the format used for an individual value
    # - col_width gives the width of an individual value
    # - off_fmt determines the formatting of the byte offset displayed
    #   on the left.
    # - sep1_width determines how much whitespaces is inserted between
    #   columns 8 and 9.
    # - sep2_width determines the amount of whitespace between column
    #   16 and the ASCII column on the right

    col_fmt = '%02X '
    col_width = 3
    off_fmt = '%%0%dX    ' % int(ceil(log(len(buf), 16)))
    sep1_width = 3
    sep2_width = 5
    
    # Print all complete 16-byte chunks.
    for blk_idx in range(len(buf) // 16):
        stream.write(off_fmt % (blk_idx * 16))

        for offset in range(8):
            stream.write(col_fmt % buf[blk_idx * 16 + offset])

        stream.write(' ' * sep1_width)

        for offset in range(8, 16):
            stream.write(col_fmt % buf[blk_idx * 16 + offset])

        stream.write(' ' * sep2_width)

        for offset in range(16):
            c = chr(buf[blk_idx * 16 + offset])
            stream.write('%c' % hexdump_escape(c))

        stream.write('\n')

    # Print the remaining bytes.
    if len(buf) % 16 > 0:
        stream.write(off_fmt % (len(buf) - (len(buf) % 16)))

        blk_off = len(buf) - len(buf) % 16

        for offset in range(min(len(buf) % 16, 8)):
            stream.write(col_fmt % buf[blk_off + offset])

        stream.write(' ' * sep1_width)

        for offset in range(8, len(buf) % 16):
            stream.write(col_fmt % buf[blk_off + offset])

        stream.write(' ' * ((16 - len(buf) % 16) * col_width))
        stream.write(' ' * sep2_width)

        for offset in range(len(buf) % 16):
            c = chr(buf[len(buf) - (len(buf) // 16) * 16 + offset])
            stream.write('%c' % hexdump_escape(c))

        stream.write('\n')
