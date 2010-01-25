from sys import stdout
from socket import ntohl
from math import floor, ceil, log


def ip_to_string(ip):
    """Returns ip as a string in dotted quad notation."""
    ip = ntohl(ip)              # network byte order is big-endian
    return '%d.%d.%d.%d' % (ip & 0xff,
                            (ip >> 8) & 0xff,
                            (ip >> 16) & 0xff,
                            (ip >> 24) & 0xff)


def hexdump_escape(c):
    """Returns c if its ASCII code is in [32,126]."""
    if 32 <= ord(c) <= 126:
        return c
    else:
        return '.'


def hexdump_bytes(buf, stream=stdout):
    """Prints a 'classic' hexdump, ie two blocks of 8 bytes per line,
    to stream."""

    # Print all 16-byte chunks but the last
    for blk_idx in range(len(buf) // 16):
        stream.write(('%%0%dX    ' % int(ceil(log(len(buf), 16)))) % (blk_idx * 16))
        for offset in range(8):
            stream.write('%02X ' % buf[blk_idx * 16 + offset])
        stream.write(' ')
        for offset in range(8, 16):
            stream.write('%02X ' % buf[blk_idx * 16 + offset])
        stream.write('    ')
        for offset in range(16):
            c = chr(buf[blk_idx * 16 + offset])
            stream.write('%c' % hexdump_escape(c))
        stream.write('\n')

    # Print the last chunk, possibly less than 16 bytes long
    stream.write(('%%0%dX   ' % int(ceil(log(len(buf), 16))) % (len(buf) - (len(buf) % 16))))
    for offset in range(min(len(buf) % 16, 8)):
        stream.write('%02X ' % buf[len(buf) - (len(buf) // 16) * 16 + offset])

    stream.write('  ')
    for offset in range(8, min(len(buf) % 16, 16)):
        stream.write('%02X ' % buf[len(buf) - (len(buf) // 16) * 16 + offset])
    stream.write('\n')
