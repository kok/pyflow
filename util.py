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
