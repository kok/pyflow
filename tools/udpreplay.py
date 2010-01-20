#!/usr/bin/env python

from os import stat
from stat import ST_SIZE
from sys import argv, exit, stderr
from socket import socket, AF_INET, SOCK_DGRAM
from struct import unpack
from time import sleep

def replay(dump_filename, port, dst_addr='127.0.0.1'):
    addr = (dst_addr, port)
    sock = socket(AF_INET, SOCK_DGRAM)

    dump_file = open(dump_filename, 'r')
    file_size = stat(dump_filename)[ST_SIZE]
    while dump_file.tell() < file_size - 1:
        length = unpack("H", dump_file.read(2))[0]
        data = dump_file.read(length)
        sock.sendto(data, addr)
        sleep(1)

if __name__=='__main__':
    if len(argv) < 3:
        stderr.write('usage: %s file port [address]\n' % argv[0])
        exit(1)
    elif len(argv) == 3:
        replay(argv[1], int(argv[2]))
    elif len(argv) == 4:
        replay(argv[1], int(argv[2]), argv[3])
    else:
        stderr.write('usage: %s file port [address]\n' % argv[0])
        exit(1)
