#!/usr/bin/env python

from sys import argv, exit, stderr
from socket import socket, AF_INET, SOCK_DGRAM
from struct import pack

def dump(dump_file, port, if_addr='0.0.0.0'):
    listen_addr = (if_addr, port)
    sock = socket(AF_INET, SOCK_DGRAM)
    sock.bind(listen_addr)

    while True:
        data, addr = sock.recvfrom(65535)
        dump_file.write(pack("H", len(data)))
        dump_file.write(data)
        dump_file.flush()

if __name__=='__main__':
    if len(argv) < 3:
        stderr.write('usage: %s file port [address]\n' % argv[0])
        exit(1)
    elif len(argv) == 3:
        dump_file = open(argv[1], 'w')
        dump(dump_file, int(argv[2]))
    elif len(argv) == 4:
        dump_file = open(argv[1], 'w')
        dump(dump_file, int(argv[2]), argv[3])
    else:
        stderr.write('usage: %s file port [address]\n' % argv[0])
        exit(1)
