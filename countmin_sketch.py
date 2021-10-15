#!/usr/bin/python
#
# univmon.py eBPF Countmin Sketch implementation
#
# Copyright (c) Sebastiano Miano <mianosebastiano@gmail.com>
# Licensed under the Apache License, Version 2.0 (the "License")

import ctypes
from bcc import BPF
from scipy import stats
from bcc import libbcc
import numpy as np
import pyroute2
import time
import sys
import argparse
import resource
from ctypes import *
import socket
import heapq
import ipaddress
import copy
import math

FAST_HASH_FILE = "src/hash_lib/libfasthash.so"

SEED_HASHFN = 0x2d31e867

CS_ROWS = 4
CS_COLUMNS = 512

# This should be a power of two to avoid the module operation on the data plane
MAX_GEOSAMPLING_SIZE = 32768
MAX_HEAP_ENTRIES = 3000000

flags = 0

class Pkt5Tuple(ctypes.Structure):
    """ creates a struct to match pkt_5tuple """
    _pack_ = 1
    _fields_ = [('src_ip', ctypes.c_uint32),
                ('dst_ip', ctypes.c_uint32),
                ('src_port', ctypes.c_uint16),
                ('dst_port', ctypes.c_uint16),
                ('proto', ctypes.c_uint8)]

    def __str__(self):
        str = f"Source IP: {ipaddress.IPv4Address(socket.ntohl(self.src_ip))}\n"
        str += f"Dest IP: {ipaddress.IPv4Address(socket.ntohl(self.dst_ip))}\n"
        str += f"Source Port: {socket.ntohs(self.src_port)}\n"
        str += f"Dst Port: {socket.ntohs(self.dst_port)}\n"
        str += f"Proto: {self.proto}\n"
        return str

class CountSketch(ctypes.Structure):
    """ creates a struct to match cm_value """
    _fields_ = [('values', (ctypes.c_uint32 * CS_COLUMNS) * CS_ROWS)]

def queryLayer(pkt, cm_value):
    def read(i):
        hash_64 = fasthash_functions.fasthash64(ctypes.byref(pkt), ctypes.sizeof(pkt), ctypes.c_uint32(SEED_HASHFN))
        if i == 0:
            hash = hash_64 & 0xFFFF
        elif i == 1:
            hash = hash_64  >> 16 & 0xFFFF
        elif i == 2:
            hash = hash_64  >> 32 & 0xFFFF
        elif i == 3:
            hash = hash_64  >> 48 & 0xFFFF
        else:
            print("Invalid row number")
            return 0

        idx = hash % CS_COLUMNS

        return cm_value.values[i][idx]
    return np.min([read(i) for i in range(CS_ROWS)])

def query_sketch(cmd):
    pkt = Pkt5Tuple()

    if len(cmd) != 6:
        print("You should specify the entire 5 tuple")
        return
    
    try:
        pkt.src_ip = ctypes.c_uint32(socket.htonl(int(ipaddress.IPv4Address(cmd[1]))))
        pkt.dst_ip = ctypes.c_uint32(socket.htonl(int(ipaddress.IPv4Address(cmd[2]))))
        pkt.proto = ctypes.c_uint8(int(cmd[3]))
        pkt.src_port = ctypes.c_uint16(socket.htons(int(cmd[4])))
        pkt.dst_port = ctypes.c_uint16(socket.htons(int(cmd[5])))
    except ValueError:
        print("Error while parsing the 5 tuple values")
        return

    cs_table = b.get_table("countmin")

    # Reading all the values "manually", since BCC does not support matrix types
    key = ctypes.c_uint32(0)
    cs = CountSketch()
    fd = ctypes.c_int(cs_table.get_fd())
    res = libbcc.lib.bpf_lookup_elem(fd, ctypes.byref(key), ctypes.byref(cs))
    if res < 0:
        print("Error in reading the sketch")
        return
    
    sketch_value = queryLayer(pkt, cs)
    print(sketch_value)

def print_dropcnt(cmd, quiet=False, print_pkts=True, print_bytes=False):
    dropcnt = b.get_table("dropcnt")
    prev_pkt_cnt = [0] 
    prev_bytes_cnt = [0] 

    if len(cmd) < 2 or not cmd[1].isdigit():
        print("Second argument should be a number")
        return

    rates = []
    throughput = []
    final_count = int(cmd[1])
    count = 0
    if not quiet : print("Reading dropcount")
    while count < final_count:
        for k in dropcnt.keys():
            array_val = dropcnt.getvalue(k)
            bytes = 0
            pkts = 0
            for elem in array_val:
                if print_pkts:
                    pkts += elem.drop_cnt
                if print_bytes:
                    bytes += elem.bytes_cnt
            i = k.value
            if pkts and print_pkts:
                delta = pkts - prev_pkt_cnt[i]
                prev_pkt_cnt[i] = pkts
                rates.append(delta)
                if not quiet : print("{}: {} pkt/s".format(i, delta))
            if bytes and print_bytes:
                delta = bytes - prev_bytes_cnt[i]
                prev_bytes_cnt[i] = bytes
                throughput.append(delta)
                if not quiet : print("{}: {} Gbps".format(i, (delta*8)/1e9))
        count+=1
        time.sleep(1)
    avg = list()

    if print_pkts:
        avg_pkts = round(np.average(rates[1:]), 2)
        avg.append(avg_pkts)
        if not quiet: print(f"Average pkts rate: {avg_pkts}")
    if print_bytes:
        avg_bytes = round(np.average(throughput[1:]), 2)
        avg.append(avg_bytes)
        if not quiet: print(f"Average Gbps rate: {(avg_bytes*8)/1e9}")

    return avg

def pline(arr):
    print(','.join([str(x) for x in arr]))

def print_help():
    print("\nFull list of commands")
    print("read <N>: \tread the dropcount value for N seconds")
    print("query <ipsrc> <ipdst> <proto> <srcPort> <dstPort>: \tquery the sketch and return the associated counter")
    print("quit: \t\texit and detach the eBPF program from the XDP hook")
    print("help: \t\tprint this help")

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='eBPF Count-min Sketch implementation')
    parser.add_argument("-i", "--interface", required=True, type=str, help="The name of the interface where to attach the program")
    parser.add_argument("-m", "--mode", choices=["NATIVE", "SKB", "TC"], default="NATIVE", type=str,
                        help="The default mode where to attach the XDP program")
    parser.add_argument("-a", "--action", choices=["DROP", "REDIRECT"], default="DROP", type=str, help="Final action to apply")
    parser.add_argument("-o", "--output-iface", type=str, help="The output interface where to redirect packets. Valid only if action is REDIRECT")
    parser.add_argument("-r", "--read", type=int, help="Read throughput after X time and print result")
    parser.add_argument("-q", "--quiet", action="store_true", help="Do not print debug information")
    parser.add_argument("--count-pkts", default=True, action="store_true", help="Print number of packets per second (default True)")
    parser.add_argument("--count-bytes", default=False, action="store_true", help="Print number of bytes per second (default False)")

    args = parser.parse_args()

    mode = args.mode
    device = args.interface
    action = args.action

    print_pkts = args.count_pkts
    print_bytes = args.count_bytes

    if action == "REDIRECT":
        if hasattr(args, "output_iface"):
            ip = pyroute2.IPRoute()
            out_idx = ip.link_lookup(ifname=args.output_iface)[0]
        else:
            print("When the action is REDIRECT you need to set the output interface")
            exit()

    fasthash_functions = CDLL(FAST_HASH_FILE)

    fasthash_functions = CDLL(FAST_HASH_FILE)
    fasthash_functions.fasthash64.argtypes = [ctypes.c_void_p, ctypes.c_uint64, ctypes.c_uint32]
    fasthash_functions.fasthash64.restype = ctypes.c_uint64

    maptype = "percpu_array"
    if mode == "TC":
        hook = BPF.SCHED_CLS
    elif mode == "SKB":
        hook = BPF.XDP
        flags |= (1 << 1)
    else:
        hook = BPF.XDP

    if hook == BPF.XDP:
        ret = "XDP_DROP"
        ctxtype = "xdp_md"
    else:
        ret = "TC_ACT_SHOT"
        ctxtype = "__sk_buff"

    custom_cflags = ["-w", f"-DRETURNCODE={ret}", f"-DCTXTYPE={ctxtype}", f"-DMAPTYPE=\"{maptype}\""]
    custom_cflags.append(f"-I{sys.path[0]}/src/ebpf/")
    custom_cflags.append(f"-I{sys.path[0]}/src/ebpf/countmin")
    custom_cflags.append("-I/usr/include/linux")

    custom_cflags.append(f"-D_CS_ROWS={CS_ROWS}")
    custom_cflags.append(f"-D_CS_COLUMNS={CS_COLUMNS}")
    custom_cflags.append(f"-D_MAX_HEAP_ENTRIES={MAX_HEAP_ENTRIES}")
    custom_cflags.append(f"-D_SEED_HASHFN={SEED_HASHFN}")

    if action == "DROP":
        custom_cflags.append("-D_ACTION_DROP=1")
    else:
        custom_cflags.append("-D_ACTION_DROP=0")
        custom_cflags.append(f"-D_OUTPUT_INTERFACE_IFINDEX={out_idx}")

    if print_pkts:
        custom_cflags.append("-D_COUNT_PACKETS=1")
    else:
        custom_cflags.append("-D_COUNT_PACKETS=0")

    if print_bytes:
        custom_cflags.append("-D_COUNT_BYTES=1")
    else:
        custom_cflags.append("-D_COUNT_BYTES=0")

    # load BPF program
    b = BPF(src_file='src/ebpf/countmin/countmin_main.h', cflags=custom_cflags,
            device=None)

    fn = b.load_func("xdp_prog1", hook, None)

    if hook == BPF.XDP:
        b.attach_xdp(device, fn, flags)
        if action == "REDIRECT":
            out_fn = b.load_func("xdp_dummy", BPF.XDP)
            b.attach_xdp(args.output_iface, out_fn, flags)
    else:
        ip = pyroute2.IPRoute()
        ipdb = pyroute2.IPDB(nl=ip)
        idx = ipdb.interfaces[device].index
        ip.tc("add", "clsact", idx)
        ip.tc("add-filter", "bpf", idx, ":1", fd=fn.fd, name=fn.name,
            parent="ffff:fff2", classid=1, direct_action=True)

    try:
        if not args.quiet : print("Ready, please insert a new command (type 'help' for the full list)")
        if hasattr(args, "read") and args.read is not None:
            line = f"read {args.read}"
            line = line.rstrip("\n").split(" ")
            time.sleep(5)
            res = print_dropcnt(line, quiet=True, print_pkts=print_pkts, print_bytes=print_bytes)
            # print(res)
            pline(res)
        else:
            while 1:
                line = sys.stdin.readline()
                if not line:
                    break
                line = line.rstrip("\n").split(" ")
                if (line[0] == "read"):
                    print_dropcnt(line, print_pkts=print_pkts, print_bytes=print_bytes)
                elif (line[0] == "help"):
                    print_help()
                elif (line[0] == "query"):
                    query_sketch(line)
                elif (line[0] == "quit"):
                    break
                else:
                    print("Command unknown")
    except KeyboardInterrupt:
        print("Keyboard interrupt")

    if not args.quiet : print("Removing filter from device")
    if hook == BPF.XDP:
        b.remove_xdp(device, flags)
        if action == "REDIRECT":
            b.remove_xdp(args.output_iface, flags)
    else:
        ip.tc("del", "clsact", idx)
        ipdb.release()
    b.cleanup()