#!/usr/bin/python
#
# univmon.py eBPF NitroSketch + UnivMon implementation
#
# Copyright (c) Sebastiano Miano <mianosebastiano@gmail.com>
# Licensed under the Apache License, Version 2.0 (the "License")

import ctypes
from bcc import BPF, table
from scipy import stats
from bcc import libbcc
import numpy as np
import pyroute2
import time
import sys
import argparse
import resource
from ctypes import *
import heapq
import ipaddress
import socket
import os
import copy
import errno
import subprocess

FAST_HASH_FILE = "src/hash_lib/libfasthash.so"
IRQ_AFFINITY_FILE = f"{sys.path[0]}/scripts/set_irq_affinity.sh"

SEED_HASHFN = 0x2d31e867
SEED_LAYERHASH = 0xdeadbeef
CS_ROWS = 4
CS_COLUMNS = 512
MAX_GEOSAMPLING_SIZE = 4096
HEAP_SIZE = 15
NM_LAYERS = 32

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


class TopkEntry(ctypes.Structure):
    """ creates a struct to match topk_entry """
    _fields_ = [('value', ctypes.c_int),
                ('tuple', Pkt5Tuple)]

class CountSketch(ctypes.Structure):
    """ creates a struct to match cm_value """
    _fields_ = [('values', (ctypes.c_uint32 * CS_COLUMNS) * CS_ROWS),
                ('topks', TopkEntry * HEAP_SIZE)]

def bitfield(n):
    # return [1 if digit=='1' else 0 for digit in bin(n)[2:]]
    return [int(x) for x in np.binary_repr(n, width=32)]

def trailing_zeros(n):
    s = np.binary_repr(n, width=32)
    new_s = ""
    for i in range(len(s)):
        new_s += '1' if s[i] == '0' else '0'
    new_s = new_s[::-1]
    return [int(x) for x in new_s]

def get_layer_hash(flow):
    return fasthash_functions.fasthash32(ctypes.byref(flow), ctypes.c_uint64(ctypes.sizeof(flow)), ctypes.c_uint32(SEED_LAYERHASH))

def query_sketch(g): 
    Y=np.zeros(nm_layers)
    Qbottom = get_topk(["", f"{nm_layers-1}", f"{HEAP_SIZE}"])
    Y[nm_layers-1] = sum([g(cnt) for cnt,_,fid in Qbottom])  
    for j in reversed(range(nm_layers-1)):
        Qj = get_topk(["", f"{j}", f"{HEAP_SIZE}"])
        value = 0
        for cnt,_,fid in Qj:
            layer_hash_int = get_layer_hash(fid)
            layer_hash = trailing_zeros(layer_hash_int)
            value += (1-2*layer_hash[j+1])*g(cnt)

        Y[j]=2*Y[j+1]+value
    return Y[0]


def countDistinct(cmd):
    return query_sketch(np.sign)


def get_topk(cmd):
    heap = []
    if len(cmd) != 3 or not cmd[1].isdigit() or not cmd[2].isdigit():
        print("Second and third arguments should be a number")
        return
    
    layer = int(cmd[1])
    k = int(cmd[2])

    if (k > HEAP_SIZE):
        print(f"Cannot get more than {HEAP_SIZE} TopK entries")
        return list()

    if (layer >= nm_layers):
        print(f"Layer cannot be greater than {nm_layers}")
        return list()

    cs_table = b.get_table("ns_um")

    array_val = (CountSketch * cs_table.total_cpu)()

    key = ctypes.c_int(layer)
    if libbcc.lib.bpf_lookup_elem(cs_table.get_fd(), ctypes.byref(key), ctypes.byref(array_val)) < 0:
        print("Error while reading topk map")
        return

    counter = 0
    for elem in array_val:
        for i in range(HEAP_SIZE):
            #TODO: We should check if the same element is present into different CPU 
            # and sum the values
            heap_elem = elem.topks[i]
            if (heap_elem.value == 0): continue
            heapq.heappush(heap, (int(heap_elem.value), counter, heap_elem.tuple))
            counter += 1

    topk_list = heapq.nlargest(k, heap)

    for elem in topk_list:
        print(elem[2])
        print(elem[0])

    return topk_list

def print_dropcnt(cmd, quiet=False, print_pkts=True, print_bytes=False):
    dropcnt = b.get_table("metadata")
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

def init_geo_sampling_array(prob):
    geo_var = stats.geom(prob)

    metadata_map = b.get_table("metadata")

    ini = metadata_map.Leaf()
    for i in range(0, metadata_map.total_cpu):
        ini[i].cnt = 0
        ini[i].geo_sampling_idx = 0
        ini[i].drop_cnt = 0
        for j in range(0, MAX_GEOSAMPLING_SIZE):
            value = np.uint32(geo_var.rvs())
            ini[i].geo_sampling_array[j] = ctypes.c_uint32(value)

    metadata_map[ metadata_map.Key(0) ] = ini

def pline(arr):
    print(','.join([str(x) for x in arr]))

def print_help():
    print("\nFull list of commands")
    print("read <N>: \tread the dropcount value for N seconds")
    print("quit: \t\texit and detach the eBPF program from the XDP hook")
    print("query: \t\tquery the sketch with a given 5 tuple")
    print("top <l> <n>: \t\tget the top <n> elements in the sketch at layer <l>")
    print("help: \t\tprint this help")

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='eBPF Nitrosketch + Univmon Implementation')
    parser.add_argument("-i", "--interface", required=True, type=str, help="The name of the interface where to attach the program")
    parser.add_argument("-m", "--mode", choices=["NATIVE", "SKB", "TC"], default="NATIVE", type=str,
                        help="The default mode where to attach the XDP program")
    parser.add_argument("-p", "--probability", required=True, type=float, help="The update probability of the sketch")
    parser.add_argument("-a", "--action", choices=["DROP", "REDIRECT"], default="DROP", type=str, help="Final action to apply")
    parser.add_argument("-o", "--output-iface", type=str, help="The output interface where to redirect packets. Valid only if action is REDIRECT")
    parser.add_argument("-r", "--read", type=int, help="Read throughput after X time and print result")
    parser.add_argument("-s", "--seed", type=int, help="Set a specific seed to use")
    parser.add_argument("-l", "--layers", type=int, help="Number of layers to run with", default=32)
    parser.add_argument("-q", "--quiet", action="store_true", help="Do not print debug information")
    parser.add_argument("--count-pkts", default=True, action="store_true", help="Print number of packets per second (default True)")
    parser.add_argument("--count-bytes", default=False, action="store_true", help="Print number of bytes per second (default False)")

    args = parser.parse_args()

    mode = args.mode
    device = args.interface
    probability = args.probability
    action = args.action
    nm_layers = args.layers

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

    fasthash_functions.fasthash32.argtypes = [ctypes.c_void_p, ctypes.c_uint64, ctypes.c_uint32]
    fasthash_functions.fasthash32.restype = ctypes.c_uint32

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
    custom_cflags.append(f"-I{sys.path[0]}/src/ebpf/ns_um")
    custom_cflags.append("-I/usr/include/linux")
    
    update_probability = np.uint32((np.iinfo(np.uint32).max * probability))

    custom_cflags.append(f"-DUPDATE_PROBABILITY={update_probability}")
    custom_cflags.append(f"-DMAX_GEOSAMPLING_SIZE={MAX_GEOSAMPLING_SIZE}")
    custom_cflags.append(f"-D_CS_ROWS={CS_ROWS}")
    custom_cflags.append(f"-D_CS_COLUMNS={CS_COLUMNS}")
    custom_cflags.append(f"-D_NM_LAYERS={nm_layers}")
    custom_cflags.append(f"-D_HEAP_SIZE={HEAP_SIZE}")
    custom_cflags.append(f"-D_SEED_HASHFN={SEED_HASHFN}")
    custom_cflags.append(f"-D_SEED_LAYERHASH={SEED_LAYERHASH}")

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
    
    
    b = BPF(src_file='src/ebpf/ns_um/nitrosketch_univmon_main.h', cflags=custom_cflags,
            device=None)

    if args.seed is not None:
        np.random.seed(seed=args.seed)

    init_geo_sampling_array(probability)

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

    rc = subprocess.call(f"{IRQ_AFFINITY_FILE} local {device} > /dev/null 2>&1", shell=True)

    try:
        if not args.quiet : print("Ready, please insert a new command (type 'help' for the full list)")
        if hasattr(args, "read") and args.read is not None:
            line = f"read {args.read}"
            line = line.rstrip("\n").split(" ")
            time.sleep(5)
            res = print_dropcnt(line, quiet=True, print_pkts=print_pkts, print_bytes=print_bytes)

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
                    print(countDistinct(line))
                elif (line[0] == "top"):
                    topk_list = get_topk(line)
                    if len(topk_list) == 0: print("No TopK found")
                    for elem in topk_list:
                        print(f"\nValue: {elem[0]}")
                        print(f"5 Tuple:\n{elem[2]}")
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