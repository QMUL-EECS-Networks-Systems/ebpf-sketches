#!/usr/bin/python
#
# xdp_drop_count.py Drop incoming packets on XDP layer and count for which
#                   protocol type
#
# Copyright (c) 2016 PLUMgrid
# Copyright (c) 2016 Jan Ruth
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

FAST_HASH_FILE = f"{sys.path[0]}/../src/hash_lib/libfasthash.so"
LOOKUP3_HASH_FILE = f"{sys.path[0]}/../src/hash_lib/liblookup3.so"

SEED_HASHFN1 = 0x2d31e867
SEED_HASHFN2 = 0x6ad611c4
SEED_HASHFN3 = 0x00000000
SEED_HASHFN4 = 0xffffffff

CS_ROWS = 4
CS_COLUMNS = 512

# This should be a power of two to avoid the module operation on the data plane
# MAX_GEOSAMPLING_SIZE = 1048576
# MAX_GEOSAMPLING_SIZE = 32768
MAX_GEOSAMPLING_SIZE = 4096

flags = 0

def print_dropcnt(cmd, quiet=False):
    dropcnt = b.get_table("dropcnt")
    prev = [0]

    if len(cmd) < 2 or not cmd[1].isdigit():
        print("Second argument should be a number")
        return

    rates = []
    final_count = int(cmd[1])
    count = 0
    if not quiet : print("Reading dropcount")
    while count < final_count:
        for k in dropcnt.keys():
            val = dropcnt.sum(k).value
            i = k.value
            if val:
                delta = val - prev[i]
                prev[i] = val
                rates.append(delta)
                if not quiet : print("{}: {} pkt/s".format(i, delta))
        count+=1
        time.sleep(1)
    avg = round(np.average(rates[1:]), 2)
    if not quiet : print(f"Average rate: {avg}")

    return avg

def init_geo_sampling_map(prob):
    geo_var = stats.geom(prob)

    geo_sampling_map = b.get_table("geo_sampling")

    # Fill the map with the random variables
    for k in geo_sampling_map.keys():
        value = np.uint32(geo_var.rvs())
        geo_sampling_map[k] = geo_sampling_map.Leaf(value)

def print_help():
    print("\nFull list of commands")
    print("read <N>: \tread the dropcount value for N seconds")
    print("quit: \t\texit and detach the eBPF program from the XDP hook")
    print("help: \t\tprint this help")

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='eBPF Nitrosketch implementation')
    parser.add_argument("-i", "--interface", required=True, type=str, help="The name of the interface where to attach the program")
    parser.add_argument("-m", "--mode", choices=["NATIVE", "SKB", "TC"], default="NATIVE", type=str,
                        help="The default mode where to attach the XDP program")
    parser.add_argument("-p", "--probability", required=True, type=float, help="The update probability of the sketch")
    parser.add_argument("-a", "--action", choices=["DROP", "REDIRECT"], default="DROP", type=str, help="Final action to apply")
    parser.add_argument("-o", "--output-iface", type=str, help="The output interface where to redirect packets. Valid only if action is REDIRECT")
    parser.add_argument("-r", "--read", type=int, help="Read throughput after X time and print result")
    parser.add_argument("-s", "--seed", type=int, help="Set a specific seed to use")
    parser.add_argument("-q", "--quiet", action="store_true")
    
    args = parser.parse_args()

    mode = args.mode
    device = args.interface
    probability = args.probability
    action = args.action

    if action == "REDIRECT":
        if hasattr(args, "output_iface"):
            ip = pyroute2.IPRoute()
            out_idx = ip.link_lookup(ifname=args.output_iface)[0]
        else:
            print("When the action is REDIRECT you need to set the output interface")
            exit()

    fasthash_functions = CDLL(FAST_HASH_FILE)
    lookup3_functions = CDLL(LOOKUP3_HASH_FILE)

    fasthash_functions.fasthash32.argtypes = [ctypes.c_void_p, ctypes.c_uint64, ctypes.c_uint32]
    fasthash_functions.fasthash32.restype = ctypes.c_uint32
    lookup3_functions.hashlittle.argtypes = [ctypes.c_void_p, ctypes.c_uint64, ctypes.c_uint32]
    lookup3_functions.hashlittle.restype = ctypes.c_uint32

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
    custom_cflags.append(f"-I{sys.path[0]}/../src/ebpf/")
    custom_cflags.append(f"-I{sys.path[0]}/../src/ebpf/nitrosketch")
    custom_cflags.append("-I/usr/include/linux")

    update_probability = np.uint32((np.iinfo(np.uint32).max * probability))

    custom_cflags.append(f"-DUPDATE_PROBABILITY={update_probability}")
    custom_cflags.append(f"-DMAX_GEOSAMPLING_SIZE={MAX_GEOSAMPLING_SIZE}")
    custom_cflags.append(f"-D_CS_ROWS={CS_ROWS}")
    custom_cflags.append(f"-D_CS_COLUMNS={CS_COLUMNS}")

    if action == "DROP":
        custom_cflags.append("-D_ACTION_DROP=1")
    else:
        custom_cflags.append("-D_ACTION_DROP=0")
        custom_cflags.append(f"-D_OUTPUT_INTERFACE_IFINDEX={out_idx}")

    # load BPF program
    b = BPF(src_file=f'{sys.path[0]}/../src/ebpf/nitrosketch/perf-drilldown/nitrosketch_main_conf2.h', cflags=custom_cflags, device=None)

    # Initialization should be always done before the program is loaded on the interface
    # otherwise the geo sampling could have wrong values
    if args.seed is not None:
        np.random.seed(seed=args.seed)

    init_geo_sampling_map(probability)

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
            res = print_dropcnt(line, quiet=True)

            print(res)
        else:
            while 1:
                line = sys.stdin.readline()
                if not line:
                    break
                line = line.rstrip("\n").split(" ")
                if (line[0] == "read"):
                    print_dropcnt(line)
                elif (line[0] == "help"):
                    print_help()
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