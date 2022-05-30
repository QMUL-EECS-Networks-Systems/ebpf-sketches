#!/usr/bin/python
#
# xdp_drop_count.py Drop incoming packets on XDP layer and count for which
#                   protocol type
#
# Copyright (c) 2016 PLUMgrid
# Copyright (c) 2016 Jan Ruth
# Licensed under the Apache License, Version 2.0 (the "License")

from bcc import BPF
import pyroute2
import time
import sys
import os
import argparse
import shutil
from scipy import stats
import ctypes
from ctypes import *
import numpy as np
import random

device = 'ens4f0'
offload_device = None # 'ens3f1'
flags = 0
maptype = "percpu_array"

mode = BPF.XDP

MAX_GEOSAMPLING_SIZE = 32768

with open(f'{sys.path[0]}/bpf_progs/my_xdp_prog-read_rand_from_mem.c','r') as f:
    bpf_src = f.read()

def one_run(cflags, cycles, running_sec=10):    
    # load BPF program

    b = BPF(text = bpf_src,
            device=offload_device,
            cflags=cflags)
            
    fn = b.load_func("xdp_prog1", mode, offload_device)
    init_geo_sampling_array(b)
    b.attach_xdp(device, fn, flags)

    dropcnt = b.get_table("metadata")
    prev = [0]
    print("Printing drops per IP protocol-number, hit CTRL+C to stop")
    
    history = []
    history_randrate = []
    while running_sec > 0:
        try:
            for k in dropcnt.keys():
                array_val = dropcnt.getvalue(k)
                val = 0
                for elem in array_val:
                    val += elem.drop_cnt
                i = k.value
                if val:
                    delta = val - prev[i]
                    prev[i] = val
                    print("{}: {} pkt/s".format(i, delta))
                    print("{}: {} Mrand/s".format(i, (delta*cycles)/1e6))
                    history.append(delta)
                    history_randrate.append(delta*cycles)
            time.sleep(1)
            running_sec-=1
        except KeyboardInterrupt:
            print("Interrupted, Removing filter from device")
            break
    b.remove_xdp(device, flags)
    b.cleanup()
    maxpps=max(history[2:] + history[-2:])
    max_randrate=max(history_randrate[2:] + history_randrate[-2:])
    print('Done running! max throughput/pps is:', maxpps, 'flags are:', cflags)
    print('Done running! max Mrand/s is:', max_randrate/1e6, 'flags are:', cflags)
    return max_randrate/1e6


def run_experiment_ht(cycles):
    outputfn=f'outputrandfrom_mem/exp-rand-mem-{cycles}.log'
    cf=['-Ofast','-march=native', #-mcpu=probe
        f'-D_RAND_CYCLES={cycles}',
        f'-D_MAX_GEOSAMPLING_SIZE={MAX_GEOSAMPLING_SIZE}']
    cf.append(f"-I{sys.path[0]}/../../src/ebpf/")
    cf.append(f"-I{sys.path[0]}/bpf_progs/hash_libs/")
    cf.append("-I/usr/include/linux")

    print('running, write to', outputfn, ' and flags=', cf)

    for _ in range(5):
        max_randrate=one_run(cf, cycles, test_duration)
        with open(outputfn, 'a+') as f:
            f.write(f'{max_randrate}\n')

def init_geo_sampling_array(b):
    geo_array_map = b.get_table("geo_sampling")

    # Fill the map with the random variables
    for j in range(0, MAX_GEOSAMPLING_SIZE):
        value = np.uint32(random.randint(1,np.iinfo(np.uint32).max))
        geo_array_map[0].geo_array[j] = ctypes.c_uint32(value)
            

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Run experiment to benchmark different read of rand num from mem in eBPF')
    parser.add_argument("-d", "--duration", type=int, default=15, help="Duration of every single run")

    args = parser.parse_args()
    test_duration = args.duration
    
    if os.path.exists("outputrandfrom_mem"):
        shutil.rmtree('outputrandfrom_mem', ignore_errors=True)

    os.mkdir("outputrandfrom_mem")
    
    for rand_cycles in [1, 2, 4, 8, 16, 32, 64, 128, 256, 512]:
        run_experiment_ht(rand_cycles)
