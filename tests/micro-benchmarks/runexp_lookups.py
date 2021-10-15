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
import pyroute2
import time
import sys
import os
import numpy as np
from scipy import stats

device = 'ens4f0'
offload_device = None # 'ens3f1'
flags = 0
maptype = "percpu_array"

mode = BPF.XDP

def init_geo_sampling_map(bpf, prob, map_name):
    geo_var = stats.geom(prob)

    geo_sampling_map = bpf.get_table(map_name)

    # Fill the map with the random variables
    for k in geo_sampling_map.keys():
        value = np.uint32(geo_var.rvs())
        geo_sampling_map[k] = geo_sampling_map.Leaf(value)


def init_geo_sampling_array(bpf, prob, map_name):
    geo_var = stats.geom(prob)

    geo_sampling_map = bpf.get_table(map_name)

    # Fill the map with the random variables
    for k in geo_sampling_map.keys():
        for i in range(len(geo_sampling_map[k].geo_array)):
            value = np.uint32(geo_var.rvs())
            geo_sampling_map[k].geo_array[i] = ctypes.c_uint32(value)


def one_run(bpf_src, cflags, test_name, num_reads, running_sec=10):    
    # load BPF program
    b = BPF(text = bpf_src, device=offload_device, cflags=cflags)
    fn = b.load_func("xdp_prog1", mode, offload_device)
    b.attach_xdp(device, fn, flags)

    if test_name == "4MAPSNLOOKUPS":
        if (num_reads > 0): init_geo_sampling_map(b, 0.5, "geo_sampling1")
        if (num_reads > 1): init_geo_sampling_map(b, 0.5, "geo_sampling2")
        if (num_reads > 2): init_geo_sampling_map(b, 0.5, "geo_sampling3")
        if (num_reads > 3): init_geo_sampling_map(b, 0.5, "geo_sampling4")
        if (num_reads > 4): init_geo_sampling_map(b, 0.5, "geo_sampling5")
    elif test_name == "1MAPNLOOKUPS" and num_reads > 0:
        init_geo_sampling_map(b, 0.5, "geo_sampling")
    elif test_name == "1MAPNREADS" and num_reads > 0:
        init_geo_sampling_array(b, 0.5, "geo_sampling")

    dropcnt = b.get_table("metadata")
    prev = [0]
    print("Printing drops per IP protocol-number, hit CTRL+C to stop")
    
    history = []
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
                    history.append(delta)
            time.sleep(1)
            running_sec-=1
        except KeyboardInterrupt:
            print("Interrupted, Removing filter from device")
            break
    b.remove_xdp(device, flags)
    b.cleanup()
    maxpps=max(history[2:] + history[-2:])
    print('Done running! max throughput/pps is:', maxpps, 'flags are:', cflags)
    return maxpps


def run_experiment_ht(test_name, num_reads=0):
    outputfn=f'outputlookups/exp-{test_name}-{num_reads}.log'
    cf=['-Ofast','-march=native', "-DCTXTYPE=xdp_md",
        f'-D_NUM_LOOKUPS={num_reads}']
    print('running, write to', outputfn, ' and flags=', cf)
    if not os.path.exists("outputlookups"):
        os.mkdir("outputlookups")

    for _ in range(5):
        with open(f'{sys.path[0]}/bpf_progs/my_xdp_prog-{test_name}.c','r') as f:
            bpf_src = f.read()
            maxpps=one_run(bpf_src, cf, test_name, num_reads)
            with open(outputfn, 'a+') as f:
                f.write(f'{maxpps}\n')


for test_name in ['4MAPSNLOOKUPS', '1MAPNLOOKUPS', '1MAPNREADS']:
    for i in range(5):
        run_experiment_ht(test_name, i)
