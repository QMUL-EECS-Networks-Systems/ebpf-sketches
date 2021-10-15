#!/usr/bin/python
#
# xdp_drop_count.py Drop incoming packets on XDP layer and count for which
#                   protocol type
#
# Copyright (c) 2016 PLUMgrid
# Copyright (c) 2016 Jan Ruth
# Licensed under the Apache License, Version 2.0 (the "License")

import ctypes
from ctypes import *
from bcc import BPF
import pyroute2
import time
import sys
import os
import numpy as np
from scipy import stats
from bcc import libbcc
import argparse
import subprocess

device = 'ens4f0'
offload_device = None # 'ens3f1'
flags = 0
maptype = "percpu_array"

NUM_LAYERS = 16
CS_ROWS = 5
CS_COLUMNS = 512

mode = BPF.XDP

output_dir = ""

def setup_array_of_array_map(bpf, num_writes):
    sketch_map = bpf.get_table("sketch_map")

    for i in range(num_writes):
        name = f"sketch_map_single{i+1}"
        single_map = bpf.get_table(name)

        sketch_map[ctypes.c_int(i)] = ctypes.c_int(single_map.get_fd())


def one_run(bpf_src, cflags, test_name, num_writes, run, maptype, use_atomic=False, use_perf=False, running_sec=15):    
    # load BPF program
    b = BPF(text = bpf_src, device=offload_device, cflags=cflags)
    fn = b.load_func("xdp_prog1", mode, offload_device)
    b.attach_xdp(device, fn, flags)

    if test_name == "MAP_OF_MAP_ARRAY":
        setup_array_of_array_map(b, num_writes)

    dropcnt = b.get_table("metadata")
    try:
        if use_perf:
            outputprofile=f'{output_dir}/exp-{test_name}-{num_writes}-{maptype}-atomic{use_atomic}-run{run}.perf.log'

            with open(outputprofile,'w') as profile:
                subprocess.Popen(f"bpftool --json --pretty prog profile name xdp_prog1 duration {running_sec} cycles instructions llc_misses dtlb_misses", shell=True, stdout=profile)
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
    finally:
        if use_perf:
            profile.close()

    return maxpps


def run_experiment_ht(test_name, num_writes=0, per_cpu=False,  use_atomic=False, use_perf=False, running_sec=15):
    if per_cpu:
        maptype = "percpu_array"
    else:
        maptype = "array"
    
    outputfn=f'{output_dir}/exp-{test_name}-{num_writes}-{maptype}-atomic{use_atomic}.log'

    atomic_define = 0
    if use_atomic:
        atomic_define = 1

    cf=['-Ofast','-march=native', "-DCTXTYPE=xdp_md",
        f'-DEXPERIMENT_MAPTYPE=\"{maptype}\"',
        f'-D_NUM_WRITES={num_writes}',
        f'-D_CS_ROWS={CS_ROWS}',
        f'-D_CS_COLUMNS={CS_COLUMNS}',
        f'-D_CS_ROWS_COLUMNS={CS_ROWS*CS_COLUMNS}',
        f'-D_NUM_LAYERS={NUM_LAYERS}',
        f'-D_USE_ATOMIC={atomic_define}']
    print('running, write to', outputfn, ' and flags=', cf)
    if not os.path.exists(f"{output_dir}"):
        os.mkdir(f"{output_dir}")

    for i in range(5):
        with open(f'{sys.path[0]}/bpf_progs/my_xdp_prog-{test_name}.c','r') as f:
            bpf_src = f.read()
            maxpps=one_run(bpf_src, cf, test_name, num_writes, i, maptype, use_atomic=use_atomic, use_perf=use_perf, running_sec=running_sec)
            with open(outputfn, 'a+') as f:
                f.write(f'{maxpps}\n')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Run experiment to benchmark different sketch data structures options')
    parser.add_argument("-o", "--output", type=str, default="outputsketchds", help="Directory where the results are placed")
    parser.add_argument("-p", "--perf", action="store_true", help="If set, run perf to profile the eBPF program")
    parser.add_argument("-d", "--duration", type=int, default=15, help="Duration of every single run")

    args = parser.parse_args()

    output_dir = args.output
    duration = args.duration

    for test_name in ['SINGLE_ARRAY', 'SINGLE_ROWS_SPLIT_ARRAY', 'SINGLE_ROWS_COLUMNS_SPLIT_ARRAY']:
        for per_cpu in [True, False]:
            for use_atomic in [True, False]:
                for i in range(CS_ROWS+1):
                    run_experiment_ht(test_name, i, per_cpu=per_cpu,  use_atomic=use_atomic, use_perf=args.perf, running_sec=duration)

    for test_name in ['MAP_OF_MAP_ARRAY', 'SINGLE_DOUBLE_ARRAY']:
        for use_atomic in [True, False]:
            for i in range(CS_ROWS+1):
                run_experiment_ht(test_name, i, per_cpu=False, use_atomic=use_atomic, use_perf=args.perf, running_sec=duration)
