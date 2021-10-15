#!/usr/bin/python
#
# xdp_drop_count.py Drop incoming packets on XDP layer and count for which
#                   protocol type
#
# Copyright (c) 2016 PLUMgrid
# Copyright (c) 2016 Jan Ruth
# Licensed under the Apache License, Version 2.0 (the "License")

from bcc import BPF
from bcc import libbcc
import pyroute2
import time
import sys
import random
import numpy as np
import ctypes
import subprocess
import sys
import os
import argparse

device = 'ens4f0'
offload_device = None # 'ens3f1'
flags = 0
maptype = "percpu_array"

mode = BPF.XDP

with open(f'{sys.path[0]}/bpf_progs/my_xdp_prog-arraysize.c','r') as f:
    bpf_src=f.read()
    
def one_run(cflags, maptype, table_size, num_insert, action, run, use_perf=False, running_sec=15):    
    # load BPF program
    b = BPF(text = bpf_src,
            device=offload_device,
            cflags=cflags)
    fn = b.load_func("xdp_prog1", mode, offload_device)
    b.attach_xdp(device, fn, flags)

    dropcnt = b.get_table("dropcnt")

    try:
        if use_perf:
            outputprofile=f'outputarr/exp-{maptype}-ts{table_size}-ni{num_insert}-{action}-run{run}.perf.log'

            profile = open(outputprofile,'w')
            subprocess.Popen(f"bpftool --json --pretty prog profile name xdp_prog1 duration {running_sec} cycles instructions llc_misses dtlb_misses", shell=True, stdout=profile)

        prev = [0]
        print("Printing drops per IP protocol-number, hit CTRL+C to stop")

        history=[]
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
        maxpps=max(history[2:]+history[-2:])
        print('Done running! max throughput/pps is:',maxpps, 'flags are:',cflags)
    finally:
        if use_perf:
            profile.close()

    return maxpps


def run_experiment_ht(use_percpu=False, table_size=128, num_insert=128, action='ACTION_WRITE', use_perf=False):
    if use_percpu:
        maptype='percpu_array'
    else:
        maptype='array'
    assert(action in ['ACTION_WRITE','ACTION_INC','ACTION_READ','ACTION_WRITE_UPDATE'])
    
    outputfn=f'outputarr/exp-{maptype}-ts{table_size}-ni{num_insert}-{action}.log'
    cf=['-Ofast','-march=native', #-mcpu=probe
        f'-DEXPERIMENT_MAPTYPE=\"{maptype}\"',
        f'-DEXPERIMENT_TABLE_SIZE={table_size}',
        f'-DEXPERIMENT_NUM_ELEM={num_insert}',
        f'-D{action}']
    print('running, write to',outputfn,' and flags=',cf)

    if not os.path.exists("outputarr"):
        os.mkdir("outputarr")

    for i in range(3):
        maxpps=one_run(cf, maptype, table_size, num_insert, action, i, use_perf=use_perf)
        with open(outputfn,'a+') as f:
            f.write(f'{maxpps}\n')
        

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Run experiment to benchmark array tables')
    parser.add_argument("-p", "--perf", action="store_true", help="If set, run perf to profile the eBPF program")

    args = parser.parse_args()

    for use_percpu in [False]:
        for table_size in [2**i for i in range(23,23+1)]:#8 to 8388608
            # for num_insert in [table_size,table_size//2,table_size//4]:
            for num_insert in [table_size]:
                # for action in ['ACTION_WRITE','ACTION_INC', 'ACTION_READ','ACTION_WRITE_UPDATE']:
                for action in ['ACTION_WRITE']:
                    run_experiment_ht(use_percpu=use_percpu,
                                      table_size=table_size,
                                      num_insert=num_insert,
                                      action=action,
                                      use_perf=args.perf)
