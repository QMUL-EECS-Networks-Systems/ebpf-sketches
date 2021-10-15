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

device = 'ens4f0'
offload_device = None # 'ens3f1'
flags = 0
maptype = "percpu_array"

mode = BPF.XDP

def one_run(bpf_src, cflags, running_sec=10):    
    # load BPF program
    b = BPF(text = bpf_src,
         device=offload_device,
           #cflags=['-Ofast','-march=native']
           cflags=cflags
           )
    fn = b.load_func("xdp_prog1", mode, offload_device)
    b.attach_xdp(device, fn, flags)

    dropcnt = b.get_table("metadata")
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
    del b
    os.close(fn.fd)
    maxpps=max(history[2:] + history[-2:])
    print('Done running! max throughput/pps is:', maxpps, 'flags are:', cflags)
    return maxpps

def run_experiment_ht(geo_value=32):    
    outputfn=f'outputgeoarray/exp-{geo_value}.log'
    cf=['-Ofast','-march=native', "-DCTXTYPE=xdp_md"]

    print('running, write to', outputfn, ' and flags=', cf)
    if not os.path.exists("outputgeoarray"):
        os.mkdir("outputgeoarray")

    for _ in range(5):
        with open(f'{sys.path[0]}/bpf_progs/my_xdp_prog-geo-array{geo_value}.c','r') as f:
            bpf_src = f.read()
            maxpps=one_run(bpf_src, cf)
            with open(outputfn, 'a+') as f:
                f.write(f'{maxpps}\n')
            
for i in [32, 64, 96, 128]:
    run_experiment_ht(geo_value=i)
