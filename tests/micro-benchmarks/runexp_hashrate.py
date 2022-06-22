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

with open(f'{sys.path[0]}/bpf_progs/my_xdp_prog-hashrate.c','r') as f:
    bpf_src = f.read()

def one_run(cflags, running_sec=10):    
    # load BPF program

    b = BPF(text = bpf_src,
            device=offload_device,
            cflags=cflags)
            
    fn = b.load_func("xdp_prog1", mode, offload_device)
    b.attach_xdp(device, fn, flags)

    dropcnt = b.get_table("dropcnt")
    prev = [0] * 256
    print("Printing drops per IP protocol-number, hit CTRL+C to stop")
    
    history = []
    while running_sec > 0:
        try:
            for k in dropcnt.keys():
                val = dropcnt[k].value if maptype == "array" else dropcnt.sum(k).value
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


def run_experiment_ht(hname, hnum, num_hashes):
    outputfn=f'outputhashrate/exp-{hname}-num{num_hashes}.log'
    cf=['-Ofast','-march=native', #-mcpu=probe
        f'-D_HASH_NUM={hnum}',
        f'-D_NUM_HASHES={num_hashes}']
    cf.append("-I/usr/include/linux")
    cf.append(f"-I{sys.path[0]}/bpf_progs/hash_libs/")

    print('running, write to', outputfn, ' and flags=', cf)
    if not os.path.exists("outputhashrate"):
        os.mkdir("outputhashrate")

    for _ in range(5):
        maxpps=one_run(cf)
        with open(outputfn, 'a+') as f:
            f.write(f'{maxpps}\n')
            
i = 0
for hash_name in ['JHASH', 'HASHLITTLE', 'FASTHASH32', 'XXHASH32', 'CSIPHASH', 'XXHASH32_DANNY', 'MURMURHASH3']:
    for num in range(6):
        run_experiment_ht(hash_name, i, num)
    i+=1
