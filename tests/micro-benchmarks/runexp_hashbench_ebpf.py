#!/usr/bin/python
#
# Licensed under the Apache License, Version 2.0 (the "License")

from bcc import BPF
import pyroute2
import time
import sys
import os
import argparse
import random
import numpy as np

device = 'ens4f0'
offload_device = None # 'ens3f1'
flags = 0
maptype = "percpu_array"

mode = BPF.XDP

with open(f'{sys.path[0]}/bpf_progs/my_xdp_prog-hashbench.c','r') as f:
    bpf_src = f.read()

def one_run(cflags, running_sec=10):    
    # load BPF program

    b = BPF(text = bpf_src,
            device=offload_device,
            cflags=cflags)
            
    fn = b.load_func("xdp_prog1", mode, offload_device)
    b.attach_xdp(device, fn, flags)

    dropcnt = b.get_table("dropcnt")
    prev = [0]
    print("Printing drops, hit CTRL+C to stop")
    
    history = []
    history_hashrate = []
    while running_sec > 0:
        try:
            for k in dropcnt.keys():
                val = dropcnt.sum(k).value
                i = k.value
                if val:
                    delta = val - prev[i]
                    prev[i] = val
                    print("{}: {} pkt/s".format(i, delta))
                    print("{}: {} Mh/s".format(i, (delta*hash_cycles)/1e6))
                    history.append(delta)
                    history_hashrate.append(delta*hash_cycles)
            time.sleep(1)
            running_sec-=1
        except KeyboardInterrupt:
            print("Interrupted, Removing filter from device")
            break
    b.remove_xdp(device, flags)
    b.cleanup()
    maxpps=max(history[2:] + history[-2:])
    max_hashrate=max(history_hashrate[2:] + history_hashrate[-2:])
    print('Done running! max throughput/pps is:', maxpps, 'flags are:', cflags)
    print('Done running! max Mh/s is:', max_hashrate/1e6, 'flags are:', cflags)
    return max_hashrate/1e6

def run_experiment_ht(hname, hnum):
    outputfn=f'outputhashbench_ebpf/exp-{hname}.log'

    if parsing:
        parse_packet = 1
    else:
        parse_packet = 0

    cf=['-w', '-Ofast','-march=native', #-mcpu=probe
        f'-D_HASH_NUM={hnum}',
        f'-D_HASH_CYCLES={hash_cycles}',
        f'-D_PARSE_PACKET={parse_packet}',
        f'-D_HASH_START_VALUE={hash_start_value}']
    cf.append(f"-I{sys.path[0]}/bpf_progs/hash_libs/")
    cf.append(f"-I{sys.path[0]}/../../src/ebpf/")
    cf.append("-I/usr/include/linux")

    print('running, write to', outputfn, ' and flags=', cf)
    if not os.path.exists("outputhashbench_ebpf"):
        os.mkdir("outputhashbench_ebpf")

    for _ in range(5):
        maxhash_rate=one_run(cf, test_duration)
        with open(outputfn, 'a+') as f:
            f.write(f'{maxhash_rate}\n')
            

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Run experiment to benchmark different hash function in eBPF')
    parser.add_argument("-d", "--duration", type=int, default=15, help="Duration of every single run")
    parser.add_argument("-c", "--cycles", type=int, default=100, help="Number of cycles for every hash")
    parser.add_argument("-p", "--parsing", action="store_true", default=False, help="Parse the packet")
    parser.add_argument("-s", "--seed", type=int, help="Set a specific seed to use")

    args = parser.parse_args()
    hash_cycles = args.cycles
    test_duration = args.duration
    parsing = args.parsing

    if args.seed is not None:
        random.seed(args.seed)

    hash_start_value = random.randint(1, np.iinfo(np.uint32).max)

    i = 0
    # run_experiment_ht('JHASH', 0)
    # run_experiment_ht('FASTHASH32', 2)
    # run_experiment_ht('XXHASH32_DANNY', 5)
    # run_experiment_ht('XXHASH32_SEB', 6)

    for hash_name in ['JHASH', 'HASHLITTLE', 'FASTHASH32', 'XXHASH32', 'CSIPHASH', 'XXHASH32_DANNY', 'MURMURHASH3']:
        run_experiment_ht(hash_name, i)
        i+=1
