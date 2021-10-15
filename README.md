# eBPF Sketches

This repository contains a list of the most famous sketches implemented within the eBPF/XDP subsystem.

In particular, we have:

1. [Count Sketch](#count-sketch)
2. [Count-min Sketch](#count-min-sketch)
2. [Nitrosketch + Count Sketch](#nitrosketch)
2. [UnivMon + Nitrosketch](#univmon)

## Requirements

To run correctly the sketches you first need to install [BCC](https://github.com/iovisor/bcc).

```shell
# Clone BCC repo
git clone https://github.com/iovisor/bcc.git

mkdir bcc/build; cd bcc/build
cmake -DPYTHON_CMD=python3 .. # build python3 binding
make -jN
sudo make install
```

Then, you need to install the python3 requirements:

```shell
# Clone BCC repo
pip3 install -r requirements.txt
```

## Count-Sketch
If you want to run count-sketch, this is an example.
This script will attach the XDP program in `XDP_DRV` mode and the final action to execute will be `DROP`.
```shell
sudo python3 count_sketch.py -i eth0 -m NATIVE -a DROP
```

When the program is up and running, you can type `help` to list the runtime commands to execute.

```shell
root@ubuntu:~/dev/ebpf-sketch$ sudo python3 count_sketch.py -i ens4f0
Ready, please insert a new command (type 'help' for the full list)
help

Full list of commands
read <N>:       read the dropcount value for N seconds
quit:           exit and detach the eBPF program from the XDP hook
help:           print this help
Ready, please insert a new command (type 'help' for the full list)
```

For instance, the `read 10` command will print the drop count of the sketch for `10` seconds, and will print the average throughput:
```shell
read 10
Reading dropcount
0: XXX pkt/s
Average rate: XXX
```

The complete list of commands is the following:

```shell
usage: count_sketch.py [-h] -i INTERFACE [-m {NATIVE,SKB,TC}] [-a {DROP,REDIRECT}] [-o OUTPUT_IFACE] [-r READ] [-q] [--count-pkts] [--count-bytes]

eBPF Count Sketch implementation

optional arguments:
  -h, --help            show this help message and exit
  -i INTERFACE, --interface INTERFACE
                        The name of the interface where to attach the program
  -m {NATIVE,SKB,TC}, --mode {NATIVE,SKB,TC}
                        The default mode where to attach the XDP program
  -a {DROP,REDIRECT}, --action {DROP,REDIRECT}
                        Final action to apply
  -o OUTPUT_IFACE, --output-iface OUTPUT_IFACE
                        The output interface where to redirect packets. Valid only if action is REDIRECT
  -r READ, --read READ  Read throughput after X time and print result
  -q, --quiet           Do not print debug information
  --count-pkts          Print number of packets per second (default True)
  --count-bytes         Print number of bytes per second (default False)
```

## Count-min Sketch
As for the [Count Sketch](#count-sketch), the Count-min Sketch can be execute with the following command:
```shell
sudo python3 countmin_sketch.py -i eth0 -m NATIVE -a DROP
```

The full list of commands is the following:
```shell
usage: countmin_sketch.py [-h] -i INTERFACE [-m {NATIVE,SKB,TC}] [-a {DROP,REDIRECT}] [-o OUTPUT_IFACE] [-r READ] [-q] [--count-pkts] [--count-bytes]

eBPF Count-min Sketch implementation

optional arguments:
  -h, --help            show this help message and exit
  -i INTERFACE, --interface INTERFACE
                        The name of the interface where to attach the program
  -m {NATIVE,SKB,TC}, --mode {NATIVE,SKB,TC}
                        The default mode where to attach the XDP program
  -a {DROP,REDIRECT}, --action {DROP,REDIRECT}
                        Final action to apply
  -o OUTPUT_IFACE, --output-iface OUTPUT_IFACE
                        The output interface where to redirect packets. Valid only if action is REDIRECT
  -r READ, --read READ  Read throughput after X time and print result
  -q, --quiet           Do not print debug information
  --count-pkts          Print number of packets per second (default True)
  --count-bytes         Print number of bytes per second (default False)
```

## <a id="nitrosketch"></a>Nitrosketch + Count Sketch
If you want to run `Nitrosketch`, this is an example.
This script will attach the XDP program in `XDP_DRV` mode and the final action to execute will be `DROP`; the sketch will run with a probability `p=0.1` (i.e., `1%`).

```shell
sudo python3 nitrosketch.py -i ens4f0 -a DROP -p 0.1
```

The full list of commands is the following:
```shell
usage: nitrosketch.py [-h] -i INTERFACE [-m {NATIVE,SKB,TC}] -p PROBABILITY [-a {DROP,REDIRECT}] [-o OUTPUT_IFACE] [-r READ] [-s SEED] [-q] [--count-pkts] [--count-bytes]

eBPF Nitrosketch implementation

optional arguments:
  -h, --help            show this help message and exit
  -i INTERFACE, --interface INTERFACE
                        The name of the interface where to attach the program
  -m {NATIVE,SKB,TC}, --mode {NATIVE,SKB,TC}
                        The default mode where to attach the XDP program
  -p PROBABILITY, --probability PROBABILITY
                        The update probability of the sketch
  -a {DROP,REDIRECT}, --action {DROP,REDIRECT}
                        Final action to apply
  -o OUTPUT_IFACE, --output-iface OUTPUT_IFACE
                        The output interface where to redirect packets. Valid only if action is REDIRECT
  -r READ, --read READ  Read throughput after X time and print result
  -s SEED, --seed SEED  Set a specific seed to use
  -q, --quiet           Do not print debug information
  --count-pkts          Print number of packets per second (default True)
  --count-bytes         Print number of bytes per second (default False)
```

## <a id="univmon"></a>UnivMon + Nitrosketch
If you want to run `UnivMon + Nitrosketch`, this is an example.
This script will attach the XDP program in `XDP_DRV` mode and the final action to execute will be `DROP`; the sketch will run with a probability `p=0.1` (i.e., `1%`), and with a number of layers `l=16`.

```shell
sudo python3 nitrosketch.py -i ens4f0 -a DROP -p 0.1 -l 16
```

The full list of commands is the following:
```shell
usage: nitrosketch-univmon.py [-h] -i INTERFACE [-m {NATIVE,SKB,TC}] -p PROBABILITY [-a {DROP,REDIRECT}] [-o OUTPUT_IFACE] [-r READ] [-s SEED] [-l LAYERS] [-q] [--count-pkts] [--count-bytes]

eBPF Nitrosketch + Univmon Implementation

optional arguments:
  -h, --help            show this help message and exit
  -i INTERFACE, --interface INTERFACE
                        The name of the interface where to attach the program
  -m {NATIVE,SKB,TC}, --mode {NATIVE,SKB,TC}
                        The default mode where to attach the XDP program
  -p PROBABILITY, --probability PROBABILITY
                        The update probability of the sketch
  -a {DROP,REDIRECT}, --action {DROP,REDIRECT}
                        Final action to apply
  -o OUTPUT_IFACE, --output-iface OUTPUT_IFACE
                        The output interface where to redirect packets. Valid only if action is REDIRECT
  -r READ, --read READ  Read throughput after X time and print result
  -s SEED, --seed SEED  Set a specific seed to use
  -l LAYERS, --layers LAYERS
                        Number of layers to run with
  -q, --quiet           Do not print debug information
  --count-pkts          Print number of packets per second (default True)
  --count-bytes         Print number of bytes per second (default False)
```

