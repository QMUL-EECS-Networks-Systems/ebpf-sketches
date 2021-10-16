# How to run the pktgen

To run the tests in this repo, you first need to configure the packet generator on the second server machine, directly connected to the DUT.
We use Pktgen-DPDK to generate random packets used for the syntetic trace experiments and dpdk-burst-replay to send the [IMC trace](http://pages.cs.wisc.edu/~tbenson/IMC10_Data.html).

## Install DPDK

The first thing to do is to install DPDK.
To do so, follow these instructions:

```shell
# Clone DPDK
wget https://fast.dpdk.org/rel/dpdk-20.11.3.tar.xz

tar -xvf dpdk-20.11.3.tar.xz
cd dpdk-20.11.3

meson build
ninja -C build
sudo ninja -C build install
```

After DPDK is installed, you need to mount the hugepages and bind the ports to the DPDK UIO driver.
Follow [these](https://doc.dpdk.org/guides/linux_gsg/sys_reqs.html#running-dpdk-applications) instructions to do it.

## Pktgen-DPDK
After DPDK is installed, now it is time to install pktgen-DPDK.

```shell
# Clone Pktgen-DPDK
git clone --depth 1 --branch pktgen-21.03.1 <https://github.com/pktgen/Pktgen-DPDK.git

cd Pktgen-DPDK
meson build
ninja -C build
sudo ninja -C build install
sudo ldconfig
```

At this point, Pktgen-DPDK is installed. To run the generator uses the following command.
Please note that the cores allocation should be customized to your environment.

```shell
sudo /usr/local/bin/pktgen -c fffff -n 4 --proc-type auto --file-prefix pg -- -T -P -m "[1/3/5:7/9].0, [11/13/15:17/19].1" -f pktgen-dpdk-cfg 
```

After the initialization, you can type `start 0` to start sending packets.

## DPDK Burst Replay
In our tests, we use the data center trace UNI1 from [this link](http://pages.cs.wisc.edu/~tbenson/IMC10_Data.html).
Before start sending the trace, we need to do some additional elaboration to (1) add the Ethernet layer and (2) add a payload in the packets of the trace to match the wire size, since the capture file was trimmed for privacy reasons.

In all the commands, the parameters under <> should be filled with your settings.

### Trace preparation
Download the trace, and run the following command to add the Ethernet layer.

```shell
wget http://pages.cs.wisc.edu/~tbenson/IMC_DATA/univ1_trace.tgz
tar -xzf univ1_trace.tgz
tcprewrite --dlt=enet --enet-dmac=<mac_src> --enet-smac=<mac_dst> --infile=univ1_pt1 --outfile=output.pcap
```

Then, clone the following repository and run this script.

```shell
git clone git@github.com:sebymiano/classbench-generators.git

cd classbench-generators
pip3 install -r requirements.txt

python3 pcap/convert-trace-with-right-size-single-core.py -i output.pcap -o output_complete.pcap -s <mac_src> -d <mac_dst> -p
```

The last script will take a while until the trace is created.
After this step, you can start sending the trace with DPDK Burst Replay.

### DPDK Burst Replay Installation
Clone the DPDK Burst Replay repository and apply our patch.

```shell
git clone https://github.com/FraudBuster/dpdk-burst-replay.git

cd dpdk-burst-replay
git apply dpdk-burst-replay.patch

autoreconf -i && ./configure && make && sudo make install
```

At this point, the dpdk-burst-replay tool is installed. To start sending the trace, run this command.

```shell
sudo dpdk-replay --nbruns 100000000000 --numacore <set_numa_id (e.g., 1)> output_complete.pcap <pci_dev_id (e.g., 0000:af:00.0)>
```