#!/bin/bash

#set -x

TEST_DIR="results/tests/xdp-baseline-drop"
IFACE="ens4f0"
TEST_DURATION=10
PROBS=( 0.01 0.05 0.1 0.15 0.2 0.25 0.3 0.35 0.4 0.45 0.5 0.55 0.6 0.65 0.7 0.75 0.8 0.85 0.9 0.95 1 )

pushd ..

now=`date +"%Y-%m-%d_%H-%M-%S"`
new_dir_name="${TEST_DIR}/run_${now}"
mkdir -p ${new_dir_name}
rm ${new_dir_name}/output.txt

for p in "${PROBS[@]}"
do
   echo "Starting run with probability ${p}"
   file_name="xdp-baseline-1-core"

   sudo ./scripts/setup_flow_director_single_core.sh ${IFACE}

   echo "Result for probability: ${p}" |& tee -a ${new_dir_name}/output.txt
   result=$(timeout -s SIGINT 120 sudo python3 xdp-baseline/drop/xdp_drop_baseline_1mem_bytes.py -i ${IFACE} --read ${TEST_DURATION} -q --count-bytes --count-pkts)
   echo "${result}" |& tee -a ${new_dir_name}/output.txt
   echo "${p},${result}" &>> ${new_dir_name}/${file_name}.log
   echo "" |& tee -a ${new_dir_name}/output.txt
   sleep 5
done
popd

sudo ethtool --features ${IFACE} ntuple off
sudo ethtool --features ${IFACE} ntuple on

if [ -z "${1}" ]; then
    echo "Done!"
    exit 0
else
   curl -X POST -H 'Content-type: application/json' --data '{"text":"Test XDP Baseline Drop done!"}' $1
fi
