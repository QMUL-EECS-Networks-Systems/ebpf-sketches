#!/bin/bash

#set -x

TEST_DIR="results/tests/countsketch-drop"
IFACE="ens4f0"
TEST_DURATION=30

pushd ..

now=`date +"%Y-%m-%d_%H-%M-%S"`
new_dir_name="${TEST_DIR}/run_${now}"
mkdir -p ${new_dir_name}
rm ${new_dir_name}/output.txt

file_name="exp-1-cores"

echo "Results for CountSketch eBPF" |& tee -a ${new_dir_name}/output.txt
for i in {1..5}
do
   echo "Starting run ${i}"
   sudo ./scripts/setup_flow_director_single_core.sh ${IFACE}

   result=$(timeout -s SIGINT 120 sudo python3 count_sketch.py -i ${IFACE} --read ${TEST_DURATION} -q --count-bytes --count-pkts)
   echo "${result}" |& tee -a ${new_dir_name}/output.txt
   echo "${i},${result}" &>> ${new_dir_name}/${file_name}.log
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
   curl -X POST -H 'Content-type: application/json' --data '{"text":"Test CountSketch Drop done!"}' $1
fi
