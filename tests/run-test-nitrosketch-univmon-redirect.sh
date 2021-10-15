#!/bin/bash

#set -x

TEST_DIR="results/tests/nitrosketch-univmon-redirect"
IFACE="ens4f0"
OUT_IFACE="ens4f1"
TEST_DURATION=10
PROBS=( 0.01 0.05 0.1 0.15 0.2 0.25 0.3 0.35 0.4 0.45 0.5 0.55 0.6 0.65 0.7 0.75 0.8 0.85 0.9 0.95 1 )
SEEDS=( 1234 2375 3522 23738 1918 )

sudo ./setup_flow_director_single_core.sh ${IFACE}

pushd ..
for i in "${SEEDS[@]}"
do
   echo "Starting run with seed ${i}"
   now=`date +"%Y-%m-%d_%H-%M-%S"`

   new_dir_name="${TEST_DIR}/run_${i}_${now}"
   mkdir -p ${new_dir_name}

   rm ${new_dir_name}/output.txt
   rand=$i
   for p in "${PROBS[@]}"
   do
      echo "Result for probability: ${p}, seed: ${rand}" |& tee -a ${new_dir_name}/output.txt
      timeout -s SIGINT 120 sudo python3 nitrosketch-univmon.py -i ${IFACE} -p ${p} --read ${TEST_DURATION} -s ${rand} -q -a REDIRECT -o ${OUT_IFACE} |& tee -a ${new_dir_name}/output.txt
      echo "" |& tee -a ${new_dir_name}/output.txt
      sleep 5
   done
done
popd

sudo ethtool --features ${IFACE} ntuple off
sudo ethtool --features ${IFACE} ntuple on

if [ -z "$1" ]; then
    echo "Done!"
    exit 0
else
   curl -X POST -H 'Content-type: application/json' --data '{"text":"Test Nitrosketch Univmon Redirect done!"}' $1
fi
