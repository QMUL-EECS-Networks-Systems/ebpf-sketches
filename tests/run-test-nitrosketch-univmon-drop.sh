#!/bin/bash

#set -x

TEST_DIR="results/tests/nitrosketch-univmon-drop"
IFACE="ens4f0"
TEST_DURATION=10
PROBS=( 0.01 0.05 0.1 0.15 0.2 0.25 0.3 0.35 0.4 0.45 0.5 0.55 0.6 0.65 0.7 0.75 0.8 0.85 0.9 0.95 1 )
SEEDS=( 1234 2375 3522 23738 1918 )

pushd ..

now=`date +"%Y-%m-%d_%H-%M-%S"`
new_dir_name="${TEST_DIR}/run_${now}"
mkdir -p ${new_dir_name}
rm ${new_dir_name}/output.txt

for p in "${PROBS[@]}"
do
   echo "Starting run with probability ${p}"
   file_name="exp-1-cores-${p}"

   for i in "${SEEDS[@]}"
   do
      rand=$i
      echo "Result for probability: ${p}, seed: ${rand}" |& tee -a ${new_dir_name}/output.txt
      result=$(timeout -s SIGINT 120 sudo python3 nitrosketch-univmon.py -i ${IFACE} -p ${p} --read ${TEST_DURATION} -s ${rand} -q --count-bytes --count-pkts)
      echo "${result}" |& tee -a ${new_dir_name}/output.txt
      echo "${p},${result},${i}" &>> ${new_dir_name}/${file_name}.log
      echo "" |& tee -a ${new_dir_name}/output.txt
      sleep 5
   done
done
popd

if [ -z "${1}" ]; then
    echo "Done!"
    exit 0
else
   curl -X POST -H 'Content-type: application/json' --data '{"text":"Test Nitrosketch Univmon Drop one!"}' $1
fi
