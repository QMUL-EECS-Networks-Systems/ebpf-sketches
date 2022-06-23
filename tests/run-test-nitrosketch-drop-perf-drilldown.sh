#!/bin/bash

#set -x

TEST_DIR="results/perf-drilldown/nitrosketch"
IFACE="ens4f0"
TEST_DURATION=10
PROBS=( 0.01 0.5 1 )
SEEDS=( 1234 2375 3522 23738 1918 )

SCRIPT_BASE_DIR="nitrosketch-perf-drilldown"

declare -a arr=("nitrosketch-conf1.py" 
                "nitrosketch-conf2.py"
                "nitrosketch-conf3.py"
                "nitrosketch-conf4.py"
                "nitrosketch-conf5.py"
                "nitrosketch-conf6.py"
                )

pushd ..

now=`date +"%Y-%m-%d_%H-%M-%S"`
new_dir_name="${TEST_DIR}/run_${now}"
mkdir -p ${new_dir_name}
rm ${new_dir_name}/output.txt

run=0
for script_name in "${arr[@]}"
do
    run=$((run+1))
    for p in "${PROBS[@]}"
    do
        echo "Starting ${script_name} with probability ${p}"
        file_name="exp-ns-conf${run}-perc-${p}"
        for seed in "${SEEDS[@]}"
        do
            echo "Result for probability: ${p}, seed: ${seed}" |& tee -a ${new_dir_name}/output.txt
            result=$(timeout -s SIGINT 120 sudo python3 ${SCRIPT_BASE_DIR}/${script_name} -i ${IFACE} -p ${p} --read ${TEST_DURATION} -s ${seed} -q)
            echo "${result}" |& tee -a ${new_dir_name}/output.txt
            echo "${p},${result},${seed}" &>> ${new_dir_name}/${file_name}.log
            echo "" |& tee -a ${new_dir_name}/output.txt
            sleep 5
        done
    done
done
popd

if [ -z "${1}" ]; then
    echo "Done!"
    exit 0
else
    curl -X POST -H 'Content-type: application/json' --data '{"text":"Test Nitrosketch Drop Performance Drilldown done!"}' $1
fi
