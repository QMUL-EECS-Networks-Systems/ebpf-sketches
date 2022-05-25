#!/bin/bash

NUMBER_RUNS=5

BIN_FOLDER="build"
RESULT_FOLDER="results"

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

APP_CONFIG='-l 0,1 -n 4 -- -p 0x3 --config="(0,0,1),(1,0,1)"'

function show_help() {
usage="$(basename "$0") [-h] [-r #runs]
Run tests to benchmark different rand functions
where:
    -h  show this help text
    -r  number of runs for the test"

echo "$usage"
}

declare -a cycles=(1 2 4 8 16 32 64 128 256 512)

while getopts :r:h option; do
 case "${option}" in
 h|\?)
	show_help
	exit 0
	;;
 r) NUMBER_RUNS=${OPTARG}
	;;
 :)
    echo "Option -$OPTARG requires an argument." >&2
    show_help
    exit 0
    ;;
 esac
done

pushd .
cd ${DIR}

make test
echo "Programs compiled"

rm -rf ${RESULT_FOLDER}
mkdir -p "${RESULT_FOLDER}"

# SIP
for i in "${cycles[@]}"
do
    echo "SIP:"
    for (( c=1; c<=$NUMBER_RUNS; c++ ))
    do
        sudo ./${BIN_FOLDER}/rand_rate_sip_$i ${APP_CONFIG} |& tee -a ${RESULT_FOLDER}/exp-rand-sip-$i.log
        echo "" |& tee -a ${RESULT_FOLDER}/exp-rand-sip-$i.log
        sleep 5
    done
done

# TAUSWORTHE
for i in "${cycles[@]}"
do
    echo "TAUSWORTHE:"
    for (( c=1; c<=$NUMBER_RUNS; c++ ))
    do
        sudo ./${BIN_FOLDER}/rand_rate_tausworthe_$i ${APP_CONFIG} |& tee -a ${RESULT_FOLDER}/exp-rand-tausworthe-$i.log
        echo "" |& tee -a ${RESULT_FOLDER}/exp-rand-tausworthe-$i.log
        sleep 5
    done
done

popd