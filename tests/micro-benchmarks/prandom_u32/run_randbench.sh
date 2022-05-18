#!/bin/bash

NUMBER_RUNS=1

BIN_FOLDER="bin"
RESULT_FOLDER="results"

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

function show_help() {
usage="$(basename "$0") [-h] [-r #runs]
Run tests to benchmark different hash functions
where:
    -h  show this help text
    -r  number of runs for the test"

echo "$usage"
}

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

make
echo "Programs compiled"

rm -rf ${RESULT_FOLDER}
mkdir -p "${RESULT_FOLDER}"

# SIP
for (( c=1; c<=$NUMBER_RUNS; c++ ))
do
    echo "SIP:"
    sudo ./${BIN_FOLDER}/main_sip |& tee -a ${RESULT_FOLDER}/exp-sip.log
    echo "" |& tee -a ${RESULT_FOLDER}/exp-sip.log
    sleep 5
done

# TAUSWORTHE
for (( c=1; c<=$NUMBER_RUNS; c++ ))
do
    echo "TAUSWORTHE:"
    sudo ./${BIN_FOLDER}/main_tausworthe |& tee -a ${RESULT_FOLDER}/exp-main_tausworthe.log
    echo "" |& tee -a ${RESULT_FOLDER}/exp-main_tausworthe.log
    sleep 5
done

popd