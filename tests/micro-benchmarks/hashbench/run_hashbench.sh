#!/bin/bash

NUMBER_RUNS=5

SIMD_TEST=false
NO_SIMD_TEST=false
COMPILE_ONLY=false

SIMD_BIN_FOLDER="bin-simd"
NO_SIMD_BIN_FOLDER="bin-no-simd"
OBJ_DUMP_FOLDER="obj-dump"

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

function show_help() {
usage="$(basename "$0") [-h] [-r #runs] [-o output_file] [-i|-n]
Run tests to benchmark different hash functions
where:
    -h  show this help text
    -r  number of runs for the test
    -s  run SIMD tests
    -n  run no-SIMD tests
    -d  dump assembly code
    -c  compile only"

echo "$usage"
}

while getopts :r:sndch option; do
 case "${option}" in
 h|\?)
	show_help
	exit 0
	;;
 r) NUMBER_RUNS=${OPTARG}
	;;
 s) SIMD_TEST=true
	;;
 n) NO_SIMD_TEST=true
  ;;
 c) COMPILE_ONLY=true
  ;;
 d) DUMP_ASSEMBLY=true
  ;;
 :)
    echo "Option -$OPTARG requires an argument." >&2
    show_help
    exit 0
    ;;
 esac
done

function dump_assembly_code() {
    rm -rf ${OBJ_DUMP_FOLDER}
    mkdir -p ${OBJ_DUMP_FOLDER}

    # JHASH
    objdump -d ${SIMD_BIN_FOLDER}/bench_jhash-simd-on > ${OBJ_DUMP_FOLDER}/bench_jhash-simd-on.dump
    objdump -d ${NO_SIMD_BIN_FOLDER}/bench_jhash-simd-off > ${OBJ_DUMP_FOLDER}/bench_jhash-simd-off.dump

    # LITTLEHASH
    objdump -d ${SIMD_BIN_FOLDER}/bench_littlehash-simd-on > ${OBJ_DUMP_FOLDER}/bench_littlehash-simd-on.dump
    objdump -d ${NO_SIMD_BIN_FOLDER}/bench_littlehash-simd-off > ${OBJ_DUMP_FOLDER}/bench_littlehash-simd-off.dump

    # FASTHASH
    objdump -d ${SIMD_BIN_FOLDER}/bench_fasthash-simd-on > ${OBJ_DUMP_FOLDER}/bench_fasthash-simd-on.dump
    objdump -d ${NO_SIMD_BIN_FOLDER}/bench_fasthash-simd-off > ${OBJ_DUMP_FOLDER}/bench_fasthash-simd-off.dump

    # CSIPHASH
    objdump -d ${SIMD_BIN_FOLDER}/bench_csiphash-simd-on > ${OBJ_DUMP_FOLDER}/bench_csiphash-simd-on.dump
    objdump -d ${NO_SIMD_BIN_FOLDER}/bench_csiphash-simd-off > ${OBJ_DUMP_FOLDER}/bench_csiphash-simd-off.dump

    # XXHASH32
    objdump -d ${SIMD_BIN_FOLDER}/bench_xxhash32-simd-on > ${OBJ_DUMP_FOLDER}/bench_xxhash32-simd-on.dump
    objdump -d ${NO_SIMD_BIN_FOLDER}/bench_xxhash32-simd-off > ${OBJ_DUMP_FOLDER}/bench_xxhash32-simd-off.dump

    echo "Objects dumped"
}

NO_SIMD_FLAGS="-fno-tree-vectorize -mno-mmx -mno-sse -mno-avx -mno-avx512f"
SIMD_FLAGS="-O3 -march=native -msse2 -ffast-math"
function compile_programs() {
    rm -rf ${SIMD_BIN_FOLDER}
    rm -rf ${NO_SIMD_BIN_FOLDER}
    mkdir -p ${SIMD_BIN_FOLDER}
    mkdir -p ${NO_SIMD_BIN_FOLDER}
    # JHASH
    gcc -flto ${SIMD_FLAGS} -I../bpf_progs/hash_libs bench_jhash.c -o ${SIMD_BIN_FOLDER}/bench_jhash-simd-on
    gcc -flto -O3 -DNO_SIMD ${NO_SIMD_FLAGS} -I../bpf_progs/hash_libs bench_jhash.c -o ${NO_SIMD_BIN_FOLDER}/bench_jhash-simd-off

    # LITTLEHASH
    gcc -flto ${SIMD_FLAGS} -I../bpf_progs/hash_libs bench_littlehash.c -o ${SIMD_BIN_FOLDER}/bench_littlehash-simd-on
    gcc -flto -O3 -DNO_SIMD ${NO_SIMD_FLAGS} -I../bpf_progs/hash_libs bench_littlehash.c -o ${NO_SIMD_BIN_FOLDER}/bench_littlehash-simd-off

    # FASTHASH
    gcc -flto ${SIMD_FLAGS} -I../bpf_progs/hash_libs bench_fasthash.c -o ${SIMD_BIN_FOLDER}/bench_fasthash-simd-on
    gcc -flto -O3 -DNO_SIMD ${NO_SIMD_FLAGS} -I../bpf_progs/hash_libs bench_fasthash.c -o ${NO_SIMD_BIN_FOLDER}/bench_fasthash-simd-off

    # CSIPHASH
    gcc -flto ${SIMD_FLAGS} -I../bpf_progs/hash_libs bench_csiphash.c -o ${SIMD_BIN_FOLDER}/bench_csiphash-simd-on
    gcc -flto -O3 -DNO_SIMD ${NO_SIMD_FLAGS} -I../bpf_progs/hash_libs bench_csiphash.c -o ${NO_SIMD_BIN_FOLDER}/bench_csiphash-simd-off

    # XXHASH32
    gcc -flto ${SIMD_FLAGS} -I../bpf_progs/hash_libs bench_xxhash32.c -o ${SIMD_BIN_FOLDER}/bench_xxhash32-simd-on
    gcc -flto -O3 -DNO_SIMD ${NO_SIMD_FLAGS} -I../bpf_progs/hash_libs bench_xxhash32.c -o ${NO_SIMD_BIN_FOLDER}/bench_xxhash32-simd-off

    echo "Programs compiled"
}

pushd .
cd ${DIR}

compile_programs
if [ "$COMPILE_ONLY" = true ] ; then
    exit 0
fi

if [ "$DUMP_ASSEMBLY" = true ] ; then
    dump_assembly_code
    exit 0
fi

echo "Starting benchmark..."
rm -rf results
mkdir results

# JHASH
for i in {1..$NUMBER_RUNS}
do
    if [ "$SIMD_TEST" = true ] ; then
        sudo ./${SIMD_BIN_FOLDER}/bench_jhash-simd-on |& tee -a results/exp-JHASH-simd.log
        echo "" |& tee -a results/exp-JHASH-simd.log
        sleep 5
    fi
    if [ "$NO_SIMD_TEST" = true ] ; then
        sudo ./${NO_SIMD_BIN_FOLDER}/bench_jhash-simd-off |& tee -a results/exp-JHASH-simd-off.log
        echo "" |& tee -a results/exp-JHASH-simd-off.log
        sleep 5
    fi
done

# LITTLEHASH
for i in {1..$NUMBER_RUNS}
do
    if [ "$SIMD_TEST" = true ] ; then
        sudo ./${SIMD_BIN_FOLDER}/bench_littlehash-simd-on |& tee -a results/exp-LITTLEHASH-simd.log
        echo "" |& tee -a results/exp-LITTLEHASH-simd.log
        sleep 5
    fi
    if [ "$NO_SIMD_TEST" = true ] ; then
        sudo ./${NO_SIMD_BIN_FOLDER}/bench_littlehash-simd-off |& tee -a results/exp-LITTLEHASH-simd-off.log
        echo "" |& tee -a results/exp-LITTLEHASH-simd-off.log
        sleep 5
    fi
done

# FASTHASH
for i in {1..$NUMBER_RUNS}
do
    if [ "$SIMD_TEST" = true ] ; then
        sudo ./${SIMD_BIN_FOLDER}/bench_fasthash-simd-on |& tee -a results/exp-FASTHASH-simd.log
        echo "" |& tee -a results/exp-FASTHASH-simd.log
        sleep 5
    fi
    if [ "$NO_SIMD_TEST" = true ] ; then
        sudo ./${NO_SIMD_BIN_FOLDER}/bench_fasthash-simd-off |& tee -a results/exp-FASTHASH-simd-off.log
        echo "" |& tee -a results/exp-FASTHASH-simd-off.log
        sleep 5
    fi
done

# CSIPHASH
for i in {1..$NUMBER_RUNS}
do
    if [ "$SIMD_TEST" = true ] ; then
        sudo ./${SIMD_BIN_FOLDER}/bench_csiphash-simd-on |& tee -a results/exp-CSIPHASH-simd.log
        echo "" |& tee -a results/exp-CSIPHASH-simd.log
        sleep 5
    fi
    if [ "$NO_SIMD_TEST" = true ] ; then
        sudo ./${NO_SIMD_BIN_FOLDER}/bench_csiphash-simd-off |& tee -a results/exp-CSIPHASH-simd-off.log
        echo "" |& tee -a results/exp-CSIPHASH-simd-off.log
        sleep 5
    fi
done

# XXHASH32
for i in {1..$NUMBER_RUNS}
do
    if [ "$SIMD_TEST" = true ] ; then
        sudo ./${SIMD_BIN_FOLDER}/bench_xxhash32-simd-on |& tee -a results/exp-XXHASH32-simd.log
        echo "" |& tee -a results/exp-XXHASH32-simd.log
        sleep 5
    fi
    if [ "$NO_SIMD_TEST" = true ] ; then
        sudo ./${NO_SIMD_BIN_FOLDER}/bench_xxhash32-simd-off |& tee -a results/exp-XXHASH32-simd-off.log
        echo "" |& tee -a results/exp-XXHASH32-simd-off.log
        sleep 5
    fi
done

popd