#!/bin/bash

NUMBER_RUNS=5

SIMD_TEST=false
NO_SIMD_TEST=false
COMPILE_ONLY=false

SIMD_BIN_FOLDER="bin-simd"
NO_SIMD_BIN_FOLDER="bin-no-simd"
OBJ_DUMP_FOLDER="obj-dump"

COMPILER=clang
OBJDUMP=llvm-objdump

# COMPILER=gcc-11
# OBJDUMP=objdump

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
    $OBJDUMP -f -d -S ${SIMD_BIN_FOLDER}/bench_jhash-simd-on > ${OBJ_DUMP_FOLDER}/bench_jhash-simd-on.dump
    $OBJDUMP -f -d -S ${NO_SIMD_BIN_FOLDER}/bench_jhash-simd-off > ${OBJ_DUMP_FOLDER}/bench_jhash-simd-off.dump

    # LITTLEHASH
    $OBJDUMP -f -d -S ${SIMD_BIN_FOLDER}/bench_littlehash-simd-on > ${OBJ_DUMP_FOLDER}/bench_littlehash-simd-on.dump
    $OBJDUMP -f -d -S ${NO_SIMD_BIN_FOLDER}/bench_littlehash-simd-off > ${OBJ_DUMP_FOLDER}/bench_littlehash-simd-off.dump

    # FASTHASH
    $OBJDUMP -f -d -S ${SIMD_BIN_FOLDER}/bench_fasthash-simd-on > ${OBJ_DUMP_FOLDER}/bench_fasthash-simd-on.dump
    $OBJDUMP -f -d -S ${NO_SIMD_BIN_FOLDER}/bench_fasthash-simd-off > ${OBJ_DUMP_FOLDER}/bench_fasthash-simd-off.dump

    # CSIPHASH
    $OBJDUMP -f -d -S ${SIMD_BIN_FOLDER}/bench_csiphash-simd-on > ${OBJ_DUMP_FOLDER}/bench_csiphash-simd-on.dump
    $OBJDUMP -f -d -S ${NO_SIMD_BIN_FOLDER}/bench_csiphash-simd-off > ${OBJ_DUMP_FOLDER}/bench_csiphash-simd-off.dump

    # XXHASH32
    $OBJDUMP -f -d -S ${SIMD_BIN_FOLDER}/bench_xxhash32-simd-on > ${OBJ_DUMP_FOLDER}/bench_xxhash32-simd-on.dump
    $OBJDUMP -f -d -S ${NO_SIMD_BIN_FOLDER}/bench_xxhash32-simd-off > ${OBJ_DUMP_FOLDER}/bench_xxhash32-simd-off.dump

    # XXHASH32_DANNY
    $OBJDUMP -f -d -S ${SIMD_BIN_FOLDER}/bench_xxhash32_danny-simd-on > ${OBJ_DUMP_FOLDER}/bench_xxhash32_danny-simd-on.dump
    $OBJDUMP -f -d -S ${NO_SIMD_BIN_FOLDER}/bench_xxhash32_danny-simd-off > ${OBJ_DUMP_FOLDER}/bench_xxhash32_danny-simd-off.dump

    # MURMURHASH3
    $OBJDUMP -f -d -S ${SIMD_BIN_FOLDER}/bench_murmurhash3-simd-on > ${OBJ_DUMP_FOLDER}/bench_murmurhash3-simd-on.dump
    $OBJDUMP -f -d -S ${NO_SIMD_BIN_FOLDER}/bench_murmurhash3-simd-off > ${OBJ_DUMP_FOLDER}/bench_murmurhash3-simd-off.dump

    echo "Objects dumped"
}

NO_SIMD_FLAGS="-O3 -DNO_SIMD -fno-tree-vectorize -mno-mmx -mno-sse -mno-avx -mno-avx512f"
# SIMD_FLAGS="-O3 -march=native -msse2 -ffast-math"
SIMD_FLAGS="-O3 -march=native"
function compile_programs() {
    rm -rf ${SIMD_BIN_FOLDER}
    rm -rf ${NO_SIMD_BIN_FOLDER}
    mkdir -p ${SIMD_BIN_FOLDER}
    mkdir -p ${NO_SIMD_BIN_FOLDER}
    # JHASH
    $COMPILER $1 ${SIMD_FLAGS} -I../bpf_progs/hash_libs bench_jhash.c -o ${SIMD_BIN_FOLDER}/bench_jhash-simd-on
    $COMPILER $1 ${NO_SIMD_FLAGS} -I../bpf_progs/hash_libs bench_jhash.c -o ${NO_SIMD_BIN_FOLDER}/bench_jhash-simd-off

    # LITTLEHASH
    $COMPILER $1 ${SIMD_FLAGS} -I../bpf_progs/hash_libs bench_littlehash.c -o ${SIMD_BIN_FOLDER}/bench_littlehash-simd-on
    $COMPILER $1 ${NO_SIMD_FLAGS} -I../bpf_progs/hash_libs bench_littlehash.c -o ${NO_SIMD_BIN_FOLDER}/bench_littlehash-simd-off

    # FASTHASH
    $COMPILER $1 ${SIMD_FLAGS} -I../bpf_progs/hash_libs bench_fasthash.c -o ${SIMD_BIN_FOLDER}/bench_fasthash-simd-on
    $COMPILER $1 ${NO_SIMD_FLAGS} -I../bpf_progs/hash_libs bench_fasthash.c -o ${NO_SIMD_BIN_FOLDER}/bench_fasthash-simd-off

    # CSIPHASH
    $COMPILER $1 ${SIMD_FLAGS} -I../bpf_progs/hash_libs bench_csiphash.c -o ${SIMD_BIN_FOLDER}/bench_csiphash-simd-on
    $COMPILER $1 ${NO_SIMD_FLAGS} -I../bpf_progs/hash_libs bench_csiphash.c -o ${NO_SIMD_BIN_FOLDER}/bench_csiphash-simd-off

    # XXHASH32
    $COMPILER $1 ${SIMD_FLAGS} -I../bpf_progs/hash_libs bench_xxhash32.c -o ${SIMD_BIN_FOLDER}/bench_xxhash32-simd-on
    $COMPILER $1 ${NO_SIMD_FLAGS} -I../bpf_progs/hash_libs bench_xxhash32.c -o ${NO_SIMD_BIN_FOLDER}/bench_xxhash32-simd-off

    # XXHASH32_DANNY
    $COMPILER $1 ${SIMD_FLAGS} -I../bpf_progs/hash_libs bench_xxhash32_danny.c -o ${SIMD_BIN_FOLDER}/bench_xxhash32_danny-simd-on
    $COMPILER $1 ${NO_SIMD_FLAGS} -I../bpf_progs/hash_libs bench_xxhash32_danny.c -o ${NO_SIMD_BIN_FOLDER}/bench_xxhash32_danny-simd-off

    # MURMURHASH3
    $COMPILER $1 ${SIMD_FLAGS} -I../bpf_progs/hash_libs bench_murmurhash3.c -o ${SIMD_BIN_FOLDER}/bench_murmurhash3-simd-on
    $COMPILER $1 ${NO_SIMD_FLAGS} -I../bpf_progs/hash_libs bench_murmurhash3.c -o ${NO_SIMD_BIN_FOLDER}/bench_murmurhash3-simd-off

    echo "Programs compiled"
}

pushd .
cd ${DIR}

if [ "$DUMP_ASSEMBLY" = true ] ; then
    compile_programs "-g"
    dump_assembly_code
    exit 0
fi

compile_programs
if [ "$COMPILE_ONLY" = true ] ; then
    exit 0
fi

echo "Starting benchmark..."
rm -rf results
mkdir results

# JHASH
for (( c=1; c<=$NUMBER_RUNS; c++ ))
do
    if [ "$SIMD_TEST" = true ]; then
        sudo ./${SIMD_BIN_FOLDER}/bench_jhash-simd-on |& tee -a results/exp-JHASH-simd.log
        echo "" |& tee -a results/exp-JHASH-simd.log
        sleep 5
    fi
    if [ "$NO_SIMD_TEST" = true ]; then
        sudo ./${NO_SIMD_BIN_FOLDER}/bench_jhash-simd-off |& tee -a results/exp-JHASH-simd-off.log
        echo "" |& tee -a results/exp-JHASH-simd-off.log
        sleep 5
    fi
done

# LITTLEHASH
for (( c=1; c<=$NUMBER_RUNS; c++ ))
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
for (( c=1; c<=$NUMBER_RUNS; c++ ))
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
for (( c=1; c<=$NUMBER_RUNS; c++ ))
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
for (( c=1; c<=$NUMBER_RUNS; c++ ))
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

# XXHASH32_DANNY
for (( c=1; c<=$NUMBER_RUNS; c++ ))
do
    if [ "$SIMD_TEST" = true ] ; then
        sudo ./${SIMD_BIN_FOLDER}/bench_xxhash32_danny-simd-on |& tee -a results/exp-XXHASH32_DANNY-simd.log
        echo "" |& tee -a results/exp-XXHASH32_DANNY-simd.log
        sleep 5
    fi
    if [ "$NO_SIMD_TEST" = true ] ; then
        sudo ./${NO_SIMD_BIN_FOLDER}/bench_xxhash32_danny-simd-off |& tee -a results/exp-XXHASH32_DANNY-simd-off.log
        echo "" |& tee -a results/exp-XXHASH32_DANNY-simd-off.log
        sleep 5
    fi
done

# MURMURHASH3
for (( c=1; c<=$NUMBER_RUNS; c++ ))
do
    if [ "$SIMD_TEST" = true ] ; then
        sudo ./${SIMD_BIN_FOLDER}/bench_murmurhash3-simd-on |& tee -a results/exp-MURMURHASH3-simd.log
        echo "" |& tee -a results/exp-MURMURHASH3-simd.log
        sleep 5
    fi
    if [ "$NO_SIMD_TEST" = true ] ; then
        sudo ./${NO_SIMD_BIN_FOLDER}/bench_murmurhash3-simd-off |& tee -a results/exp-MURMURHASH3-simd-off.log
        echo "" |& tee -a results/exp-MURMURHASH3-simd-off.log
        sleep 5
    fi
done

popd