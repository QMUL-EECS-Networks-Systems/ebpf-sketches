#!/bin/bash

NUMBER_RUNS=1

SIMD_TEST=false
NO_SIMD_TEST=false
COMPILE_ONLY=false
TEST_ALL_OPT_LEVELS=false

GCC_SIMD_BIN_FOLDER="gcc-bin-simd"
GCC_NO_SIMD_BIN_FOLDER="gcc-bin-no-simd"

CLANG_SIMD_BIN_FOLDER="clang-bin-simd"
CLANG_NO_SIMD_BIN_FOLDER="clang-bin-no-simd"

OBJ_DUMP_CLANG_FOLDER="obj-dump-clang"
OBJ_DUMP_GCC_FOLDER="obj-dump-gcc"

COMPILER_CLANG=clang
COMPILER_CLANGPP=clang++
OBJDUMP_CLANG=llvm-objdump

COMPILER_GCC=gcc-11
COMPILER_GPP=g++
OBJDUMP_GCC=objdump

BASE_GCC_RESULT_FOLDER="results-gcc"
BASE_CLANG_RESULT_FOLDER="results-clang"

OPT_LEVEL="-Ofast"
BASE_NO_SIMD_FLAGS="-DNO_SIMD -fno-tree-vectorize -mno-mmx -mno-sse -mno-avx -mno-avx512f"
BASE_SIMD_FLAGS="-march=native -msse2 -mavx -mavx512f"

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

function show_help() {
usage="$(basename "$0") [-h] [-r #runs]
Run tests to benchmark different hash functions
where:
    -h  show this help text
    -r  number of runs for the test
    -s  run SIMD tests
    -n  run no-SIMD tests
    -d  dump assembly code
    -c  compile only
    -a  test all optimization levels"

echo "$usage"
}

while getopts :r:sndach option; do
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
 a) TEST_ALL_OPT_LEVELS=true
  ;;
 :)
    echo "Option -$OPTARG requires an argument." >&2
    show_help
    exit 0
    ;;
 esac
done

function dump_assembly_code() {
    rm -rf ${4}
    mkdir -p ${4}

    # JHASH
    ${1} -f -d -S ${2}/bench_jhash-simd-on > ${4}/bench_jhash-simd-on.dump
    ${1} -f -d -S ${3}/bench_jhash-simd-off > ${4}/bench_jhash-simd-off.dump

    # LITTLEHASH
    ${1} -f -d -S ${2}/bench_littlehash-simd-on > ${4}/bench_littlehash-simd-on.dump
    ${1} -f -d -S ${3}/bench_littlehash-simd-off > ${4}/bench_littlehash-simd-off.dump

    # FASTHASH
    ${1} -f -d -S ${2}/bench_fasthash-simd-on > ${4}/bench_fasthash-simd-on.dump
    ${1} -f -d -S ${3}/bench_fasthash-simd-off > ${4}/bench_fasthash-simd-off.dump

    # CSIPHASH
    ${1} -f -d -S ${2}/bench_csiphash-simd-on > ${4}/bench_csiphash-simd-on.dump
    ${1} -f -d -S ${3}/bench_csiphash-simd-off > ${4}/bench_csiphash-simd-off.dump

    # XXHASH32
    ${1} -f -d -S ${2}/bench_xxhash32-simd-on > ${4}/bench_xxhash32-simd-on.dump
    ${1} -f -d -S ${3}/bench_xxhash32-simd-off > ${4}/bench_xxhash32-simd-off.dump

    # XXHASH32_DANNY
    ${1} -f -d -S ${2}/bench_xxhash32_danny-simd-on > ${4}/bench_xxhash32_danny-simd-on.dump
    ${1} -f -d -S ${3}/bench_xxhash32_danny-simd-off > ${4}/bench_xxhash32_danny-simd-off.dump

    # MURMURHASH3
    ${1} -f -d -S ${2}/bench_murmurhash3-simd-on > ${4}/bench_murmurhash3-simd-on.dump
    ${1} -f -d -S ${3}/bench_murmurhash3-simd-off > ${4}/bench_murmurhash3-simd-off.dump

    echo "Objects dumped"
}

function compile_programs() {
    rm -rf ${2}
    rm -rf ${3}
    mkdir -p ${2}
    mkdir -p ${3}

    echo "SIMD flags: ${SIMD_FLAGS}"
    echo "NO-SIMD flags: ${NO_SIMD_FLAGS}"

    # JHASH
    $1 $4 ${SIMD_FLAGS} -I../bpf_progs/hash_libs bench_jhash.c -o ${2}/bench_jhash-simd-on
    $1 $4 ${NO_SIMD_FLAGS} -I../bpf_progs/hash_libs bench_jhash.c -o ${3}/bench_jhash-simd-off

    # LITTLEHASH
    $1 $4 ${SIMD_FLAGS} -I../bpf_progs/hash_libs bench_littlehash.c -o ${2}/bench_littlehash-simd-on
    $1 $4 ${NO_SIMD_FLAGS} -I../bpf_progs/hash_libs bench_littlehash.c -o ${3}/bench_littlehash-simd-off

    # FASTHASH
    $1 $4 ${SIMD_FLAGS} -I../bpf_progs/hash_libs bench_fasthash.c -o ${2}/bench_fasthash-simd-on
    $1 $4 ${NO_SIMD_FLAGS} -I../bpf_progs/hash_libs bench_fasthash.c -o ${3}/bench_fasthash-simd-off

    # CSIPHASH
    $1 $4 ${SIMD_FLAGS} -I../bpf_progs/hash_libs bench_csiphash.c -o ${2}/bench_csiphash-simd-on
    $1 $4 ${NO_SIMD_FLAGS} -I../bpf_progs/hash_libs bench_csiphash.c -o ${3}/bench_csiphash-simd-off

    # XXHASH32
    $1 $4 ${SIMD_FLAGS} -I../bpf_progs/hash_libs bench_xxhash32.c -o ${2}/bench_xxhash32-simd-on
    $1 $4 ${NO_SIMD_FLAGS} -I../bpf_progs/hash_libs bench_xxhash32.c -o ${3}/bench_xxhash32-simd-off

    # XXHASH32_DANNY
    $1 $4 ${SIMD_FLAGS} -I../bpf_progs/hash_libs bench_xxhash32_danny.c -o ${2}/bench_xxhash32_danny-simd-on
    $1 $4 ${NO_SIMD_FLAGS} -I../bpf_progs/hash_libs bench_xxhash32_danny.c -o ${3}/bench_xxhash32_danny-simd-off

    # MURMURHASH3
    $1 $4 ${SIMD_FLAGS} -I../bpf_progs/hash_libs bench_murmurhash3.c -o ${2}/bench_murmurhash3-simd-on
    $1 $4 ${NO_SIMD_FLAGS} -I../bpf_progs/hash_libs bench_murmurhash3.c -o ${3}/bench_murmurhash3-simd-off

    echo "Programs compiled"
}

function compile_programs_cpp() {
    echo "SIMD flags: ${SIMD_FLAGS}"
    echo "NO-SIMD flags: ${NO_SIMD_FLAGS}"

    # XXHASH32_PARALLEL
    $1 $4 ${SIMD_FLAGS} -I../hashbench bench_xxhash32_parallel.cc -o ${2}/bench_xxhash32_parallel-simd-on
    $1 $4 ${NO_SIMD_FLAGS} -I../hashbench bench_xxhash32_parallel.cc -o ${3}/bench_xxhash32_parallel-simd-off

    # MURMUR3_PARALLEL
    $1 $4 ${SIMD_FLAGS} -I../hashbench bench_murmurhash3_parallel.cc -o ${2}/bench_murmurhash3_parallel-simd-on

    echo "CPP Programs compiled"
}

pushd .
cd ${DIR}

if [ "$DUMP_ASSEMBLY" = true ] ; then
    SIMD_FLAGS="${OPT_LEVEL} ${BASE_SIMD_FLAGS}"
    NO_SIMD_FLAGS="${OPT_LEVEL} ${BASE_NO_SIMD_FLAGS}"

    compile_programs ${COMPILER_GCC} ${GCC_SIMD_BIN_FOLDER} ${GCC_NO_SIMD_BIN_FOLDER} "-g"
    compile_programs ${COMPILER_CLANG} ${CLANG_SIMD_BIN_FOLDER} ${CLANG_NO_SIMD_BIN_FOLDER} "-g"
    compile_programs_cpp ${COMPILER_GPP} ${GCC_SIMD_BIN_FOLDER} ${GCC_NO_SIMD_BIN_FOLDER} "-g"
    compile_programs_cpp ${COMPILER_CLANGPP} ${CLANG_SIMD_BIN_FOLDER} ${CLANG_NO_SIMD_BIN_FOLDER} "-g"
    dump_assembly_code ${OBJDUMP_GCC} ${GCC_SIMD_BIN_FOLDER} ${GCC_NO_SIMD_BIN_FOLDER} ${OBJ_DUMP_GCC_FOLDER}
    dump_assembly_code ${OBJDUMP_CLANG} ${CLANG_SIMD_BIN_FOLDER} ${CLANG_NO_SIMD_BIN_FOLDER} ${OBJ_DUMP_CLANG_FOLDER}
    exit 0
fi

if [ "$TEST_ALL_OPT_LEVELS" = true ] ; then
    declare -a OPTS=("-O0" "-O1" "-O2" "-O3" "-Ofast")
else
    declare -a OPTS=("-Ofast")
fi

for opt in "${OPTS[@]}"
do
    OPT_LEVEL=${opt}
    GCC_RESULT_FOLDER="${BASE_GCC_RESULT_FOLDER}${opt}"
    CLANG_RESULT_FOLDER="${BASE_CLANG_RESULT_FOLDER}${opt}"
    SIMD_FLAGS="${OPT_LEVEL} ${BASE_SIMD_FLAGS}"
    NO_SIMD_FLAGS="${OPT_LEVEL} ${BASE_NO_SIMD_FLAGS}"
    
    compile_programs ${COMPILER_GCC} ${GCC_SIMD_BIN_FOLDER} ${GCC_NO_SIMD_BIN_FOLDER}
    compile_programs ${COMPILER_CLANG} ${CLANG_SIMD_BIN_FOLDER} ${CLANG_NO_SIMD_BIN_FOLDER}

    compile_programs_cpp ${COMPILER_GPP} ${GCC_SIMD_BIN_FOLDER} ${GCC_NO_SIMD_BIN_FOLDER}
    compile_programs_cpp ${COMPILER_CLANGPP} ${CLANG_SIMD_BIN_FOLDER} ${CLANG_NO_SIMD_BIN_FOLDER}
    if [ "$COMPILE_ONLY" = true ] ; then
        exit 0
    fi

    echo "Starting benchmark for ${opt}..."
    rm -rf ${GCC_RESULT_FOLDER}
    mkdir ${GCC_RESULT_FOLDER}

    rm -rf ${CLANG_RESULT_FOLDER}
    mkdir ${CLANG_RESULT_FOLDER}

    # JHASH
    for (( c=1; c<=$NUMBER_RUNS; c++ ))
    do
        if [ "$SIMD_TEST" = true ]; then
            echo "GCC:"
            sudo ./${GCC_SIMD_BIN_FOLDER}/bench_jhash-simd-on |& tee -a ${GCC_RESULT_FOLDER}/exp-JHASH-simd.log
            echo "CLANG:"
            sudo ./${CLANG_SIMD_BIN_FOLDER}/bench_jhash-simd-on |& tee -a ${CLANG_RESULT_FOLDER}/exp-JHASH-simd.log
            echo "" |& tee -a ${GCC_RESULT_FOLDER}/exp-JHASH-simd.log
            echo "" |& tee -a ${CLANG_RESULT_FOLDER}/exp-JHASH-simd.log
            sleep 5
        fi
        if [ "$NO_SIMD_TEST" = true ]; then
            echo "GCC NO-SIMD"
            sudo ./${GCC_NO_SIMD_BIN_FOLDER}/bench_jhash-simd-off |& tee -a ${GCC_RESULT_FOLDER}/exp-JHASH-simd-off.log
            echo "CLANG NO-SIMD"
            sudo ./${CLANG_NO_SIMD_BIN_FOLDER}/bench_jhash-simd-off |& tee -a ${CLANG_RESULT_FOLDER}/exp-JHASH-simd-off.log
            echo "" |& tee -a ${GCC_RESULT_FOLDER}/exp-JHASH-simd-off.log
            echo "" |& tee -a ${CLANG_RESULT_FOLDER}/exp-JHASH-simd-off.log
            sleep 5
        fi
    done

    # LITTLEHASH
    for (( c=1; c<=$NUMBER_RUNS; c++ ))
    do
        if [ "$SIMD_TEST" = true ] ; then
            echo "GCC:"
            sudo ./${GCC_SIMD_BIN_FOLDER}/bench_littlehash-simd-on |& tee -a ${GCC_RESULT_FOLDER}/exp-LITTLEHASH-simd.log
            echo "CLANG:"
            sudo ./${CLANG_SIMD_BIN_FOLDER}/bench_littlehash-simd-on |& tee -a ${CLANG_RESULT_FOLDER}/exp-LITTLEHASH-simd.log
            echo "" |& tee -a ${GCC_RESULT_FOLDER}/exp-LITTLEHASH-simd.log
            echo "" |& tee -a ${CLANG_RESULT_FOLDER}/exp-LITTLEHASH-simd.log
            sleep 5
        fi
        if [ "$NO_SIMD_TEST" = true ] ; then
            echo "GCC NO-SIMD"
            sudo ./${GCC_NO_SIMD_BIN_FOLDER}/bench_littlehash-simd-off |& tee -a ${GCC_RESULT_FOLDER}/exp-LITTLEHASH-simd-off.log
            echo "CLANG NO-SIMD"
            sudo ./${CLANG_NO_SIMD_BIN_FOLDER}/bench_littlehash-simd-off |& tee -a ${CLANG_RESULT_FOLDER}/exp-LITTLEHASH-simd-off.log
            echo "" |& tee -a ${GCC_RESULT_FOLDER}/exp-LITTLEHASH-simd-off.log
            echo "" |& tee -a ${CLANG_RESULT_FOLDER}/exp-LITTLEHASH-simd-off.log
            sleep 5
        fi
    done

    # FASTHASH
    for (( c=1; c<=$NUMBER_RUNS; c++ ))
    do
        if [ "$SIMD_TEST" = true ] ; then
            echo "GCC:"
            sudo ./${GCC_SIMD_BIN_FOLDER}/bench_fasthash-simd-on |& tee -a ${GCC_RESULT_FOLDER}/exp-FASTHASH-simd.log
            echo "CLANG:"
            sudo ./${CLANG_SIMD_BIN_FOLDER}/bench_fasthash-simd-on |& tee -a ${CLANG_RESULT_FOLDER}/exp-FASTHASH-simd.log
            echo "" |& tee -a ${GCC_RESULT_FOLDER}/exp-FASTHASH-simd.log
            echo "" |& tee -a ${CLANG_RESULT_FOLDER}/exp-FASTHASH-simd.log
            sleep 5
        fi
        if [ "$NO_SIMD_TEST" = true ] ; then
            echo "GCC NO-SIMD"
            sudo ./${GCC_NO_SIMD_BIN_FOLDER}/bench_fasthash-simd-off |& tee -a ${GCC_RESULT_FOLDER}/exp-FASTHASH-simd-off.log
            echo "CLANG NO-SIMD"
            sudo ./${CLANG_NO_SIMD_BIN_FOLDER}/bench_fasthash-simd-off |& tee -a ${CLANG_RESULT_FOLDER}/exp-FASTHASH-simd-off.log
            echo "" |& tee -a ${GCC_RESULT_FOLDER}/exp-FASTHASH-simd-off.log
            echo "" |& tee -a ${CLANG_RESULT_FOLDER}/exp-FASTHASH-simd-off.log
            sleep 5
        fi
    done

    # CSIPHASH
    for (( c=1; c<=$NUMBER_RUNS; c++ ))
    do
        if [ "$SIMD_TEST" = true ] ; then
            echo "GCC:"
            sudo ./${GCC_SIMD_BIN_FOLDER}/bench_csiphash-simd-on |& tee -a ${GCC_RESULT_FOLDER}/exp-CSIPHASH-simd.log
            echo "CLANG:"
            sudo ./${CLANG_SIMD_BIN_FOLDER}/bench_csiphash-simd-on |& tee -a ${CLANG_RESULT_FOLDER}/exp-CSIPHASH-simd.log
            echo "" |& tee -a ${GCC_RESULT_FOLDER}/exp-CSIPHASH-simd.log
            echo "" |& tee -a ${CLANG_RESULT_FOLDER}/exp-CSIPHASH-simd.log
            sleep 5
        fi
        if [ "$NO_SIMD_TEST" = true ] ; then
            echo "GCC NO-SIMD"
            sudo ./${GCC_NO_SIMD_BIN_FOLDER}/bench_csiphash-simd-off |& tee -a ${GCC_RESULT_FOLDER}/exp-CSIPHASH-simd-off.log
            echo "CLANG NO-SIMD"
            sudo ./${CLANG_NO_SIMD_BIN_FOLDER}/bench_csiphash-simd-off |& tee -a ${CLANG_RESULT_FOLDER}/exp-CSIPHASH-simd-off.log
            echo "" |& tee -a ${GCC_RESULT_FOLDER}/exp-CSIPHASH-simd-off.log
            echo "" |& tee -a ${CLANG_RESULT_FOLDER}/exp-CSIPHASH-simd-off.log
            sleep 5
        fi
    done

    # XXHASH32
    # for (( c=1; c<=$NUMBER_RUNS; c++ ))
    # do
    #     if [ "$SIMD_TEST" = true ] ; then
    #         echo "GCC:"
    #         sudo ./${GCC_SIMD_BIN_FOLDER}/bench_xxhash32-simd-on |& tee -a ${GCC_RESULT_FOLDER}/exp-XXHASH32-simd.log
    #         echo "CLANG:"
    #         sudo ./${CLANG_SIMD_BIN_FOLDER}/bench_xxhash32-simd-on |& tee -a ${CLANG_RESULT_FOLDER}/exp-XXHASH32-simd.log
    #         echo "" |& tee -a ${GCC_RESULT_FOLDER}/exp-XXHASH32-simd.log
    #         echo "" |& tee -a ${CLANG_RESULT_FOLDER}/exp-XXHASH32-simd.log
    #         sleep 5
    #     fi
    #     if [ "$NO_SIMD_TEST" = true ] ; then
    #         echo "GCC NO-SIMD"
    #         sudo ./${GCC_NO_SIMD_BIN_FOLDER}/bench_xxhash32-simd-off |& tee -a ${GCC_RESULT_FOLDER}/exp-XXHASH32-simd-off.log
    #         echo "CLANG NO-SIMD"
    #         sudo ./${CLANG_NO_SIMD_BIN_FOLDER}/bench_xxhash32-simd-off |& tee -a ${CLANG_RESULT_FOLDER}/exp-XXHASH32-simd-off.log
    #         echo "" |& tee -a ${GCC_RESULT_FOLDER}/exp-XXHASH32-simd-off.log
    #         echo "" |& tee -a ${CLANG_RESULT_FOLDER}/exp-XXHASH32-simd-off.log
    #         sleep 5
    #     fi
    # done

    # XXHASH32_DANNY
    for (( c=1; c<=$NUMBER_RUNS; c++ ))
    do
        if [ "$SIMD_TEST" = true ] ; then
            echo "GCC:"
            sudo ./${GCC_SIMD_BIN_FOLDER}/bench_xxhash32_danny-simd-on |& tee -a ${GCC_RESULT_FOLDER}/exp-XXHASH32_DANNY-simd.log
            echo "CLANG:"
            sudo ./${CLANG_SIMD_BIN_FOLDER}/bench_xxhash32_danny-simd-on |& tee -a ${CLANG_RESULT_FOLDER}/exp-XXHASH32_DANNY-simd.log
            echo "" |& tee -a ${GCC_RESULT_FOLDER}/exp-XXHASH32_DANNY-simd.log
            echo "" |& tee -a ${CLANG_RESULT_FOLDER}/exp-XXHASH32_DANNY-simd.log
            sleep 5
        fi
        if [ "$NO_SIMD_TEST" = true ] ; then
            echo "GCC NO-SIMD"
            sudo ./${GCC_NO_SIMD_BIN_FOLDER}/bench_xxhash32_danny-simd-off |& tee -a ${GCC_RESULT_FOLDER}/exp-XXHASH32_DANNY-simd-off.log
            echo "CLANG NO-SIMD"
            sudo ./${CLANG_NO_SIMD_BIN_FOLDER}/bench_xxhash32_danny-simd-off |& tee -a ${CLANG_RESULT_FOLDER}/exp-XXHASH32_DANNY-simd-off.log
            echo "" |& tee -a ${GCC_RESULT_FOLDER}/exp-XXHASH32_DANNY-simd-off.log
            echo "" |& tee -a ${CLANG_RESULT_FOLDER}/exp-XXHASH32_DANNY-simd-off.log
            sleep 5
        fi
    done

    # XXHASH32_PARALLEL
    for (( c=1; c<=$NUMBER_RUNS; c++ ))
    do
        if [ "$SIMD_TEST" = true ] ; then
            echo "GCC:"
            sudo ./${GCC_SIMD_BIN_FOLDER}/bench_xxhash32_parallel-simd-on |& tee -a ${GCC_RESULT_FOLDER}/exp-XXHASH32_PARALLEL-simd.log
            echo "CLANG:"
            sudo ./${CLANG_SIMD_BIN_FOLDER}/bench_xxhash32_parallel-simd-on |& tee -a ${CLANG_RESULT_FOLDER}/exp-XXHASH32_PARALLEL-simd.log
            echo "" |& tee -a ${GCC_RESULT_FOLDER}/exp-XXHASH32_PARALLEL-simd.log
            echo "" |& tee -a ${CLANG_RESULT_FOLDER}/exp-XXHASH32_PARALLEL-simd.log
            sleep 5
        fi
        if [ "$NO_SIMD_TEST" = true ] ; then
            echo "GCC NO-SIMD"
            sudo ./${GCC_NO_SIMD_BIN_FOLDER}/bench_xxhash32_parallel-simd-off |& tee -a ${GCC_RESULT_FOLDER}/exp-XXHASH32_PARALLEL-simd-off.log
            echo "CLANG NO-SIMD"
            sudo ./${CLANG_NO_SIMD_BIN_FOLDER}/bench_xxhash32_parallel-simd-off |& tee -a ${CLANG_RESULT_FOLDER}/exp-XXHASH32_PARALLEL-simd-off.log
            echo "" |& tee -a ${GCC_RESULT_FOLDER}/exp-XXHASH32_PARALLEL-simd-off.log
            echo "" |& tee -a ${CLANG_RESULT_FOLDER}/exp-XXHASH32_PARALLEL-simd-off.log
            sleep 5
        fi
    done

    # MURMURHASH3
    for (( c=1; c<=$NUMBER_RUNS; c++ ))
    do
        if [ "$SIMD_TEST" = true ] ; then
            echo "GCC:"
            sudo ./${GCC_SIMD_BIN_FOLDER}/bench_murmurhash3-simd-on |& tee -a ${GCC_RESULT_FOLDER}/exp-MURMURHASH3-simd.log
            echo "CLANG:"
            sudo ./${CLANG_SIMD_BIN_FOLDER}/bench_murmurhash3-simd-on |& tee -a ${CLANG_RESULT_FOLDER}/exp-MURMURHASH3-simd.log
            echo "" |& tee -a ${GCC_RESULT_FOLDER}/exp-MURMURHASH3-simd.log
            echo "" |& tee -a ${CLANG_RESULT_FOLDER}/exp-MURMURHASH3-simd.log
            sleep 5
        fi
        if [ "$NO_SIMD_TEST" = true ] ; then
            echo "GCC NO-SIMD"
            sudo ./${GCC_NO_SIMD_BIN_FOLDER}/bench_murmurhash3-simd-off |& tee -a ${GCC_RESULT_FOLDER}/exp-MURMURHASH3-simd-off.log
            echo "CLANG NO-SIMD"
            sudo ./${CLANG_NO_SIMD_BIN_FOLDER}/bench_murmurhash3-simd-off |& tee -a ${CLANG_RESULT_FOLDER}/exp-MURMURHASH3-simd-off.log
            echo "" |& tee -a ${GCC_RESULT_FOLDER}/exp-MURMURHASH3-simd-off.log
            echo "" |& tee -a ${CLANG_RESULT_FOLDER}/exp-MURMURHASH3-simd-off.log
            sleep 5
        fi
    done


    # MURMURHASH3_PARALLEL
    for (( c=1; c<=$NUMBER_RUNS; c++ ))
    do
        if [ "$SIMD_TEST" = true ] ; then
            echo "GCC:"
            sudo ./${GCC_SIMD_BIN_FOLDER}/bench_murmurhash3_parallel-simd-on |& tee -a ${GCC_RESULT_FOLDER}/exp-MURMURHASH3_PARALLEL-simd.log
            echo "CLANG:"
            sudo ./${CLANG_SIMD_BIN_FOLDER}/bench_murmurhash3_parallel-simd-on |& tee -a ${CLANG_RESULT_FOLDER}/exp-MURMURHASH3_PARALLEL-simd.log
            echo "" |& tee -a ${GCC_RESULT_FOLDER}/exp-MURMURHASH3_PARALLEL-simd.log
            echo "" |& tee -a ${CLANG_RESULT_FOLDER}/exp-MURMURHASH3_PARALLEL-simd.log
            sleep 5
        fi
    done

    
done

popd