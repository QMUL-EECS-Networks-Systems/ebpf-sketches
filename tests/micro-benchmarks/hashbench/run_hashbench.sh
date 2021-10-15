#!/bin/bash

NUMBER_RUNS=5

SIMD_TEST=false
NO_SIMD_TEST=false
COMPILE_ONLY=false

function show_help() {
usage="$(basename "$0") [-h] [-r #runs] [-o output_file] [-i|-n]
Run tests to benchmark different hash functions
where:
    -h  show this help text
    -r  number of runs for the test
    -s  run SIMD tests
    -n  run no-SIMD tests
    -c  compile only"

echo "$usage"
}

while getopts :r:snch option; do
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
 :)
    echo "Option -$OPTARG requires an argument." >&2
    show_help
    exit 0
    ;;
 esac
done

function compile_programs() {
    rm -rf bin-simd
    rm -rf bin-no-simd
    mkdir -p bin-simd
    mkdir -p bin-no-simd
    # JHASH
    gcc -flto -Ofast	-march=native -msse2 -ffast-math -I../bpf_progs/hash_libs bench_jhash.c -o bin-simd/bench_jhash-simd-on
    gcc -flto -Ofast	-fno-tree-vectorize -mno-avx -mno-avx512f -I../bpf_progs/hash_libs bench_jhash.c -o bin-no-simd/bench_jhash-simd-off

    # LITTLEHASH
    gcc -flto -Ofast	-march=native -msse2 -ffast-math -I../bpf_progs/hash_libs bench_littlehash.c -o bin-simd/bench_littlehash-simd-on
    gcc -flto -Ofast	-fno-tree-vectorize -mno-avx -mno-avx512f -I../bpf_progs/hash_libs bench_littlehash.c -o bin-no-simd/bench_littlehash-simd-off

    # FASTHASH
    gcc -flto -Ofast	-march=native -msse2 -ffast-math -I../bpf_progs/hash_libs bench_fasthash.c -o bin-simd/bench_fasthash-simd-on
    gcc -flto -Ofast	-fno-tree-vectorize -mno-avx -mno-avx512f -I../bpf_progs/hash_libs bench_fasthash.c -o bin-no-simd/bench_fasthash-simd-off

    # CSIPHASH
    gcc -flto -Ofast	-march=native -msse2 -ffast-math -I../bpf_progs/hash_libs bench_csiphash.c -o bin-simd/bench_csiphash-simd-on
    gcc -flto -Ofast	-fno-tree-vectorize -mno-avx -mno-avx512f -I../bpf_progs/hash_libs bench_csiphash.c -o bin-no-simd/bench_csiphash-simd-off

    # XXHASH32
    gcc -flto -Ofast	-march=native -msse2 -ffast-math -I../bpf_progs/hash_libs bench_xxhash32.c -o bin-simd/bench_xxhash32-simd-on
    gcc -flto -Ofast	-fno-tree-vectorize -mno-avx -mno-avx512f -I../bpf_progs/hash_libs bench_xxhash32.c -o bin-no-simd/bench_xxhash32-simd-off

    echo "Programs compiled"
}

compile_programs
if [ "$COMPILE_ONLY" = true ] ; then
    exit 0
fi

echo "Starting benchmark..."
rm -rf results
mkdir results

# JHASH
for i in {1..$NUMBER_RUNS}
do
    if [ "$SIMD_TEST" = true ] ; then
        sudo ./bin-simd/bench_jhash-simd-on |& tee -a results/exp-JHASH-simd.log
        echo "" |& tee -a results/exp-JHASH-simd.log
        sleep 5
    fi
    if [ "$NO_SIMD_TEST" = true ] ; then
        sudo ./bin-no-simd/bench_jhash-simd-off |& tee -a results/exp-JHASH-simd-off.log
        echo "" |& tee -a results/exp-JHASH-simd-off.log
        sleep 5
    fi
done

# LITTLEHASH
for i in {1..$NUMBER_RUNS}
do
    if [ "$SIMD_TEST" = true ] ; then
        sudo ./bin-simd/bench_littlehash-simd-on |& tee -a results/exp-LITTLEHASH-simd.log
        echo "" |& tee -a results/exp-LITTLEHASH-simd.log
        sleep 5
    fi
    if [ "$NO_SIMD_TEST" = true ] ; then
        sudo ./bin-no-simd/bench_littlehash-simd-off |& tee -a results/exp-LITTLEHASH-simd-off.log
        echo "" |& tee -a results/exp-LITTLEHASH-simd-off.log
        sleep 5
    fi
done

# FASTHASH
for i in {1..$NUMBER_RUNS}
do
    if [ "$SIMD_TEST" = true ] ; then
        sudo ./bin-simd/bench_fasthash-simd-on |& tee -a results/exp-FASTHASH-simd.log
        echo "" |& tee -a results/exp-FASTHASH-simd.log
        sleep 5
    fi
    if [ "$NO_SIMD_TEST" = true ] ; then
        sudo ./bin-no-simd/bench_fasthash-simd-off |& tee -a results/exp-FASTHASH-simd-off.log
        echo "" |& tee -a results/exp-FASTHASH-simd-off.log
        sleep 5
    fi
done

# CSIPHASH
for i in {1..$NUMBER_RUNS}
do
    if [ "$SIMD_TEST" = true ] ; then
        sudo ./bin-simd/bench_csiphash-simd-on |& tee -a results/exp-CSIPHASH-simd.log
        echo "" |& tee -a results/exp-CSIPHASH-simd.log
        sleep 5
    fi
    if [ "$NO_SIMD_TEST" = true ] ; then
        sudo ./bin-no-simd/bench_csiphash-simd-off |& tee -a results/exp-CSIPHASH-simd-off.log
        echo "" |& tee -a results/exp-CSIPHASH-simd-off.log
        sleep 5
    fi
done

# XXHASH32
for i in {1..$NUMBER_RUNS}
do
    if [ "$SIMD_TEST" = true ] ; then
        sudo ./bin-simd/bench_xxhash32-simd-on |& tee -a results/exp-XXHASH32-simd.log
        echo "" |& tee -a results/exp-XXHASH32-simd.log
        sleep 5
    fi
    if [ "$NO_SIMD_TEST" = true ] ; then
        sudo ./bin-no-simd/bench_xxhash32-simd-off |& tee -a results/exp-XXHASH32-simd-off.log
        echo "" |& tee -a results/exp-XXHASH32-simd-off.log
        sleep 5
    fi
done