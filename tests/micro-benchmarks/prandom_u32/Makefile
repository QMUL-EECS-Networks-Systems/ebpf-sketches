
KERNEL_SOURCE=/usr/src/linux-headers-$(shell uname -r)/include/
#KERNEL_SOURCE_ASM=/usr/src/linux-headers-$(shell uname -r)/include/asm-generic/
KERNEL_SOURCE_ASM=.

# g++ main.cpp -O main -I${KERNEL_SOURCE} -I${KERNEL_SOURCE_ASM} -I.
main: main_sip.cpp main_tausworthe.cpp
	@rm -rf bin
	@mkdir -p bin
	g++ -Ofast -march=native main_sip.cpp -o bin/main_sip 
	g++ -Ofast -march=native main_tausworthe.cpp -o bin/main_tausworthe 
