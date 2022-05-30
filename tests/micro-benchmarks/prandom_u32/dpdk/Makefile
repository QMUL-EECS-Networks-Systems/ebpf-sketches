# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2010-2014 Intel Corporation

# binary name
APP1 = rand_rate_sip
APP2 = rand_rate_tausworthe

# all source are stored in SRCS-y
SRCSAPP1-y := rand_rate_sip.c
SRCSAPP2-y := rand_rate_tausworthe.c

SRCSAPP1-mem-y := rand_rate_sip_from_mem.c
SRCSAPP2-mem-y := rand_rate_tausworthe_from_mem.c

PKGCONF ?= pkg-config

# Build using pkg-config variables if possible
ifneq ($(shell $(PKGCONF) --exists libdpdk && echo 0),0)
$(error "no installation of DPDK found")
endif

all: clean static
.PHONY: static
static: build/$(APP1) build/$(APP2)
test: clean build/$(APP1)-test build/$(APP2)-test
test-mem: clean build/$(APP1)-test-mem build/$(APP2)-test-mem

PC_FILE := $(shell $(PKGCONF) --path libdpdk 2>/dev/null)
CFLAGS += -O3 $(shell $(PKGCONF) --cflags libdpdk)
LDFLAGS_SHARED = $(shell $(PKGCONF) --libs libdpdk) -lm
LDFLAGS_STATIC = $(shell $(PKGCONF) --static --libs libdpdk) -lm

CFLAGS += -DALLOW_EXPERIMENTAL_API
NUMBERS = 1 2 4 8 16 32 64 128 256 512
build/$(APP1): $(SRCSAPP1-y) Makefile $(PC_FILE) | build
	$(foreach number,$(NUMBERS),$(CC) $(CFLAGS) -D_NUM_RAND_CYCLES=$(number) -DDEBUG $(SRCSAPP1-y) -o build/$(APP1)_$(number) $(LDFLAGS) $(LDFLAGS_STATIC);)

build/$(APP2): $(SRCSAPP2-y) Makefile $(PC_FILE) | build
	$(foreach number,$(NUMBERS),$(CC) $(CFLAGS) -D_NUM_RAND_CYCLES=$(number) -DDEBUG $(SRCSAPP2-y) -o build/$(APP2)_$(number) $(LDFLAGS) $(LDFLAGS_STATIC);)

build/$(APP1)-test: $(SRCSAPP1-y) Makefile $(PC_FILE) | build
	$(foreach number,$(NUMBERS),$(CC) $(CFLAGS) -D_NUM_RAND_CYCLES=$(number) $(SRCSAPP1-y) -o build/$(APP1)_$(number) $(LDFLAGS) $(LDFLAGS_STATIC);)

build/$(APP2)-test: $(SRCSAPP2-y) Makefile $(PC_FILE) | build
	$(foreach number,$(NUMBERS),$(CC) $(CFLAGS) -D_NUM_RAND_CYCLES=$(number) $(SRCSAPP2-y) -o build/$(APP2)_$(number) $(LDFLAGS) $(LDFLAGS_STATIC);)

build/$(APP1)-test-mem: $(SRCSAPP1-mem-y) Makefile $(PC_FILE) | build
	$(foreach number,$(NUMBERS),$(CC) $(CFLAGS) -D_NUM_RAND_CYCLES=$(number) $(SRCSAPP1-mem-y) -o build/$(APP1)_mem_$(number) $(LDFLAGS) $(LDFLAGS_STATIC);)

build/$(APP2)-test-mem: $(SRCSAPP2-mem-y) Makefile $(PC_FILE) | build
	$(foreach number,$(NUMBERS),$(CC) $(CFLAGS) -D_NUM_RAND_CYCLES=$(number) $(SRCSAPP2-mem-y) -o build/$(APP2)_mem_$(number) $(LDFLAGS) $(LDFLAGS_STATIC);)

build:
	@mkdir -p $@

.PHONY: clean
clean:
	rm -rf build
