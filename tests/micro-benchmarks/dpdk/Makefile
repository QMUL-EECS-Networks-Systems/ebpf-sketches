# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2010-2014 Intel Corporation

# binary name
APP1 = array_test_1MAP4READS
APP2 = array_test_4MAP4READS

# all source are stored in SRCS-y
SRCSAPP1-y := array_test_1MAP4READS.c
SRCSAPP2-y := array_test_4MAP4READS.c

PKGCONF ?= pkg-config

# Build using pkg-config variables if possible
ifneq ($(shell $(PKGCONF) --exists libdpdk && echo 0),0)
$(error "no installation of DPDK found")
endif

all: shared
.PHONY: shared static
shared: build/$(APP1)-shared build/$(APP2)-shared
		ln -sf $(APP1)-shared build/$(APP1)
		ln -sf $(APP2)-shared build/$(APP2)
static: build/$(APP1)-static build/$(APP2)-static
		ln -sf $(APP1)-static build/$(APP1)
		ln -sf $(APP2)-static build/$(APP2)

PC_FILE := $(shell $(PKGCONF) --path libdpdk 2>/dev/null)
CFLAGS += -O3 $(shell $(PKGCONF) --cflags libdpdk)
LDFLAGS_SHARED = $(shell $(PKGCONF) --libs libdpdk) -lm
LDFLAGS_STATIC = $(shell $(PKGCONF) --static --libs libdpdk) -lm

CFLAGS += -DALLOW_EXPERIMENTAL_API

build/$(APP1)-shared: $(SRCSAPP1-y) Makefile $(PC_FILE) | build
	$(CC) $(CFLAGS) $(SRCSAPP1-y) -o $@ $(LDFLAGS) $(LDFLAGS_SHARED) 

build/$(APP1)-static: $(SRCSAPP1-y) Makefile $(PC_FILE) | build
	$(CC) $(CFLAGS) $(SRCSAPP1-y) -o $@ $(LDFLAGS) $(LDFLAGS_STATIC)

build/$(APP2)-shared: $(SRCSAPP2-y) Makefile $(PC_FILE) | build
	$(CC) $(CFLAGS) $(SRCSAPP2-y) -o $@ $(LDFLAGS) $(LDFLAGS_SHARED) 

build/$(APP2)-static: $(SRCSAPP2-y) Makefile $(PC_FILE) | build
	$(CC) $(CFLAGS) $(SRCSAPP2-y) -o $@ $(LDFLAGS) $(LDFLAGS_STATIC)

build:
	@mkdir -p $@

.PHONY: clean
clean:
	rm -f build/$(APP1) build/$(APP1)-static build/$(APP1)-shared
	rm -f build/$(APP2) build/$(APP2)-static build/$(APP2)-shared
	test -d build && rmdir -p build || true
