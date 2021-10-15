CC = cc  # C compiler
CFLAGS = -fPIC  # C flags
LDFLAGS = -shared   # linking flags
RM = rm -f   # rm command

FASTHASH_LIB = libfasthash.so  # target lib
LOOKUP3_LIB = liblookup3.so  # target lib
JHASH_LIB = libjhash.so  # target lib
XXHASH32_LIB = libxxhash32.so  # target lib
XXHASH64_LIB = libxxhash64.so  # target lib

FASTHASH_SRCS = fasthash.c # source files
LOOKUP3_SRCS = lookup3.c
JHASH_SRCS = jhash.c
XXHASH32_SRCS = xxhash32.c
XXHASH64_SRCS = xxhash64.c

FASTHASH_OBJS = $(FASTHASH_SRCS:.c=.o)
LOOKUP3_OBJS = $(LOOKUP3_SRCS:.c=.o)
JHASH_OBJS = $(JHASH_SRCS:.c=.o)
XXHASH32_OBJS = $(XXHASH32_SRCS:.c=.o)
XXHASH64_OBJS = $(XXHASH64_SRCS:.c=.o)

.PHONY: all
all: ${FASTHASH_LIB} ${LOOKUP3_LIB} $(JHASH_LIB) $(XXHASH32_LIB) $(XXHASH64_LIB) clean-obj

$(FASTHASH_LIB): $(FASTHASH_OBJS)
	$(CC) $(CFLAGS) ${LDFLAGS} -o $@ $^

$(LOOKUP3_LIB): $(LOOKUP3_OBJS)
	$(CC) $(CFLAGS) ${LDFLAGS} -o $@ $^

$(JHASH_LIB): $(JHASH_OBJS)
	$(CC) $(CFLAGS) ${LDFLAGS} -o $@ $^

$(XXHASH32_LIB): $(XXHASH32_OBJS)
	$(CC) $(CFLAGS) ${LDFLAGS} -o $@ $^

$(XXHASH64_LIB): $(XXHASH64_OBJS)
	$(CC) $(CFLAGS) ${LDFLAGS} -o $@ $^

clean-obj:
	-${RM} ${FASTHASH_OBJS} ${LOOKUP3_OBJS} ${JHASH_OBJS} ${XXHASH32_OBJS} ${XXHASH64_OBJS}

.PHONY: clean
clean:
	-${RM} ${FASTHASH_LIB} ${LOOKUP3_LIB} ${JHASH_LIB} $(XXHASH32_LIB) $(XXHASH64_LIB) ${FASTHASH_OBJS} ${LOOKUP3_OBJS} ${JHASH_OBJS} ${XXHASH32_OBJS} ${XXHASH64_OBJS} $(FASTHASH_SRCS:.c=.d) $(LOOKUP3_SRCS:.c=.d) $(JHASH_SRCS:.c=.d) $(XXHASH32_SRCS:.c=.d) $(XXHASH64_SRCS:.c=.d)