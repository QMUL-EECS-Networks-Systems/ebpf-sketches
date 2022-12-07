#pragma once

#define FORCE_INLINE inline __attribute__((__always_inline__))

/* from linux/socket.h */
#define AF_INET 2   /* Internet IP Protocol 	*/
#define AF_INET6 10 /* IP version 6			*/
/***********************/

/* from linux/filter.h */
#define BPF_NET_OFF (-0x100000)
#define BPF_LL_OFF (-0x200000)
/***********************/

/* Accept - allow any number of bytes */
#define SKB_PASS -1
/* Drop, cut packet to zero bytes */
#define SKB_REJECT 0

#define ETH_P_IP 0x0800
#define ETH_P_IPV6 0x86DD

#define CHECK_BIT(var,pos) ((var) & (1<<(pos)))

unsigned long long load_byte(void *skb, unsigned long long off) asm("llvm.bpf.load.byte");
unsigned long long load_half(void *skb, unsigned long long off) asm("llvm.bpf.load.half");
unsigned long long load_word(void *skb, unsigned long long off) asm("llvm.bpf.load.word");

#define ARRAY_SIZE(a) (sizeof(a)/sizeof(a[0]))

struct eth_hdr {
  __be64 dst : 48;
  __be64 src : 48;
  __be16 proto;
} __attribute__((packed));

/*The struct defined in tcp.h lets flags be accessed only one by one,
*it is not needed here.*/
struct tcp_hdr {
  __be16 source;
  __be16 dest;
  __be32 seq;
  __be32 ack_seq;
  __u8 doff : 4, res1 : 4;
  __u8 flags;
  __be16 window;
  __sum16 check;
  __be16 urg_ptr;
} __attribute__((packed));


static uint32_t __always_inline leftmost_ones(uint32_t x)
{
    x = ~x;
    x |= x >> 16;
    x |= x >> 8;
    x |= x >> 4;
    x |= x >> 2;
    x |= x >> 1;
    x = ~x;

    return (x & 1) + (x >> 1 & 1) + (x >> 2 & 1) + (x >> 3 & 1) + (x >> 4 & 1) + 
        (x >> 5 & 1) + (x >> 6 & 1) + (x >> 7 & 1) + (x >> 8 & 1) + (x >> 9 & 1) + 
        (x >> 10 & 1) + (x >> 11 & 1) + (x >> 12 & 1) + (x >> 13 & 1) + (x >> 14 & 1) +
        (x >> 15 & 1) + (x >> 16 & 1) + (x >> 17 & 1) + (x >> 18 & 1) + (x >> 19 & 1) +
        (x >> 20 & 1) + (x >> 21 & 1) + (x >> 22 & 1) + (x >> 23 & 1) + (x >> 24 & 1) +
        (x >> 25 & 1) + (x >> 26 & 1) + (x >> 27 & 1) + (x >> 28 & 1) + (x >> 29 & 1) +
        (x >> 30 & 1) + (x >> 31 & 1);
}

// This would be the preferred choice, but the __builtin_clz function is not available
static uint32_t __always_inline leftmost_ones2(uint32_t x)
{
    if (x == 0) return 0;
    return __builtin_clz(~x);
}

static __always_inline uint32_t leftmost_ones3(uint32_t value) {
    if (~value == 0) {
        return 32;
    }

    value = ~value;
    uint32_t msb = 1 << (32 - 1);
    uint32_t count = 0;

// #pragma clang loop unroll(full)
    for(int i = 0; i < 32; i++)
    {
        /* If leading set bit is found */
        if((value << i) & msb)
        {
            /* Terminate the loop */
            break;
        }

        count++;
    }
    return count;
}

static uint32_t leftmost_ones4(uint32_t value) {
    if (value == 4294967295) {
        return 32;
    }

    uint32_t msb = 1 << (32 - 1);

    uint32_t count = 0;

// #pragma clang loop unroll(full)
    for(int i = 0; i < 32; i++)
    {
        /* If leading set bit is found */
        if((value << i) & msb)
        {
            /* Terminate the loop */
            count++;
        } else {
        	break;
		}        
    }
    return count;
}

static uint32_t leftmost_ones5(uint32_t x)
{
	x = ~x;
    const uint32_t numIntBits = sizeof(uint32_t) * 8; //compile time constant
    //do the smearing
    x |= x >> 1; 
    x |= x >> 2;
    x |= x >> 4;
    x |= x >> 8;
    x |= x >> 16;

    x -= x >> 1 & 0x55555555;
    x = (x >> 2 & 0x33333333) + (x & 0x33333333);
    x = (x >> 4) + x & 0x0f0f0f0f;
    x += x >> 8;
    x += x >> 16;
    return numIntBits - (x & 0x0000003f); 
}

static int average_without_overflow(int a, int b) {
    return (a & b) + ((a ^ b) >> 1);
}

static int __always_inline median(int *vect, int len) {
    int temp;
    int i, j;
    // the following two loops sort the array in ascending order
    // FIXME: We might implement something more efficient here (e.g., quicksort)
    for(i = 0; i < len-1; i++) {
        for(j = i+1; j < len; j++) {
            if(vect[j] < vect[i]) {
                // swap elements
                temp = vect[i];
                vect[i] = vect[j];
                vect[j] = temp;
            }
        }
    }

    if(len % 2 == 0) {
        // if there is an even number of elements, return mean of the two elements in the middle
        // return((vect[len/2] + vect[len/2 - 1]) / 2);
        average_without_overflow(vect[len/2], vect[len/2 - 1]);
    } else {
        // else return the element in the middle
        return vect[len/2];
    }
}

static int __always_inline median_of_five(int a, int b, int c, int d, int e)
{
    return b < a ? d < c ? b < d ? a < e ? a < d ? e < d ? e : d
    : c < a ? c : a
    : e < d ? a < d ? a : d
    : c < e ? c : e
    : c < e ? b < c ? a < c ? a : c
    : e < b ? e : b
    : b < e ? a < e ? a : e
    : c < b ? c : b
    : b < c ? a < e ? a < c ? e < c ? e : c
    : d < a ? d : a
    : e < c ? a < c ? a : c
    : d < e ? d : e
    : d < e ? b < d ? a < d ? a : d
    : e < b ? e : b
    : b < e ? a < e ? a : e
    : d < b ? d : b
    : d < c ? a < d ? b < e ? b < d ? e < d ? e : d
    : c < b ? c : b
    : e < d ? b < d ? b : d
    : c < e ? c : e
    : c < e ? a < c ? b < c ? b : c
    : e < a ? e : a
    : a < e ? b < e ? b : e
    : c < a ? c : a
    : a < c ? b < e ? b < c ? e < c ? e : c
    : d < b ? d : b
    : e < c ? b < c ? b : c
    : d < e ? d : e
    : d < e ? a < d ? b < d ? b : d
    : e < a ? e : a
    : a < e ? b < e ? b : e
    : d < a ? d : a;
}

typedef __u8  __attribute__((__may_alias__))  __u8_alias_t;
typedef __u16 __attribute__((__may_alias__)) __u16_alias_t;
typedef __u32 __attribute__((__may_alias__)) __u32_alias_t;
typedef __u64 __attribute__((__may_alias__)) __u64_alias_t;

static __always_inline void __read_once_size_custom(const volatile void *p, void *res, int size)
{
	switch (size) {
	case 1: *(__u8_alias_t  *) res = *(volatile __u8_alias_t  *) p; break;
	case 2: *(__u16_alias_t *) res = *(volatile __u16_alias_t *) p; break;
	case 4: *(__u32_alias_t *) res = *(volatile __u32_alias_t *) p; break;
	case 8: *(__u64_alias_t *) res = *(volatile __u64_alias_t *) p; break;
	default:
		asm volatile ("" : : : "memory");
		__builtin_memcpy((void *)res, (const void *)p, size);
		asm volatile ("" : : : "memory");
	}
}

static __always_inline void __write_once_size_custom(volatile void *p, void *res, int size)
{
	switch (size) {
	case 1: *(volatile  __u8_alias_t *) p = *(__u8_alias_t  *) res; break;
	case 2: *(volatile __u16_alias_t *) p = *(__u16_alias_t *) res; break;
	case 4: *(volatile __u32_alias_t *) p = *(__u32_alias_t *) res; break;
	case 8: *(volatile __u64_alias_t *) p = *(__u64_alias_t *) res; break;
	default:
		asm volatile ("" : : : "memory");
		__builtin_memcpy((void *)p, (const void *)res, size);
		asm volatile ("" : : : "memory");
	}
}

#define READ_ONCE(x)					\
({							\
	union { typeof(x) __val; char __c[1]; } __u =	\
		{ .__c = { 0 } };			\
	__read_once_size_custom(&(x), __u.__c, sizeof(x));	\
	__u.__val;					\
})

#define WRITE_ONCE(x, val)				\
({							\
	union { typeof(x) __val; char __c[1]; } __u =	\
		{ .__val = (val) }; 			\
	__write_once_size_custom(&(x), __u.__c, sizeof(x));	\
	__u.__val;					\
})

#define NO_TEAR_ADD(x, val) WRITE_ONCE((x), READ_ONCE(x) + (val))
#define NO_TEAR_INC(x) NO_TEAR_ADD((x), 1)

// static int __always_inline quickselect(int *v, int len, int k) {
// 	int i, st, tmp;
 
// 	for (st = i = 0; i < len - 1; i++) {
// 		if (v[i] > v[len-1]) continue;
// 		SWAP(i, st);
// 		st++;
// 	}
 
// 	SWAP(len-1, st);
 
// 	return k == st	?v[st]
// 			:st > k	? quickselect(v, st, k)
// 				: quickselect(v + st, len - st, k - st);
// }