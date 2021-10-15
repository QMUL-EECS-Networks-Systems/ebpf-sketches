/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2006 Bob Jenkins <bob_jenkins@burtleburtle.net> */
/* Copyright (C) 2006-2020 Authors of the Linux kernel */
/* Copyright (C) 2020 Authors of Cilium */

#include <stdio.h>
#include <stddef.h>
#include <stdint.h>

#define JHASH_INITVAL	0xdeadbeef

static __always_inline uint32_t rol32(uint32_t word, uint32_t shift)
{
	return (word << shift) | (word >> ((-shift) & 31));
}

#define __jhash_mix(a, b, c)			\
{						\
	a -= c;  a ^= rol32(c, 4);  c += b;	\
	b -= a;  b ^= rol32(a, 6);  a += c;	\
	c -= b;  c ^= rol32(b, 8);  b += a;	\
	a -= c;  a ^= rol32(c, 16); c += b;	\
	b -= a;  b ^= rol32(a, 19); a += c;	\
	c -= b;  c ^= rol32(b, 4);  b += a;	\
}

#define __jhash_final(a, b, c)			\
{						\
	c ^= b; c -= rol32(b, 14);		\
	a ^= c; a -= rol32(c, 11);		\
	b ^= a; b -= rol32(a, 25);		\
	c ^= b; c -= rol32(b, 16);		\
	a ^= c; a -= rol32(c, 4);		\
	b ^= a; b -= rol32(a, 14);		\
	c ^= b; c -= rol32(b, 24);		\
}

uint32_t jhash(const void *key, uint32_t length, uint32_t initval)
{
	const unsigned char *k = key;
	uint32_t a, b, c;
	
	a = b = c = JHASH_INITVAL + length + initval;

	while (length > 12) {
		a += *(uint32_t *)(k);
		b += *(uint32_t *)(k + 4);
		c += *(uint32_t *)(k + 8);

		__jhash_mix(a, b, c);
		length -= 12;
		k += 12;
	}

	switch (length) {
	case 12: c += (uint32_t)k[11] << 24;
	case 11: c += (uint32_t)k[10] << 16;
	case 10: c +=  (uint32_t)k[9] <<  8;
	case 9:  c +=  (uint32_t)k[8];
	case 8:  b +=  (uint32_t)k[7] << 24;
	case 7:  b +=  (uint32_t)k[6] << 16;
	case 6:  b +=  (uint32_t)k[5] <<  8;
	case 5:  b +=  (uint32_t)k[4];
	case 4:  a +=  (uint32_t)k[3] << 24;
	case 3:  a +=  (uint32_t)k[2] << 16;
	case 2:  a +=  (uint32_t)k[1] <<  8;
	case 1:  a +=  (uint32_t)k[0];

		__jhash_final(a, b, c);
	case 0: /* Nothing left to add */
		break;
	}

	return c;
}

static __always_inline uint32_t __jhash_nwords(uint32_t a, uint32_t b, uint32_t c,
					    uint32_t initval)
{
	a += initval;
	b += initval;
	c += initval;
	__jhash_final(a, b, c);
	return c;
}

uint32_t jhash_3words(uint32_t a, uint32_t b, uint32_t c,
					  uint32_t initval)
{
	return __jhash_nwords(a, b, c, initval + JHASH_INITVAL + (3 << 2));
}

uint32_t jhash_2words(uint32_t a, uint32_t b, uint32_t initval)
{
	return __jhash_nwords(a, b, 0, initval + JHASH_INITVAL + (2 << 2));
}

uint32_t jhash_1word(uint32_t a, uint32_t initval)
{
	return __jhash_nwords(a, 0, 0, initval + JHASH_INITVAL + (1 << 2));
}