// -*- mode: c++; c-basic-offset: 4 indent-tabs-mode: nil -*- */
//
// Copyright 2017 Juho Snellman, released under a MIT license:
//
// Permission is hereby granted, free of charge, to any person obtaining
// a copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to
// permit persons to whom the Software is furnished to do so, subject to
// the following conditions:
//
// The above copyright notice and this permission notice shall be
// included in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
// NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
// LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
// OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
// WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
//
// README
// ------
//
// Two implementations of the 32 bit version of the XXHash
// hash function.
//
// - parallel: Computing the hash values of 8 keys in parallel, using
//   AVX2 intrinsics. (There's also a version with identical semantics
//   but plain C++, which the compiler might or might not be able to
//   auto-vectorize.)
// - scalar: Computing the hash value of a single key.
//
// These are very special purpose implementations, and will not be
// of any interest in most programs. Use these functions if:
//
// - Your keys have a constant size, and are a multiple of 4 bytes
//   long. Variable size keys are not supported. Nor are non-word
//   aligned keys.
// - You have an application that can receive and process inputs
//   in batches such that you usually have 8 keys to process at once.
//   (Doesn't need to be full batches of 8, but the break-even point
//   vs. a fast scalar hash is probably around batches of 3-4 keys).
// - You can arrange for your hash keys to be in a column-major
//   order without too much pain.
// - You can compile the program with -mavx2. (While there is a
//   non-avx2 fallback, there's not a lot of point to it).
// - A single 32 bit hash value per key is sufficient.
//
// The "scalar" implementation is mainly included as a fallback, for
// programs that generally use the parallel code, but have some
// exceptional cases that need identical hash codes for individual
// keys. Except for very small keys (at most 20 bytes), you are probably
// better off with the reference implementation of some modern
// hash function.
//
// DATA LAYOUT
// -----------
//
// For the parallel version the keys should be laid out adjacent to
// each other, in column-major order. That is, the first word in
// "keys" should be the first word of the first key. The second word
// of "keys should be the first word of the second key. And so on:
//
//   key1[0] key2[0] ... key7[0]
//   key2[1] key2[1] ... key7[1]
//   ...
//   key1[SizeWords-1] key2[SizeWords-1] ... key7[SizeWords-1]
//
// EXAMPLES
// --------
//
// Assume the following definitions:
//
//   static const uint32_t KEY_LENGTH = 3;
//
//    static uint32_t rows[][KEY_LENGTH] = {
//       {1, 2, 3},
//       {4, 5, 6},
//       {7, 8, 9},
//       {10, 11, 12},
//       {13, 14, 15},
//       {16, 17, 18},
//       {19, 20, 21},
//       {22, 23, 24},
//   };
//
//   static uint32_t cols[][8] = {
//       {1, 4, 7, 10, 13, 16, 19, 22},
//       {2, 5, 8, 11, 14, 17, 20, 23},
//       {3, 6, 9, 12, 15, 18, 21, 24},
//   };
//
//   static uint32_t seeds[] = { 0x3afc8e77, 0x924f408d };
//   static const uint32_t seed_count = sizeof(seeds) / sizeof(uint32_t);
//
// The implementations could be used as follows to compute hash values
// for each of the key / seed combinations:
//
//   void example_scalar() {
//       for (int s = 0; s < seed_count; ++s) {
//           for (int i = 0; i < 8; ++i) {
//               uint32_t* row = rows[i];
//               uint32_t res = xxhash32<3>::scalar(row, seeds[s]);
//               printf("seed=%08x, key={%u,%u,%u}, hash=%u\n",
//                      seeds[s], row[0], row[1], row[2], res);
//           }
//       }
//   }
//
//   void example_parallel() {
//       for (int s = 0; s < seed_count; ++s) {
//           uint32_t res[8];
//           __m256i hash = xxhash32<3>::parallel(cols[0], seeds[s], res);
//           for (int i = 0; i < 8; ++i) {
//               printf("seed=%08x, key={%u,%u,%u}, hash=%u\n",
//                      seeds[s], cols[0][i], cols[1][i], cols[2][i],
//                      res[i]);
//           }
//       }
//   }


#ifndef PARALLEL_XXHASH_H
#define PARALLEL_XXHASH_H

#include <cstdint>
#include <cstdio>
#if __AVX2__
#include <immintrin.h>
#endif

template<int SizeWords>
struct xxhash32 {

#if __AVX2__
    // Compute a hash value for 8 keys of SizeWords*4 bytes each.
    static void parallel(const uint32_t* keys, uint32_t seed,
                         uint32_t res[8]) {
        __m256i h = _mm256_set1_epi32(seed + PRIME32_5);

        if (SizeWords >= 4) {
            __m256i v1 = _mm256_set1_epi32(seed + PRIME32_1 + PRIME32_2);
            __m256i v2 = _mm256_set1_epi32(seed + PRIME32_2);
            __m256i v3 = _mm256_set1_epi32(seed);
            __m256i v4 = _mm256_set1_epi32(seed - PRIME32_1);
            for (int i = 0; i < (SizeWords & ~3); i += 4) {
                __m256i k1 = _mm256_loadu_si256((__m256i*) (keys + (i + 0) * 8));
                __m256i k2 = _mm256_loadu_si256((__m256i*) (keys + (i + 1) * 8));
                __m256i k3 = _mm256_loadu_si256((__m256i*) (keys + (i + 2) * 8));
                __m256i k4 = _mm256_loadu_si256((__m256i*) (keys + (i + 3) * 8));
                v1 = mm256_round(v1, k1);
                v2 = mm256_round(v2, k2);
                v3 = mm256_round(v3, k3);
                v4 = mm256_round(v4, k4);
            }

            h = mm256_rol32<1>(v1) + mm256_rol32<7>(v2) + mm256_rol32<12>(v3) + mm256_rol32<18>(v4);
        }

        // Mixing in the length here is pretty silly, since it's always
        // constant. But there's probably some value in producing bitwise
        // identical results to the original xxhash code.
        h = _mm256_add_epi32(h, _mm256_set1_epi32(SizeWords * 4));

        for (int i = -(SizeWords & 3); i < 0; ++i) {
            __m256i v = _mm256_loadu_si256((__m256i*) (keys + (SizeWords + i) * 8));
            h = _mm256_add_epi32(h,
                                 _mm256_mullo_epi32(v,
                                                    _mm256_set1_epi32(PRIME32_3)));
            h = _mm256_mullo_epi32(mm256_rol32<17>(h),
                                   _mm256_set1_epi32(PRIME32_4));
        }

        _mm256_storeu_si256((__m256i*) res, mm256_fmix32(h));
    }

#else

    // This will get auto-vectorized perfectly on GCC 6 with
    // -mavx2. It gets auto-vectorized a little bit suboptimally on
    // GCC 4.92, and not at all on clang 3.8. So it's just a bit too
    // fragile actually use as the main implementation.
    static void parallel(const uint32_t* key, uint32_t seed,
                         uint32_t res[8]) {
#warning "No AVX2 support detected, using a fallback version instead."
        uint32_t h[8];
        for (int i = 0; i < 8; ++i) {
            h[i] = seed + PRIME32_5;
        }
        if (SizeWords >= 4) {
            uint32_t v1[8];
            uint32_t v2[8];
            uint32_t v3[8];
            uint32_t v4[8];
            for (int i = 0; i < 8; ++i) {
                v1[i] = seed + PRIME32_1 + PRIME32_2;
                v2[i] = seed + PRIME32_2;
                v3[i] = seed + 0;
                v4[i] = seed - PRIME32_1;
            }
            for (int i = 0; i < (SizeWords & ~3); i += 4) {
                for (int j = 0; j < 8; ++j) {
                    v1[j] = round(v1[j], key[(i + 0) * 8 + j]);
                    v2[j] = round(v2[j], key[(i + 1) * 8 + j]);
                    v3[j] = round(v3[j], key[(i + 2) * 8 + j]);
                    v4[j] = round(v4[j], key[(i + 3) * 8 + j]);
                }
            }

            for (int i = 0; i < 8; ++i) {
                h[i] = rol32<1>(v1[i]) + rol32<7>(v2[i]) + rol32<12>(v3[i]) + rol32<18>(v4[i]);
            }
        }

        for (int i = 0; i < 8; ++i) {
            h[i] += 4 * SizeWords;
        }

        for (int i = -(SizeWords & 3); i < 0; ++i) {
            for (int j = 0; j < 8; ++j) {
                h[j] += key[SizeWords + i * 8 + j] * PRIME32_3;
                h[j] = rol32<17>(h[j]) * PRIME32_4;
            }
        }

        for (int i = 0; i < 8; ++i) {
            res[i] = fmix32(h[i]);
        }
    }

#endif // __AVX2__

    // Compute a 32 bit hash value for the key.
    static uint32_t scalar(uint32_t* key, uint32_t seed) {
        uint32_t h = seed + PRIME32_5;

        if (SizeWords >= 4) {
            uint32_t v1 = seed + PRIME32_1 + PRIME32_2;
            uint32_t v2 = seed + PRIME32_2;
            uint32_t v3 = seed + 0;
            uint32_t v4 = seed - PRIME32_1;
            for (int i = 0; i < (SizeWords & ~3); i += 4) {
                v1 = round(v1, key[i]);
                v2 = round(v2, key[i + 1]);
                v3 = round(v3, key[i + 2]);
                v4 = round(v4, key[i + 3]);
            }

            h = rol32<1>(v1) + rol32<7>(v2) + rol32<12>(v3) + rol32<18>(v4);
        }

        h += 4 * SizeWords;

        for (int i = -(SizeWords & 3); i < 0; ++i) {
            h += key[SizeWords + i] * PRIME32_3;
            h = rol32<17>(h) * PRIME32_4;
        }

        return fmix32(h);
    }

private:
#if __AVX2__
    static __m256i mm256_round(__m256i seed, __m256i input) {
        seed = _mm256_add_epi32(seed,
                                _mm256_mullo_epi32(input,
                                                   _mm256_set1_epi32(PRIME32_2)));
        seed = mm256_rol32<13>(seed);
        seed = _mm256_mullo_epi32(seed,
                                  _mm256_set1_epi32(PRIME32_1));
        return seed;
    }

    static __m256i mm256_fmix32(__m256i h) {
        h = _mm256_xor_si256(h, _mm256_srli_epi32(h, 15));
        h = _mm256_mullo_epi32(h, _mm256_set1_epi32(PRIME32_2));
        h = _mm256_xor_si256(h, _mm256_srli_epi32(h, 13));
        h = _mm256_mullo_epi32(h, _mm256_set1_epi32(PRIME32_3));
        h = _mm256_xor_si256(h, _mm256_srli_epi32(h, 16));

        return h;
    }

    template<int r>
    static __m256i mm256_rol32(__m256i x) {
        return _mm256_or_si256(_mm256_slli_epi32(x, r),
                               _mm256_srli_epi32(x, 32 - r));
    }
#endif // __AVX2__

    static uint32_t round(uint32_t seed, uint32_t input) {
        seed += input * PRIME32_2;
        seed = rol32<13>(seed);
        seed *= PRIME32_1;
        return seed;
    }

    static uint32_t fmix32(uint32_t h) {
        h ^= h >> 15;
        h *= PRIME32_2;
        h ^= h >> 13;
        h *= PRIME32_3;
        h ^= h >> 16;

        return h;
    }

    template<int r>
    static uint32_t rol32(uint32_t x) {
        return (x << r) | (x >> (32 - r));
    }

    static const uint32_t PRIME32_1 = 2654435761U;
    static const uint32_t PRIME32_2 = 2246822519U;
    static const uint32_t PRIME32_3 = 3266489917U;
    static const uint32_t PRIME32_4 =  668265263U;
    static const uint32_t PRIME32_5 =  374761393U;
};

#endif // PARALLEL_XXHASH_H