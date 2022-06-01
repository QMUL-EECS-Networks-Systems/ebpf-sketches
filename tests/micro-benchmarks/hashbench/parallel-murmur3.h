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
// Three AVX2 implementations of the Murmur3 hash functions.
//
// - parallel: Computing the hash values of 8 keys in parallel.
// - parallel_multiseed: Computing N hash values for each of 8 keys
//   in parallel. Each of the N hash values for a key will be computed
//   using a different key.
// - scalar: Computing the hash value of a single key.
//
// You probably don't want to use any of these, look in
// parallel-xxhash.h instead. (It is missing parallel_multiseed, since
// my use case for that disappeared. But it'd be trivial to implement).

#ifndef PARALLEL_MURMUR3_H
#define PARALLEL_MURMUR3_H

#include <cstdint>
#include <cstdio>
#include <immintrin.h>

template<int SizeWords>
struct murmur3 {

    // Compute a hash value for 8 keys of SizeWords*4 bytes each.
    static void parallel(const uint32_t* keys, uint32_t seed,
                         uint32_t res[8]) {
        const __m256i c1 = _mm256_set1_epi32(0xcc9e2d51);
        const __m256i c2 = _mm256_set1_epi32(0x1b873593);
        __m256i h = _mm256_set1_epi32(seed);

        for (int i = 0; i < SizeWords; ++i) {
            __m256i k = _mm256_loadu_si256((__m256i*) (keys + i * 8));
            k = _mm256_mullo_epi32(k, c1);
            k = mm256_rol32<15>(k);
            k = _mm256_mullo_epi32(k, c2);

            h = _mm256_xor_si256(h, k);
            h = mm256_rol32<13>(h);
            h = _mm256_add_epi32(_mm256_mullo_epi32(h,
                                                    _mm256_set1_epi32(5)),
                                 _mm256_set1_epi32(0xe6546b64));
        }

        // Mixing in the length here is pretty silly, since it's always
        // constant. But there's probably some value in producing bitwise
        // identical results to the original murmur3 code.
        h = _mm256_xor_si256(h, _mm256_set1_epi32(SizeWords * 4));

        _mm256_storeu_si256((__m256i*) res, mm256_fmix32(h));
    }

    // For each of 8 keys, compute N hash values each with a different
    // starting seed value. The hash values will be written to "res".
    template<int N>
    static void parallel_multiseed(const uint32_t* keys, uint32_t seeds[N],
                                   __m256i res[N]) {
        const __m256i c1 = _mm256_set1_epi32(0xcc9e2d51);
        const __m256i c2 = _mm256_set1_epi32(0x1b873593);
        __m256i h[N];
        for (int j = 0; j < N; ++j) {
            h[j] = _mm256_set1_epi32(seeds[j]);
        }

        for (int i = 0; i < SizeWords; ++i) {
            __m256i k = _mm256_loadu_si256((__m256i*) (keys + i * 8));
            k = _mm256_mullo_epi32(k, c1);
            k = mm256_rol32<15>(k);
            k = _mm256_mullo_epi32(k, c2);

            for (int j = 0; j < N; ++j) {
                h[j] = _mm256_xor_si256(h[j], k);
                h[j] = mm256_rol32<13>(h[j]);
                h[j] = _mm256_add_epi32(_mm256_mullo_epi32(h[j],
                                                           _mm256_set1_epi32(5)),
                                        _mm256_set1_epi32(0xe6546b64));
            }
        }

        for (int j = 0; j < N; ++j) {
            h[j] = _mm256_xor_si256(h[j], _mm256_set1_epi32(SizeWords * 4));
            res[j] = mm256_fmix32(h[j]);
        }
    }

    // Compute a hash value for the key.
    static uint32_t scalar(uint32_t* key, uint32_t seed) {
        const uint32_t c1s = 0xcc9e2d51;
        const uint32_t c2s = 0x1b873593;
        uint32_t h = seed;

        for (int i = 0; i < SizeWords; ++i) {
            uint32_t k = key[i];
            k *= c1s;
            k = rol32<15>(k);
            k *= c2s;

            h ^= k;
            h = rol32<13>(h);
            h = h*5 + 0xe6546b64;
        }

        h ^= SizeWords * 4;

        return fmix32(h);
    }

private:
    static __m256i mm256_fmix32(__m256i h) {
        h = _mm256_xor_si256(h, _mm256_srli_epi32(h, 16));
        h = _mm256_mullo_epi32(h, _mm256_set1_epi32(0x85ebca6b));
        h = _mm256_xor_si256(h, _mm256_srli_epi32(h, 13));
        h = _mm256_mullo_epi32(h, _mm256_set1_epi32(0xc2b2ae35));
        h = _mm256_xor_si256(h, _mm256_srli_epi32(h, 16));

        return h;
    }

    template<int r>
    static __m256i mm256_rol32(__m256i x) {
        return _mm256_or_si256(_mm256_slli_epi32(x, r),
                               _mm256_srli_epi32(x, 32 - r));
    }

    static uint32_t fmix32(uint32_t h) {
        h ^= h >> 16;
        h *= 0x85ebca6b;
        h ^= h >> 13;
        h *= 0xc2b2ae35;
        h ^= h >> 16;

        return h;
    }

    template<int r>
    static uint32_t rol32(uint32_t x) {
        return (x << r) | (x >> (32 - r));
    }
};

#endif // PARALLEL_MURMUR3_H