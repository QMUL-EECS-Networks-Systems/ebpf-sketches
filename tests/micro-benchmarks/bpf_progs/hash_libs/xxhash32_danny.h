// adapted into C from C++ at https://github.com/stbrumme/xxhash/blob/master/xxhash32.h


// //////////////////////////////////////////////////////////
// xxhash32.h
// Copyright (c) 2016 Stephan Brumme. All rights reserved.
// see http://create.stephan-brumme.com/disclaimer.html
//

#pragma once
//#include <stdint.h> // for uint32_t and uint64_t

#define Prime1  2654435761U
#define Prime2  2246822519U
#define Prime3  3266489917U
#define Prime4  668265263U
#define Prime5  374761393U
/// temporarily store up to 15 bytes between multiple add() calls
static const uint32_t MaxBufferSize =16;

/// rotate bits, should compile to a single CPU instruction (ROL)
static __attribute__((always_inline)) inline  uint32_t rotateLeft(const uint32_t x, const unsigned char bits)
{
    return (x << bits) | (x >> (32 - bits));
}
/// process a block of 4x4 bytes, this is the main part of the XXHash32 algorithm
static __attribute__((always_inline)) inline void process(const void* data, uint32_t *state0, uint32_t *state1, uint32_t *state2, uint32_t *state3)
{
    const uint32_t* block = (const uint32_t*) data;
    *state0 = rotateLeft(*state0 + block[0] * Prime2, 13) * Prime1;
    *state1 = rotateLeft(*state1 + block[1] * Prime2, 13) * Prime1;
    *state2 = rotateLeft(*state2 + block[2] * Prime2, 13) * Prime1;
    *state3 = rotateLeft(*state3 + block[3] * Prime2, 13) * Prime1;
}

static uint32_t xxhash32_anylength(const void* input, const uint32_t totalLength, const uint32_t seed){
    // internal state and temporary buffer
    uint32_t      state[4]; // state[2] == seed if totalLength < MaxBufferSize
    unsigned char buffer[MaxBufferSize];
    unsigned int  bufferSize;
    
    //constructor init
    bufferSize  = 0;
    state[0] = seed + Prime1 + Prime2;
    state[1] = seed + Prime2;
    state[2] = seed;
    state[3] = seed - Prime1;
    
    uint32_t length=totalLength;
    //hasher.add(...) call
    {
        // no data ?
        if (!input || length == 0)
          return 0;

        
        // byte-wise access
        const unsigned char* data = (const unsigned char*)input;

        // unprocessed old data plus new data still fit in temporary buffer ?
        if (bufferSize + length < MaxBufferSize)
        {
          // just add new data
          while (length-- > 0)
            buffer[bufferSize++] = *data++;
          goto DONE_ADD;
        }

        // point beyond last byte
        const unsigned char* stop      = data + length;
        const unsigned char* stopBlock = stop - MaxBufferSize;

        // some data left from previous update ?
        if (bufferSize > 0)
        {
          // make sure temporary buffer is full (16 bytes)
          while (bufferSize < MaxBufferSize)
            buffer[bufferSize++] = *data++;

          // process these 16 bytes (4x4)
          process(buffer, &state[0], &state[1], &state[2], &state[3]);
        }

        // copying state to local variables helps optimizer A LOT
        uint32_t s0 = state[0], s1 = state[1], s2 = state[2], s3 = state[3];
        // 16 bytes at once
        while (data <= stopBlock)
        {
          // local variables s0..s3 instead of state[0]..state[3] are much faster
          process(data, &s0, &s1, &s2, &s3);
          data += 16;
        }
        // copy back
        state[0] = s0; state[1] = s1; state[2] = s2; state[3] = s3;

        // copy remainder to temporary buffer
        bufferSize = stop - data;
        for (unsigned int i = 0; i < bufferSize; i++)
          buffer[i] = data[i];

        // done
        goto DONE_ADD;
    }

DONE_ADD:
    //hasher.hash() call
    {
        uint32_t result = (uint32_t)totalLength;

        // fold 128 bit state into one single 32 bit value
        if (totalLength >= MaxBufferSize)
          result += rotateLeft(state[0],  1) +
                    rotateLeft(state[1],  7) +
                    rotateLeft(state[2], 12) +
                    rotateLeft(state[3], 18);
        else
          // internal state wasn't set in add(), therefore original seed is still stored in state2
          result += state[2] + Prime5;

        // process remaining bytes in temporary buffer
        const unsigned char* data = buffer;
        // point beyond last byte
        const unsigned char* stop = data + bufferSize;

        // at least 4 bytes left ? => eat 4 bytes per step
        for (; data + 4 <= stop; data += 4)
          result = rotateLeft(result + *(uint32_t*)data * Prime3, 17) * Prime4;

        // take care of remaining 0..3 bytes, eat 1 byte per step
        while (data != stop)
          result = rotateLeft(result +        (*data++) * Prime5, 11) * Prime1;

        // mix bits
        result ^= result >> 15;
        result *= Prime2;
        result ^= result >> 13;
        result *= Prime3;
        result ^= result >> 16;
        return result;
    }
}


static __always_inline uint32_t xxhash32_short(const void* input, const uint32_t totalLength, const uint32_t seed){
    // internal state and temporary buffer
    //uint32_t   state[4]; // state[2] == seed if totalLength < MaxBufferSize
    //only need 4, the 3 is for cache line alignment...
    unsigned char buffer[MaxBufferSize];
    //unsigned char __unused[MaxBufferSize];//need this so gcc does optimization correctly...
    
    //constructor init
    //state[0] = seed + Prime1 + Prime2;
    //state[1] = seed + Prime2;
    //state[2] = seed;
    //state[3] = seed - Prime1;

    uint32_t result = (uint32_t)totalLength;
    result += seed + Prime5;
    
    const unsigned char* data = input;
    // point beyond last byte
    const unsigned char* stop = data + totalLength;
    
    for (; data + 4 <= stop; data += 4)
      result = rotateLeft(result + *(uint32_t*)data * Prime3, 17) * Prime4;

    // take care of remaining 0..3 bytes, eat 1 byte per step
    while (data != stop)
      result = rotateLeft(result +        (*data++) * Prime5, 11) * Prime1;

    // mix bits
    result ^= result >> 15;
    result *= Prime2;
    result ^= result >> 13;
    result *= Prime3;
    result ^= result >> 16;
    return result;
}


static inline uint32_t xxhash32(const void* input, const uint32_t totalLength, const uint32_t seed){
    if(totalLength>=1 && totalLength<MaxBufferSize)
        return xxhash32_short(input,totalLength,seed);
    return  xxhash32_anylength(input,totalLength,seed);
}
//static __attribute__((always_inline)) inline uint32_t fn()
