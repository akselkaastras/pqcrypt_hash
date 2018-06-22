/*
 * Copyright (C) 2015-2017 Geovandro Pereira, Paulo Barreto
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "hash.h"
#include <string.h>

#ifdef DEBUG
#include <assert.h>
#endif

/**
 * Recommendation is that rp is unpredictable and r is at least 128 bits to provide minimal security
 *  
 * @param r         The randomization entropy
 * @param rlen
 * @param rp        The expanded randomized value
 */
void _rmx_salt(const unsigned char *r, const unsigned int rlen, unsigned char *rp);

/**
 * The randomization of the plain message as suggested in https://tools.ietf.org/html/draft-irtf-cfrg-rhash-01
 * 
 * @param rp                 The salt rp is xored with each data block and that will be concatenated with the randomized data later
 * @param r
 * @param rlen
 * @param d                 The plain data to be signed
 * @param dlen              The amount of bytes in data
 * @param randomizeddata     The sequence drp = rp || d1 XOR rp || ... dt XOR rp where di's are data blocks of length HASH_BLOCKSIZE and dt is possibly padded with zeros if needed
 */
void _rmx(unsigned char *rp, const unsigned char *r, const unsigned char rlen, const char *data, const unsigned long datalen, unsigned char *randomizeddata);

void _rmx_salt(const unsigned char *r, const unsigned int rlen, unsigned char *rp) {
    // Salt expansion to coincide the hash block size: rp <- r | r | ... | r | r, where last r may be truncated
    unsigned char rplen;  
    if (rlen > HASH_BLOCKSIZE) {
        memcpy(rp,r,HASH_BLOCKSIZE);
        return;
    }
    memcpy(rp,r,rlen);  
    rplen = rlen;
    while (rplen+rlen < HASH_BLOCKSIZE) {
        memcpy(&rp[rplen],r,rlen);
        rplen = rplen+rlen;
    }
    if (rplen < HASH_BLOCKSIZE) {
        memcpy(&rp[rplen],r,rplen+rlen - HASH_BLOCKSIZE);
    }
}

void _rmx(unsigned char *rp, const unsigned char *r, const unsigned char rlen, const char *d, const unsigned long dlen, unsigned char *randomizeddata) {
    unsigned long len;
 
    _rmx_salt(r, rlen, rp);
    
    // Prepare the randomized data: drp <- d1 xor rp || d2 xor rp || ... || dt xor rp
    len = 0;
    while (len < (dlen+HASH_BLOCKSIZE-1)/HASH_BLOCKSIZE) {
        for (int i = 0; i < HASH_BLOCKSIZE / sizeof(int); i++) { // Compute di xor rp by integer steps
            int temp = *((int*)&d[len+i*sizeof(int)]) ^ *((int*)&rp[i*sizeof(int)]);
            memcpy(&randomizeddata[len+i*sizeof(int)], &temp, sizeof(int));            
        }
        len = len + HASH_BLOCKSIZE;
    }

}

void etcr_hash(const unsigned char *r, const unsigned char rlen, const char *data, const unsigned short datalen, unsigned char *h) {
    unsigned char rp[HASH_BLOCKSIZE];
    unsigned char randomizeddata[HASH_BLOCKSIZE*((datalen+HASH_BLOCKSIZE-1)/HASH_BLOCKSIZE)];
    
    memcpy(&randomizeddata,data,datalen);
    _rmx(rp, r, rlen, data, datalen, randomizeddata);
    hash32((const unsigned char *)randomizeddata, HASH_BLOCKSIZE*((datalen+HASH_BLOCKSIZE-1)/HASH_BLOCKSIZE), h);
    
}

void MMO_init(mmo_t *mmo) {
    mmo->t = 16; // one AES block
    mmo->n = 0;

    memset(mmo->H, 0, 16);
}

void MMO_update(mmo_t *mmo, const unsigned char *M, unsigned int m) {
    unsigned char *ZZ = &mmo->M[16 - mmo->t];
    mmo->n += m;
    for (;;) {
        switch ((m >= mmo->t) ? mmo->t : m) {
            case 16: ZZ[15] = M[15]; // FALLTHROUGH
            case 15: ZZ[14] = M[14]; // FALLTHROUGH
            case 14: ZZ[13] = M[13]; // FALLTHROUGH
            case 13: ZZ[12] = M[12]; // FALLTHROUGH
            case 12: ZZ[11] = M[11]; // FALLTHROUGH
            case 11: ZZ[10] = M[10]; // FALLTHROUGH
            case 10: ZZ[ 9] = M[ 9]; // FALLTHROUGH
            case 9: ZZ[ 8] = M[ 8]; // FALLTHROUGH
            case 8: ZZ[ 7] = M[ 7]; // FALLTHROUGH
            case 7: ZZ[ 6] = M[ 6]; // FALLTHROUGH
            case 6: ZZ[ 5] = M[ 5]; // FALLTHROUGH
            case 5: ZZ[ 4] = M[ 4]; // FALLTHROUGH
            case 4: ZZ[ 3] = M[ 3]; // FALLTHROUGH
            case 3: ZZ[ 2] = M[ 2]; // FALLTHROUGH
            case 2: ZZ[ 1] = M[ 1]; // FALLTHROUGH
            case 1: ZZ[ 0] = M[ 0]; // FALLTHROUGH
            case 0: break;
        }
        if (m < mmo->t) {
            break; // postpone incomplete message block
        }

        aes_128_encrypt(mmo->H, mmo->M, mmo->H);

        unsigned char i;
        for (i = 0; i < (16 / sizeof (int)); i++) {
            ((int*) mmo->H)[i] ^= ((int*) mmo->M)[i];
        }

        // proceed to the next block:
        m -= mmo->t;
        M += mmo->t;
        mmo->t = 16;
        ZZ = mmo->M;
#ifdef DEBUG
        //assert(m > 0);
#endif
    }
    mmo->t -= m;
#ifdef DEBUG
    assert(mmo->t > 0);
#endif
    //assert(m == 0 || mmo->t < 16); // m == 0 here only occurs if m == 0 from the very beginning
}

void MMO_final(mmo_t *mmo, unsigned char tag[16]) {
    unsigned int i;
    unsigned char *ZZ = &mmo->M[16 - mmo->t];
#ifdef DEBUG
    assert(mmo->t > 0);
#endif
    // compute padding:
    *ZZ++ = 0x80; // padding toggle
    mmo->t--;

    if (mmo->t < 8) { // no space for 64-bit length field
        while (mmo->t > 0) {
            *ZZ++ = 0x00; // fill remainder of block with zero padding
            mmo->t--;
        }
        aes_128_encrypt(mmo->H, mmo->M, mmo->H);

        for (i = 0; i < (16 / sizeof (int)); i++) {
            ((int*) mmo->H)[i] ^= ((int*) mmo->M)[i];
        }

        mmo->t = 16; // start new block
        ZZ = mmo->M;
    }
#ifdef DEBUG
    assert(mmo->t >= 8);
#endif
    while (mmo->t > 8) {
        *ZZ++ = 0x00; // fill low half of block with zero padding
        mmo->t--;
    }
#ifdef DEBUG
    assert(mmo->t == 8);
#endif
    mmo->n <<= 3; // convert unsigned char length to bit length
    ZZ += 8;
    for (i = 0; i < 8; i++) {
        *--ZZ = mmo->n & 0xff;
        mmo->n >>= 8; // this is overkill if mmo->n is too short, but it is correct and general
    }

    aes_128_encrypt(mmo->H, mmo->M, mmo->H);

    for (i = 0; i < (16 / sizeof (int)); i++) {
        ((int*) mmo->H)[i] ^= ((int*) mmo->M)[i];
    }

    memcpy(tag, mmo->H, 16);

    mmo->t = 16; // reset
    mmo->n = 0;
}

void MMO_hash16(mmo_t *mmo, const unsigned char M[16], unsigned char tag[16]) {

    unsigned char i;

    // IV=0 already initialized as suggested in "Hash-based Signatures on Smart Cards", Busold 2012
    aes128_encrypt_keyexpanded(mmo->H, M);

    for (i = 0; i < (16 / sizeof (int)); i++) {
        ((int*) mmo->H)[i] ^= ((int*) M)[i];
    }

    memcpy(tag, mmo->H, 16);
}

void MMO_hash32(mmo_t *mmo, const unsigned char M1[16], const unsigned char M2[16], unsigned char tag[16]) {

    memset(mmo->H, 0, 16);
    memset(&mmo->H[0], 1, 1); // A fixed and different IV from MMO_hash16

    aes_128_encrypt(mmo->H, M1, mmo->H);

    unsigned char i;
    for (i = 0; i < (16 / sizeof (int)); i++) {
        ((int*) mmo->H)[i] ^= ((int*) M1)[i];
    }

    aes_128_encrypt(mmo->H, M2, mmo->H);

    for (i = 0; i < (16 / sizeof (int)); i++) {
        ((int*) mmo->H)[i] ^= ((int*) M2)[i];
    }

    memcpy(tag, mmo->H, 16);
}

void hash32(const unsigned char *in, unsigned int inlen, unsigned char *out) {
    sph_sha256_context ctx;
    
    sph_sha256_init(&ctx);
    sph_sha256(&ctx, in, inlen);
    sph_sha256_close(&ctx, out);
    
}

void hmac(const unsigned char *key, unsigned int keylen, const unsigned char *message, unsigned int msglen, unsigned char *output) {
    sph_sha256_context ctx;
    unsigned char o_key_pad[HASH_BLOCKSIZE], i_key_pad[HASH_BLOCKSIZE], temp[HASH_BLOCKSIZE];

    memset(temp, 0, HASH_BLOCKSIZE);
    
    if (keylen > HASH_BLOCKSIZE) {
        sph_sha256_init(&ctx);
        sph_sha256(&ctx, key, keylen);
        sph_sha256_close(&ctx, temp); // keys longer than blocksize are shortened
    }
    else if (keylen < HASH_BLOCKSIZE) {
        // keys shorter than blocksize are zero-padded
        memcpy(temp, key, keylen);
    } else {
        memcpy(temp, key, HASH_BLOCKSIZE);
    }
        
    memcpy(o_key_pad, temp, HASH_BLOCKSIZE);
    memcpy(i_key_pad, temp, HASH_BLOCKSIZE);
    o_key_pad[0] = ((unsigned int)(0x5c * HASH_BLOCKSIZE)) ^ temp[0];
    i_key_pad[0] = ((unsigned int)(0x36 * HASH_BLOCKSIZE)) ^ temp[0];

    sph_sha256_init(&ctx);
    sph_sha256(&ctx, i_key_pad, HASH_BLOCKSIZE);
    sph_sha256(&ctx, message, msglen);
    sph_sha256_close(&ctx, temp);
    sph_sha256_init(&ctx);
    sph_sha256(&ctx, o_key_pad, HASH_BLOCKSIZE);
    sph_sha256(&ctx, temp, HASH_OUTPUTSIZE);
    sph_sha256_close(&ctx, output);
    
}

void prg(const unsigned char seed[HASH_OUTPUTSIZE], uint64_t input, unsigned char output[HASH_OUTPUTSIZE]) {
    hmac(seed, HASH_OUTPUTSIZE, (unsigned char *)&input, 8, output);
}

void prg32(const unsigned char key[HASH_OUTPUTSIZE], const unsigned char input[HASH_OUTPUTSIZE], unsigned char output[HASH_OUTPUTSIZE]) {
    hmac(key, HASH_OUTPUTSIZE, input, HASH_OUTPUTSIZE, output);
}

void fsgen(const unsigned char seed[HASH_OUTPUTSIZE], unsigned char nextseed[HASH_OUTPUTSIZE], unsigned char rand[HASH_OUTPUTSIZE]) {
    prg(seed, 1, rand);
    prg(seed, 0, nextseed);
    
}
