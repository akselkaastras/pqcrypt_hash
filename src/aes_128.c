/*
 * Copyright (C) 2015-2016 Geovandro Pereira, Cassius Puodzius
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

#include "aes_128.h"
#include "ti_aes.h"
#include <string.h>

#ifdef DEBUG
#include <assert.h>
#endif

unsigned char IV_MMO16[176] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x62, 0x63, 0x63, 0x63, 0x62, 0x63, 0x63, 0x63, 0x62, 0x63, 0x63, 0x63, 0x62, 0x63, 0x63, 0x63,
    0x9B, 0x98, 0x98, 0xC9, 0xF9, 0xFB, 0xFB, 0xAA, 0x9B, 0x98, 0x98, 0xC9, 0xF9, 0xFB, 0xFB, 0xAA,
    0x90, 0x97, 0x34, 0x50, 0x69, 0x6C, 0xCF, 0xFA, 0xF2, 0xF4, 0x57, 0x33, 0x0B, 0x0F, 0xAC, 0x99,
    0xEE, 0x06, 0xDA, 0x7B, 0x87, 0x6A, 0x15, 0x81, 0x75, 0x9E, 0x42, 0xB2, 0x7E, 0x91, 0xEE, 0x2B,
    0x7F, 0x2E, 0x2B, 0x88, 0xF8, 0x44, 0x3E, 0x09, 0x8D, 0xDA, 0x7C, 0xBB, 0xF3, 0x4B, 0x92, 0x90,
    0xEC, 0x61, 0x4B, 0x85, 0x14, 0x25, 0x75, 0x8C, 0x99, 0xFF, 0x09, 0x37, 0x6A, 0xB4, 0x9B, 0xA7,
    0x21, 0x75, 0x17, 0x87, 0x35, 0x50, 0x62, 0x0B, 0xAC, 0xAF, 0x6B, 0x3C, 0xC6, 0x1B, 0xF0, 0x9B,
    0x0E, 0xF9, 0x03, 0x33, 0x3B, 0xA9, 0x61, 0x38, 0x97, 0x06, 0x0A, 0x04, 0x51, 0x1D, 0xFA, 0x9F,
    0xB1, 0xD4, 0xD8, 0xE2, 0x8A, 0x7D, 0xB9, 0xDA, 0x1D, 0x7B, 0xB3, 0xDE, 0x4C, 0x66, 0x49, 0x41,
    0xB4, 0xEF, 0x5B, 0xCB, 0x3E, 0x92, 0xE2, 0x11, 0x23, 0xE9, 0x51, 0xCF, 0x6F, 0x8F, 0x18, 0x8E};
//*/

/**
 * key is already expanded
 */
void aes128_encrypt_keyexpanded(unsigned char ciphertext[AES_128_BLOCK_SIZE], const unsigned char plaintext[AES_128_BLOCK_SIZE]) {//, const unsigned char expandedKey[11*AES_128_KEY_SIZE]) {

    memcpy(ciphertext, plaintext, AES_128_BLOCK_SIZE);

    aes_encr(ciphertext, IV_MMO16); // ti_aes.c
    //aes_encrypt(ciphertext, IV_MMO16); // TI_aes_128_encr_only.c
}

/**
 * Encrypt a single AES block under a 128-bit key.
 */
void aes_128_encrypt(unsigned char ciphertext[AES_128_BLOCK_SIZE], const unsigned char plaintext[AES_128_BLOCK_SIZE], const unsigned char key[AES_128_KEY_SIZE]) {

    unsigned char local_key[AES_128_KEY_SIZE];
    memcpy(local_key, key, AES_128_KEY_SIZE);
    memcpy(ciphertext, plaintext, AES_128_BLOCK_SIZE); // c saves the plaintext
#ifdef AES_ENC_DEC
    aes_enc_dec(ciphertext, local_key, 0); // TI_aes_128.c
#else
    //aes_encrypt(ciphertext, local_key); // TI_aes_128_encr_only.c
    ti_aes_encrypt(ciphertext, local_key); // (ti_aes.c) ciphertext saves the plaintext
#endif //AES_ENC_DEC
}

#ifdef AES_ENC_DEC

/**
 * Decrypt a single AES block under a 128-bit key.
 */
void aes_128_decrypt(unsigned char plaintext[AES_128_BLOCK_SIZE], const unsigned char ciphertext[AES_128_BLOCK_SIZE], const unsigned char key[AES_128_KEY_SIZE]) {
    unsigned char local_key[AES_128_KEY_SIZE];
    memcpy(local_key, key, AES_128_KEY_SIZE);
    memcpy(plaintext, ciphertext, AES_128_BLOCK_SIZE); // plaintext saves the ciphertext
    aes_enc_dec(plaintext, local_key, 1);
}

#endif //AES_ENC_DEC

#if AES_SELFTEST

#include <stdio.h>
#include "util.h"

#define BUFFER_SIZE 300

int main() {
    
    unsigned int i;

    // AES 128
    unsigned char plaintext_block[AES_128_BLOCK_SIZE] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
    unsigned char ciphertext_block[AES_128_BLOCK_SIZE];
    unsigned char key[AES_128_BLOCK_SIZE] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};

    aes_128_encrypt(ciphertext_block, plaintext_block, key);

    printf("ciphertext block:\n");
    for (i = 0; i < AES_128_BLOCK_SIZE; i++)
        printf("%02X ", ciphertext_block[i]);
    printf("\n");

    aes_128_decrypt(plaintext_block, ciphertext_block, key);

    printf("plaintext block:\n");
    for (i = 0; i < AES_128_BLOCK_SIZE; i++)
        printf("%02X ", plaintext_block[i]);
    printf("\n");

    return 0;
}

#undef BUFFER_SIZE
#endif
