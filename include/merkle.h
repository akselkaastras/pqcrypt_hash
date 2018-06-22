// Copyright (C) 2018 Aksel Kaastrup Rasmussen

#include "hash.h"
#include <math.h>

#define MERKLE_SEC_LVL	256
#define MERKLE_N 		256
#define MERKLE_KEY_LEN 265

#define LEN_BYTES(bits) ((bits)/8)

/**
 * Compute Merkle keys 
 *
 * @param seed      random seed
 * @param s         the private signing key
 * @param v         the public verification key
 */
void merkle_keygen(unsigned char seed[LEN_BYTES(MERKLE_N)],unsigned char s[MERKLE_KEY_LEN*LEN_BYTES(MERKLE_SEC_LVL)],unsigned char v[MERKLE_KEY_LEN*LEN_BYTES(MERKLE_SEC_LVL)]);
/**
 * Sign the value under private key s
 *
 * @param s		 the private signing key
 * @param h		 buffer containing the message hash to be signed
 * @param sig
 */
void merkle_sign(const unsigned char s[MERKLE_KEY_LEN*LEN_BYTES(MERKLE_SEC_LVL)], unsigned char *h, unsigned char *sig);

/**
 * Verify a signature on hash h
 *
 * @param v         The public verification key
 * @param H 		buffer containing the message hash to be signed
 * @param sig       the signature
 */
int merkle_verify(unsigned char *v, unsigned char *h, unsigned char *sig);
