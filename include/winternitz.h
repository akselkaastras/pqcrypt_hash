// Copyright (C) 2018 Aksel Kaastrup Rasmussen

#include "hash.h"
#include <math.h>


#define WINTERNITZ_SEC_LVL	128
#define WINTERNITZ_N 		256		// only 256 for this implementation
#define WINTERNITZ_W 2 				// only allows 2 for this implementation
#define WINTERNITZ_l1 256
#define WINTERNITZ_l2 9

#define WINTERNITZ_CHECKSUM_SIZE (WINTERNITZ_l2)
#define WINTERNITZ_l (WINTERNITZ_l1 + WINTERNITZ_CHECKSUM_SIZE)
#define WINTERNITZ_L (WINTERNITZ_l1 + WINTERNITZ_CHECKSUM_SIZE)

#define LEN_BYTES(bits) ((bits+7)/8)

#define WINTERNITZ_SIG_SIZE WINTERNITZ_L*LEN_BYTES(WINTERNITZ_SEC_LVL)

/**
 * Compute a Winternitz keys
 *
 * @param seed      random seed
 * @param s         the private signing key
 * @param v         the public verification key 
 */
void winternitz_keygen(unsigned char seed[LEN_BYTES(WINTERNITZ_N)], unsigned char s[WINTERNITZ_L*LEN_BYTES(WINTERNITZ_SEC_LVL)], unsigned char v[WINTERNITZ_L*LEN_BYTES(WINTERNITZ_SEC_LVL)]);

// /**
//  * Sign the value under private key s
//  *
//  * @param s		 the private signing key
//  * @param h		 buffer containing the message hash to be signed
//  * @param sig
//  */
void winternitz_sign(unsigned char s[WINTERNITZ_L*LEN_BYTES(WINTERNITZ_SEC_LVL)], unsigned char *h, unsigned char *sig);

// /**
//  * Verify a signature on hash h
//  *
//  * @param v         the public verification key
//  * @param h 		   buffer containing the message hash to be signed
//  * @param sig       the signature
//  */
int winternitz_verify(unsigned char * v, unsigned char *h, unsigned char *sig);
