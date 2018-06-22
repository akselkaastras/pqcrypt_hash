// Copyright (C) 2018 Aksel Kaastrup Rasmussen

#include "hash.h"

#define LAMPORT_SEC_LVL	256 //Security level
#define LAMPORT_N 		256

#define LEN_BYTES(bits) ((bits)/8)

#define LAMPORT_SIG_SIZE 2*LAMPORT_SEC_LVL*LAMPORT_N

/**
 * Compute a Lamport signature and verification keys.
 *
 * @param seed       random seed.
 * @param s1         the first private signing key.
 * @param s2         the second private signing key.
 * @param v1         the first public verification key.
 * @param v2         the second public verification key.
 */
void lamport_keygen(unsigned char seed[LEN_BYTES(LAMPORT_N)],unsigned char s1[LAMPORT_N*LEN_BYTES(LAMPORT_SEC_LVL)],unsigned char s2[LAMPORT_N*LEN_BYTES(LAMPORT_SEC_LVL)], unsigned char v1[LAMPORT_N*LEN_BYTES(LAMPORT_SEC_LVL)],unsigned char v2[LAMPORT_N*LEN_BYTES(LAMPORT_SEC_LVL)]);
/**
 * Sign the value under private key s1 and s2.
 *
 * @param s1        the first private signing key.
 * @param s2        the second private signing key.
 * @param h		 	buffer containing the message hash to be signed.
 * @param sig
 */
void lamport_sign(const unsigned char v1[LAMPORT_N*LEN_BYTES(LAMPORT_SEC_LVL)], const unsigned char v2[LAMPORT_N*LEN_BYTES(LAMPORT_SEC_LVL)], unsigned char *h, unsigned char *sig);

/**
 * Verify a signature on hash h
 *
 * @param v1        the first public verification key.
 * @param v2        the second public verification key.
 * @param h		 	buffer containing the message hash to be signed.
 * @param sig       the signature
 */
int lamport_verify(unsigned char *v1, unsigned char *v2, unsigned char *h, unsigned char *sig);

