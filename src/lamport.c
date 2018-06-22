// Copyright (C) 2018 Aksel Kaastrup Rasmussen

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <lamport.h>
#include <time.h>
#include "util.h"

// Function converts an integer to a binary vector of length count.
void int_to_bin_digit(unsigned int in, int count, int* out)
{
    unsigned int mask = 1U << (count-1);
    int i;
    for (i = 0; i < count; i++) {
        out[i] = (in & mask) ? 1 : 0;
        in <<= 1;
    }
}

// Function converts a hash of length LEN_BYTES(LAMPORT N) and outputs the binary representation
void hash_to_bin_digit(unsigned char h[LEN_BYTES(LAMPORT_N)],int out[256])
{
	int buf[8];
	for (int i = 0; i < LEN_BYTES(LAMPORT_N); ++i)
	{
		int_to_bin_digit(h[i],8,buf);
		memcpy(out+8*i,buf,8*sizeof(int));
	}
}

// Lamport key generation
void lamport_keygen(unsigned char seed[LEN_BYTES(LAMPORT_N)],unsigned char s1[LAMPORT_N*LEN_BYTES(LAMPORT_SEC_LVL)],unsigned char s2[LAMPORT_N*LEN_BYTES(LAMPORT_SEC_LVL)], unsigned char v1[LAMPORT_N*LEN_BYTES(LAMPORT_SEC_LVL)],unsigned char v2[LAMPORT_N*LEN_BYTES(LAMPORT_SEC_LVL)])
{
	int M = LEN_BYTES(LAMPORT_SEC_LVL);
	//unsigned char * buf1 = malloc(M*sizeof(char));
    //unsigned char * buf2 = malloc(M*sizeof(char));
    //unsigned char * hashbuf1 = malloc(M*sizeof(char));
    //unsigned char * hashbuf2 = malloc(M*sizeof(char));
    unsigned char buf1[M], buf2[M];
    unsigned char hashbuf1[M], hashbuf2[M];

    for (int i = 0; i < LAMPORT_N; ++i)
    {
    	fsgen(seed,seed,buf1);
    	fsgen(seed,seed,buf2);
    	memcpy(s1+i*M,buf1,M*sizeof(char));
    	memcpy(s2+i*M,buf2,M*sizeof(char));
    	hash32(buf1,M,hashbuf1);
    	hash32(buf2,M,hashbuf2);
    	memcpy(v1+i*M,hashbuf1,M*sizeof(char));
    	memcpy(v2+i*M,hashbuf2,M*sizeof(char));
    }
}

// Lamport signature generation
void lamport_sign(const unsigned char s1[LAMPORT_N*LEN_BYTES(LAMPORT_SEC_LVL)], const unsigned char s2[LAMPORT_N*LEN_BYTES(LAMPORT_SEC_LVL)], unsigned char *h, unsigned char *sig)
{
	int M = LEN_BYTES(LAMPORT_SEC_LVL);
	int bin_digit[LAMPORT_N];
	hash_to_bin_digit(h,bin_digit);
	
	for (int i = 0; i < LAMPORT_N; ++i)
	{
		if (bin_digit[i]==0)
		{
			memcpy(sig+i*M,s1+i*M,M*sizeof(char));
		}
		else
		{
			memcpy(sig+i*M,s2+i*M,M*sizeof(char));
		}
	}
}

// Lamport signature verification
int lamport_verify(unsigned char * v1, unsigned char * v2, unsigned char *h, unsigned char *sig)
{
	int M = LEN_BYTES(LAMPORT_SEC_LVL);
	int err_count = 0;
	int bin_digit[LAMPORT_N];
	unsigned char buf[M];
	unsigned char hashbuf[M];
	hash_to_bin_digit(h,bin_digit);	
	for (int i = 0; i < LAMPORT_N; ++i)
	{
		memcpy(buf,sig+i*M,M*sizeof(char));
		hash32(buf,M,hashbuf);
		if (bin_digit[i]==0)
		{
			if (memcmp(hashbuf,v1+i*M,M*sizeof(char)))
			{
				++err_count;
			}
		}
		else
		{
			if (memcmp(hashbuf,v2+i*M,M*sizeof(char)))
			{
				++err_count;
			}
		}
	}
	return err_count;//(err_count == 0 ? LAMPORT_OK : LAMPORT_ERROR) ;
}




int main(int argc, char const *argv[])
{
	unsigned char seed[32];
	// Execution variables only using hash size times bytes of security level.
    unsigned char s1[LEN_BYTES(LAMPORT_SEC_LVL)*256], s2[LEN_BYTES(LAMPORT_SEC_LVL)*256], v1[LEN_BYTES(LAMPORT_SEC_LVL)*256], v2[LEN_BYTES(LAMPORT_SEC_LVL)*256];
    unsigned char sig[LEN_BYTES(LAMPORT_SEC_LVL)*256], hash[32];
    // Message to be signed
    const unsigned char msg[43] = "--Hello, world!";

    int out[256];
    srand(time(NULL));

    // Generating random seed to be utilized lamport_keygen
	for (int j = 0; j < 32; ++j) {
        seed[j] = rand() ^ j; // semi-random seed
    }
    // Lamport key generation and output
    lamport_keygen(seed,s1,s2,v1,v2);

    Display("private sign key s1",s1,32);
    Display("private sign key s2",s2,32);
    Display("public sign key v1",v1,32);
    Display("public sign key v2",v2,32);

    //Hash digest
    hash32(msg,32,hash);

    // Signature generation
    lamport_sign(s1,s2,hash,sig);

    // Binary vector of hash digest
    hash_to_bin_digit(hash,out);
    printf("Message: %s\n",msg);
    printf("Hash in binary\n");
    for (int j = 0; j < 8; ++j)
    {
    	printf("%d ",out[j]);
    }
    printf(" ...\n");
    printf("\n");

    // Signature length
    printf("Signature bit-length: %lu\n",sizeof(sig)/sizeof(char));
    Display("signature",sig,32);

    //Signature verification
    int err = lamport_verify(v1,v2,hash,sig);

   	printf("Number of ERRORS: %d \nSTATUS: %s\n\n",err, err == 0 ? "SUCCESS" : "FAILURE");




    

    return 0;
}
