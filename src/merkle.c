// Copyright (C) 2018 Aksel Kaastrup Rasmussen

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <merkle.h>
#include <time.h>
#include "util.h"


void int_to_bin_digit(unsigned int in, int count, int out[count])
{
    unsigned int mask = 1U << (count-1);
    int i;
    for (i = 0; i < count; i++) {
        out[i] = (in & mask) ? 1 : 0;
        in <<= 1;
    }

    return;
}

void hash_to_bin_digit(unsigned char h[LEN_BYTES(MERKLE_N)],int out[256])
{
	int buf[8];
	for (int i = 0; i < LEN_BYTES(MERKLE_N); ++i)
	{
		int_to_bin_digit(h[i],8,buf);
		memcpy(out+8*i,buf,8*sizeof(int));
	}

	return;
}

int num_zero(int * bin_array, int n)
{
	int zero_count = 0;
	for (int i = 0; i < n; ++i)
	{
		if (bin_array[i]==0)
		{
			zero_count=zero_count+1;
		}
	}
	return zero_count;
}

// Returns Merkle OTS keys upon receiving seed.
void merkle_keygen(unsigned char seed[LEN_BYTES(MERKLE_N)],unsigned char s[MERKLE_KEY_LEN*LEN_BYTES(MERKLE_SEC_LVL)],unsigned char v[MERKLE_KEY_LEN*LEN_BYTES(MERKLE_SEC_LVL)])
{
	int M = LEN_BYTES(MERKLE_SEC_LVL);
	unsigned char buf[M];
	unsigned char hashbuf[M];

    for (int i = 0; i < MERKLE_KEY_LEN; ++i)
    {
     	fsgen(seed,seed,buf);
    	memcpy(s+i*M,buf,M*sizeof(char));
    	hash32(buf,M,hashbuf);
    	memcpy(v+i*M,hashbuf,M*sizeof(char));
    }

    return;
}

// Returns Merkle OTS signature upon receiving signature key and message
void merkle_sign(const unsigned char s[MERKLE_KEY_LEN*LEN_BYTES(MERKLE_SEC_LVL)], unsigned char *h, unsigned char *sig)
{
	int M = LEN_BYTES(MERKLE_SEC_LVL);
	int K = log2(MERKLE_N)+1;
	int bin_hash[MERKLE_N], bin_buf[K], bin_total[MERKLE_KEY_LEN]; // Recall MERKLE_KEY_LEN = MERKLE_N + K;
	int zero_count = 0;
	int j = 0;

	hash_to_bin_digit(h,bin_hash);
	zero_count = num_zero(bin_hash,MERKLE_N);
	int_to_bin_digit(zero_count,K,bin_buf);
	memcpy(bin_total,bin_hash,MERKLE_N*sizeof(int));
	memcpy(bin_total+MERKLE_N,bin_buf,K*sizeof(int));
	
	for (int i = 0; i < MERKLE_KEY_LEN; ++i)
	{
		if (bin_total[i]==1)
		{
			memcpy(sig+j*M,s+i*M,M*sizeof(char));
			++j;
		}
	}
}

// Returns number of errors in signature sig upon receiving verification key, message digest and signature.
int merkle_verify(unsigned char * v, unsigned char *h, unsigned char *sig)
{
	int M = LEN_BYTES(MERKLE_SEC_LVL);
	int err_count = 0;
	int zero_count = 0;
	int j = 0;
	int K = log2(MERKLE_N)+1;
	int bin_hash[MERKLE_N], bin_buf[K], bin_total[MERKLE_KEY_LEN]; // Recall MERKLE_KEY_LEN = MERKLE_N + K;
	unsigned char buf[M], temp[M];
	unsigned char hashbuf[M];

	hash_to_bin_digit(h,bin_hash);
	zero_count = num_zero(bin_hash,MERKLE_N);
	int_to_bin_digit(zero_count,K,bin_buf);
	memcpy(bin_total,bin_hash,MERKLE_N*sizeof(int));
	memcpy(bin_total+MERKLE_N,bin_buf,K*sizeof(int));
	for (int i = 0; i < MERKLE_KEY_LEN; ++i)
	{
		if (bin_total[i]==1)
		{
			memcpy(buf,sig+j*M,M*sizeof(char));
			hash32(buf,M,hashbuf);
			memcpy(temp,v+i*M,M*sizeof(char));
			if (memcmp(hashbuf,v+i*M,M*sizeof(char)))
			{
				++err_count;
			}
			++j;
		}
		
	}

	return err_count;
}

int main(int argc, char const *argv[])
{
	unsigned char seed[32];
	int N = MERKLE_KEY_LEN*LEN_BYTES(MERKLE_SEC_LVL);
	unsigned char s[N], v[N];

    unsigned char sig[LEN_BYTES(MERKLE_SEC_LVL)*256], hash[32];
    const unsigned char msg[16] = "--Hello, world!";


    int out[256];
    srand(time(NULL));

	for (int j = 0; j < 32; ++j) {
        seed[j] = rand() ^ j; // semi-random seed
    }

    merkle_keygen(seed,s,v);

    Display("private sign key s",s,32);
    Display("public sign key v",v,32);
    hash32(msg,32,hash);
	merkle_sign(s,hash,sig);
	hash_to_bin_digit(hash,out);
    printf("Hash in binary\n");
    for (int j = 0; j < 8; ++j)
    {
    	printf("%d ",out[j]);
    }
    printf("...\n\n");
    Display("signature",sig,32);
    int err = merkle_verify(v,hash,sig);

    printf("Number of ERRORS: %d \nSTATUS: %s\n\n",err, err == 0 ? "SUCCESS" : "FAILURE");

    return 0;
}
