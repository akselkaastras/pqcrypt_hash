// Copyright (C) 2018 Aksel Kaastrup Rasmussen

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <gmr.h>
#include <time.h>
#include "util.h"

 int power_mod(long int x, unsigned int y, long int p)
{
    int res = 1;      // Initialize result
 
    x = x % p;  // Update x if it is more than or 
                // equal to p
 
    while (y > 0)
    {
        // If y is odd, multiply x with result
        if (y & 1)
            res = (res*x) % p;
 
        // y must be even now
        y = y>>1; // y = y/2
        x = (x*x) % p;  
    }
    return res;
}

int high_pow_of_2(int *x)
{
	int d = __builtin_ctz(*x); // Find the last 1 in x's binary representation
	*x = *x/pow(2,d);
	return d;
}

// returns x where (a * x) % b == 1
int mul_inv(int a, int b)
{
	int b0 = b, t, q;
	int x0 = 0, x1 = 1;
	if (b == 1) return 1;
	while (a > 1) {
		q = a / b;
		t = b, b = a % b, a = t;
		t = x0, x0 = x1 - q * x0, x1 = t;
	}
	if (x1 < 0) x1 += b0;
	return x1;
}


void zip_merge(int *a, int *b,int n,int *c)
{
	int i = 0;
	int j = 0;
	int k = 0;
	while(k < 2*n)
	{
		c[k] = a[i];
		c[k+1] = b[j];

	    ++i;
	    ++j;
	    k = k+2;
	}
}

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

void hash_to_bin_digit(unsigned char h[LEN_BYTES(GMR_N)],int out[256])
{
	int buf[8];
	for (int i = 0; i < LEN_BYTES(GMR_N); ++i)
	{
		int_to_bin_digit(h[i],8,buf);
		memcpy(out+8*i,buf,8*sizeof(int));
	}

	return;
}

void encode(unsigned char * hash, int code[2*256+2])
{
	int N = 256;
	int buf1[N], buf2[N];
	int buf3[2*N];
	int end[2] = {0,1};
	hash_to_bin_digit(hash, buf1);
	memcpy(buf2,buf1,N*sizeof(int));
	zip_merge(buf1,buf2,N,buf3);
	memcpy(code,buf3,2*N*sizeof(int));
	memcpy(code+2*N,end,2*sizeof(int));

	return;
}

int legendre_symbol(long int a, long int p)
{
	long int k = power_mod(a,(p-1)/2,p);
	if (k > 1)
	{
		k = -p+k;
	}

	return k;
}

int find_domain(int p, int q, int * X) // only for interested people
{	
	int i = 0;
	for (int k = 1; k < p*q/2; ++k)
	{
		if ((legendre_symbol(k,p))*(legendre_symbol(k,q)) == 1)
		{
			X[i]=k;
			++i;
		}
	}
	return i;
}

int g0(int x, int n)
{
	int y = ((int) pow(x,2))%n;
	if (y > n/2)
	{
		y = (n-y)%n;
	}
	return y;
}

int g1(int x, int n)
{
	int y = 4*((int) pow(x,2))%n;
	if (y > n/2)
	{
		y = (n-y)%n;
	}
	return y;
}

int g0_inv(int x, int p, int q)
{
	int n = p*q;
	int inv = power_mod(x,((p-1)*(q-1)+4)/8,n);
	if (inv > n/2)
	{
		inv = (n-inv)%n;
	}
	return inv;
}

int g1_inv(int x, int p, int q)
{
	int n = p*q;
	int k = ((p-1)*(q-1)+4)/8;
	int c = power_mod(4,k,n);
	int inv = power_mod(x,k,n);
	int mul_inv2 = mul_inv(c,n);
	inv = mul_inv2*inv%n;
	if (inv > n/2)
	{
		inv = (n-inv)%n;
	}
	return inv;
}

// GMR keygen returns validation parameter upon receiving input of primes p and q
int gmr_keygen(int p, int q) // with resevoir sampling
{	
	double prob;
	double i = 2;
	int valpar = 1; // first possible choise of val par.

	for (int k = 2; k < p*q/2; ++k)
	{
		if ((legendre_symbol(k,p))*(legendre_symbol(k,q)) == 1)
		{
			prob = (double)rand() / (double)RAND_MAX;
			if (prob < 1/i)
			{
				valpar = k;
			}

			++i;
		}
	}

	return valpar;

}

//GMR signature returns signature S from input of encoded message, validation parameter and p and q.
int gmr_sign(int code[2*256+2],int r,int p, int q)
{
	for (int i = 0; i < 2*256+2; ++i)
	{
		if (code[i] == 0)
		{
			r = g0_inv(r,p,q);
		}
		else
		{
			r = g1_inv(r,p,q);
		}
	}
	return r;
}

//GMR verify returns true iff S is the correct signature for the encoded message and validation parameter r.
int gmr_verify(int code[2*256+2], int r, int S, int n)
{
	int truth;
	int i = 2*256+2-1;
	while(i >= 0)
	{
		if (code[i] == 0)
		{
			S = g0(S,n);
		}
		else
		{
			S = g1(S,n);
		}
		--i;
	}
	if(r==S)
	{
		truth = 1;
	}
	else
	{
		truth = 0;
	}
	return truth;
}


int main(int argc, char const *argv[])
{
	// Initialize variables
	srand(time(NULL));
	const unsigned char msg[16] = "--Hello, world!";
	unsigned char hash[32];
	int out[256];
	int code1[2*256+2];
	// Choose p and q such that n is a blum integer
	long long unsigned q = 7; // (=3 mod 4)
	long long unsigned p = 11; // (=3 mod 4)
	// Blum integer
	long long unsigned n = p*q;

	// hash and encode
	hash32(msg,32,hash);
	hash_to_bin_digit(hash,out);
    encode(hash,code1);
    int r = gmr_keygen(p,q);
    int S = gmr_sign(code1,r,p,q);
    int t = gmr_verify(code1,r,S,n);
    
    // Print stuff
   	printf("\nMessage: %s\n",msg);
	printf("Public validation parameter r = %d\n",r);
    printf("Signature: S_r(m) = %d\n",S);
    printf("Status on received message: %s\n\n", t == 1 ? "SUCCESS" : "FAILURE");

    return 0;
}
