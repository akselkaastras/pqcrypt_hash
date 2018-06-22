// Copyright (C) 2018 Aksel Kaastrup Rasmussen

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <math.h>
#include <string.h>
#include "util.h"
#include "winternitz.h"


void int_to_bin_digit(unsigned int in, int count, int out[count])
{
    /* assert: count <= sizeof(int)*CHAR_BIT */

    unsigned int mask = 1U << (count-1);
    int i;
    for (i = 0; i < count; i++) {
        out[i] = (in & mask) ? 1 : 0;
        in <<= 1;
    }

    return;
}

void hash_to_bin_digit(unsigned char h[LEN_BYTES(WINTERNITZ_N)],int out[256])
{
    int buf[8];
    for (int i = 0; i < LEN_BYTES(WINTERNITZ_N); ++i)
    {
        int_to_bin_digit(h[i],8,buf);
        memcpy(out+8*i,buf,8*sizeof(int));
    }

    return;
}

int bin_digit_to_int(int * bin, int t) {
    int output = 0, power = 1;
    for (int i = 0; i < t; i++)
   {
       output += bin[t-1-i]*power;
       power *= 2;
   }
   return output;
}

// Winternitz chaining
void winternitz_chaining(unsigned char s[LEN_BYTES(WINTERNITZ_SEC_LVL)], unsigned char output[LEN_BYTES(WINTERNITZ_SEC_LVL)],unsigned int t) {
    unsigned int i;
    if (t == 0)
    {
        memcpy(output,s,LEN_BYTES(WINTERNITZ_SEC_LVL)*sizeof(unsigned char));
        return;
    }
    int M = LEN_BYTES(WINTERNITZ_SEC_LVL);

    hash32(s,M,output);             //output = F(s)
    for (i = 1; i < t; i++)
        hash32(output,M,output);     //output = F(output)
    
}

// Returns Winternitz keys upon receiving seed
void winternitz_keygen(unsigned char seed[LEN_BYTES(WINTERNITZ_N)], unsigned char s[WINTERNITZ_L*LEN_BYTES(WINTERNITZ_SEC_LVL)], unsigned char v[WINTERNITZ_L*LEN_BYTES(WINTERNITZ_SEC_LVL)]) {

    int M = LEN_BYTES(WINTERNITZ_SEC_LVL);
    //unsigned char * buf = malloc(M*sizeof(char));
    //unsigned char * chainbuf = malloc(M*sizeof(char));
    unsigned char buf[M], chainbuf[M];
    int t = WINTERNITZ_W-1;

    for (int i = 0; i < WINTERNITZ_L; ++i)
    {
        fsgen(seed,seed,buf);
        memcpy(s+i*M,buf,M*sizeof(char));
        winternitz_chaining(buf,chainbuf,t);
        memcpy(v+i*M,chainbuf,M*sizeof(char));
    }

}

// Returns Winternitz signature upon receiving signature key and message digest
void winternitz_sign(unsigned char s[WINTERNITZ_L*LEN_BYTES(WINTERNITZ_SEC_LVL)], unsigned char *h, unsigned char *sig) {

        int M = LEN_BYTES(WINTERNITZ_SEC_LVL);
        unsigned char buf1[M];
        int digest[WINTERNITZ_N];
        unsigned char chainbuf1[M];
        int checksum[WINTERNITZ_l2];
        int mess_tot[WINTERNITZ_L];
        memset(checksum, 0, WINTERNITZ_l2*sizeof(int)); //initialize with zeros
        int sum = 0;
        int j = 0;
        int quo, rem_w;
        int i = 0;
        int K = WINTERNITZ_l1;

        hash_to_bin_digit(h,digest);

        //message digest is assumed to be of length 256 bit
        for (i = 0; i < K; ++i)
        {
            sum += WINTERNITZ_W-h[i];
        }
        // init remainder of C
        rem_w = sum;
        // Write checksum in w-ary
        i = WINTERNITZ_l2-1;
        while(i != -1 && rem_w != 0)
        {
            if(rem_w >= pow(WINTERNITZ_W,i))
            {
                int k = pow(WINTERNITZ_W,i);
                quo = rem_w/k;
                rem_w = rem_w%k;
                
                checksum[j] = quo;
                ++j;
                --i;
            }
            else
            {
                ++j;
                --i;
            }
        }
        
        //Total message including checksum C.
        memcpy(mess_tot,digest,K*sizeof(int));
        memcpy(mess_tot+K,checksum,WINTERNITZ_l2*sizeof(int));
        
        for (i = 0; i < WINTERNITZ_L; ++i)
        {
            memcpy(buf1,s+i*M,M*sizeof(unsigned char));
            winternitz_chaining(buf1,chainbuf1,mess_tot[i]);
            memcpy(sig+i*M,chainbuf1,M*sizeof(unsigned char));
        }

}

// Returns the number of errors in sig compared to a correct signature
int winternitz_verify(unsigned char * v, unsigned char *h, unsigned char *sig)
{
    // Compute C and find m_i for i = 0 .. N-1 again:
    int M = LEN_BYTES(WINTERNITZ_SEC_LVL);
    unsigned char buf2[M], chainbuf2[M], vbuf[M];
    int digest[WINTERNITZ_N];
    int checksum[WINTERNITZ_l2];
    int mess_tot[WINTERNITZ_L];
    memset(checksum, 0, WINTERNITZ_l2*sizeof(int)); //initialize with zeros
    int sum = 0;
    int j = 0;
    int quo, rem_w;
    int i = 0;
    int K = WINTERNITZ_l1;
    int err_count = 0;
    hash_to_bin_digit(h,digest);

    //message digest is assumed to be of length 256 bit
    for (i = 0; i < K; ++i)
    {
        sum += WINTERNITZ_W-h[i];
    }
    // init remainder of C
    rem_w = sum;
    // Write checksum in w-ary
    i = WINTERNITZ_l2-1;
    while(i != -1 && rem_w != 0)
    {
        if(rem_w >= pow(WINTERNITZ_W,i))
        {
            int k = pow(WINTERNITZ_W,i);
            quo = rem_w/k;
            rem_w = rem_w%k;
            
            checksum[j] = quo;
            ++j;
            --i;
        }
        else
        {
            ++j;
            --i;
        }
    }
    
    //Total message including checksum C.
    memcpy(mess_tot,digest,K*sizeof(int));
    memcpy(mess_tot+K,checksum,WINTERNITZ_l2*sizeof(int));

    for (int i = 0; i < 5; ++i)
    {
        memcpy(buf2,sig+i*M,M*sizeof(unsigned char));
        winternitz_chaining(buf2,chainbuf2,2-1-mess_tot[i]);
        memcpy(vbuf,v+i*M,M*sizeof(unsigned char));
        //Display("Chainbuf2",chainbuf2,32);
        if (memcmp(vbuf,chainbuf2,M*sizeof(unsigned char)))
        {
            ++err_count;
        }
    }

    return err_count;
}


int main()
{
    int sig_len = WINTERNITZ_L*LEN_BYTES(WINTERNITZ_SEC_LVL);
    unsigned char seed[32];
    unsigned char s[sig_len], v[sig_len];
    const unsigned char msg[16] = "--Hello, world!";
    unsigned char sig[sig_len], hash[32];
    hash32(msg,32,hash);

    
    srand(time(NULL));

    for (int j = 0; j < LEN_BYTES(WINTERNITZ_N); ++j) {
        seed[j] = rand() ^ j; // semi-random seed
    }

    printf("%s\n\n",msg);
    winternitz_keygen(seed,s,v);
    Display("private sign key s",s,32);
    Display("public sign key v",v,32);

    winternitz_sign(s,hash,sig);
    Display("Signature sig",sig,32);

    int err = winternitz_verify(v, hash, sig);

    printf("Number of ERRORS: %d \nSTATUS: %s\n\n",err, err == 0 ? "SUCCESS" : "FAILURE");


    return 0;
}

