# Shorter Merkle Signatures
A C implementation of the post-quantum Merkle signature scheme (MSS) combined with the Winternitz one-time Signature (WOTS).

This implementation is based on the recent technique that achieves shorter Merkle signatures [1] and also on the provably secure WOTS based on pseudorandom functions [2].

Note: This library is intended for academic purposes. It is not completely ready for production.


# Compilation instructions

Just type `make` at the root directory.

The executable files *mss-bench* and *mss-test* will be generated inside *bin* directory.

The file mss-bench benchmarks key generation, signing and signature verification as well. All leaves (WINTERNITZ One Time Signatures) of the Merkle tree are used to sign and an average time is taken (this time varies a little bit from leaf to leaf).

The file *mss-test* tests the signatures for all the leaves and authentication paths in the merkle tree. It outputs the exact number of leaves for which the signature failed.

The tree height can be changed by using the following compilation flag

>  **make MSS_HEIGHT=5**

Notice that treehash algorithm (BDS) is being used, so the parameter MSS_K should be changed accordingly.
The restrictions on MSS_K are:

1. (MSS_HEIGHT - MSS_K) must be even
2. 2 <= K < MSS_HEIGHT

Thus, for MSS_HEIGHT=5, MSS_K in {3}.

>  **make MSS_HEIGHT=5 MSS_K=3**

Similarly, for MSS_HEIGHT=6, MSS_K in {2,4}.

>  **make MSS_HEIGHT=6 MSS_K=2**

or

>  **make MSS_HEIGHT=6 MSS_K=4**

Increasing MSS_K increases the state size but signing is faster.

Moreover, one can use the WINTERNITZ_W parameter for a signature size x speed tradeoff.
The larger the WINTERNITZ_W the shorter the signature sizes, but keygen and signing are slower.
The library currently provides three options: WINTERNITZ_W in {2,4,8}.
A complete example is given bellow.

>  **make MSS_HEIGHT=10 MSS_K=8 WINTERNITZ_W=2**

Then, try to run

>  **./bin/mss-test**

or

>  **./bin/mss-bench**


## License
   
This library is licensed under the GPLv3 License.

# References

[1] 2016. G. Pereira, C. Puodzius and P. Barreto. "Shorter hash-based signatures" Available [`here`](http://www.sciencedirect.com/science/article/pii/S0164121215001466).

[2] 2011. J. Buchmann, E. Dahmen, S. Ereth, A. Hulsing, M. Ruckert. On the Security of the Winternitz One-Time Signature Scheme. Available [`here`](https://www.researchgate.net/profile/Andreas_Huelsing/publication/220335447_On_the_Security_of_the_Winternitz_One-Time_Signature_Scheme/links/0c960524bfdf3550f9000000.pdf).
