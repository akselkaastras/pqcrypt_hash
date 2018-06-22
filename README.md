# Hash-based signature schemes
A C implementation of various one-time signature schemes (OTS), including LD-OTS, Merkle's OTS, W-OTS and the odd one out GMR. It also features a shortened edition of Pereira and Puodzius' shorter Merkle signature scheme [1].

Note: This library is intended for academic purposes. It is not completely ready for production. The code is written as a part of a B.Sc Thesis. 


# Compilation instructions

Just type `make` at the root directory for the MSS program. The executable file mss will be generated inside *bin* directory.

For LD-OTS type `make lamport` at the root directory. The executable file lamport will be generated inside *bin* directory.

For Merkles OTS type `make merkle` at the root directory. The executable file merkle will be generated inside *bin* directory.

For W-OTS type `make winternitz` at the root directory. The executable file winternitz will be generated inside *bin* directory.

For GMR type `make gmr` at the root directory. The executable file gmr will be generated inside *bin* directory.

To change specific parameters for the one-time signatures or mss, simply go to /include and find the corresponding .h header file. Here you can edit securityparameters and tree heights.

## License
   
This library is licensed under the Apache License 2.0.

# References

[1] 2016. G. Pereira, C. Puodzius and P. Barreto. "Shorter hash-based signatures" Available [`here`](http://www.sciencedirect.com/science/article/pii/S0164121215001466).
