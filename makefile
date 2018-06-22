CC?=gcc

CFLAGS=-std=c99 -g -Wall -pedantic -I include $(MSS_PARAMS)
MSS_OBJS= bin/util.o bin/hash.o bin/sha2.o bin/aes.o bin/ti_aes.o


all:	execs libs

ti_aes:	src/ti_aes.c
		mkdir -p bin
		$(CC) src/ti_aes.c -c -o bin/ti_aes.o $(CFLAGS)
		
aes:	src/aes_128.c
		make ti_aes
		$(CC) src/aes_128.c -c -o bin/aes.o $(CFLAGS)

sha2:   src/sha2.c		
		$(CC) src/$@.c -c -o bin/$@.o $(CFLAGS)

hash:   src/hash.c
		make aes
		make sha2
		$(CC) src/$@.c -c -o bin/$@.o $(CFLAGS)

util:	src/util.c
		make hash
		$(CC) src/$@.c -c -o bin/$@.o $(CFLAGS)

lamport:	src/util.c
			make util
			make libs
			$(CC) src/$@.c -o bin/lamport $(MSS_OBJS) $(CFLAGS)

merkle:		src/util.c
			make util
			make libs
			$(CC) src/$@.c -o bin/merkle $(MSS_OBJS) $(CFLAGS)

gmr:		src/util.c
			make util
			make libs
			$(CC) src/$@.c -o bin/gmr $(MSS_OBJS) $(CFLAGS)

winternitz:	src/util.c
			make util
			make libs
			$(CC) src/$@.c -o bin/winternitz $(MSS_OBJS) $(CFLAGS)

execs:	src/util.c src/mss.c
		make util
		$(CC) src/mss.c -o bin/mss $(MSS_OBJS) $(CFLAGS)

libs:
		gcc -c -fPIC -o bin/dyn_ti_aes.o src/ti_aes.c $(CFLAGS)
		gcc -c -fPIC -o bin/dyn_sha2.o src/sha2.c $(CFLAGS)	
		gcc -c -fPIC -o bin/dyn_aes.o src/aes_128.c $(CFLAGS)
		gcc -c -fPIC -o bin/dyn_hash.o src/hash.c $(CFLAGS)
		gcc -c -fPIC -o bin/dyn_util.o src/util.c $(CFLAGS)
		gcc -shared -Wl,-install_name,libcrypto.so -o bin/libcrypto.so bin/dyn_*.o -lc
		ar rcs bin/libcrypto.a bin/aes.o bin/sha2.o bin/hash.o bin/util.o
clean:		
		rm -rf *.o bin/* lib/*