CC=gcc

CFLAGS=-Wall -m32 -g -fno-pic -fno-pie #-pie -fPIC #-fno-pic -fno-pie

all: loader test 

loader: loader.c
	$(CC) $(CFLAGS) loader.c -o loader

test: test.o 
	ld -m elf_i386 -o test test.o -no-pie -e main

test.o: test.c
	$(CC) -c -static -ggdb -m32 -fno-omit-frame-pointer test.c -fno-pic -fno-pie

#-fPIC -pie

clean:
	rm *.o loader