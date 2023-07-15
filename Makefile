CC=gcc

CFLAGS=-Wall -m32 -g -fno-pic -fno-pie #-pie -fPIC #-fno-pic -fno-pie

all: loader test_sin_libc

loader: loader.c
	$(CC) $(CFLAGS) loader.c -o loader

#test: test.o 
#	ld -m elf_i386 -o test test.o -no-pie -e main

#test.o: test.c
#	$(CC) -c -static -ggdb -m32 -fno-omit-frame-pointer test.c -fno-pic -fno-pie

#-fPIC -pie

test:
	$(CC) -static -ggdb -m32 -fno-pic -fno-pie -no-pie -fno-omit-frame-pointer test.c -o test

test_sin_libc:
	$(CC) -static -ggdb -m32 -fno-pic -fno-pie -no-pie -fno-omit-frame-pointer test_sin_libc.c -o test_sin_libc

#test_sin_libc: test_sin_libc.o 
#	ld -m elf_i386 -o test_sin_libc test_sin_libc.o -no-pie -e main
#
#test_sin_libc.o: test_sin_libc.c
#	$(CC) -c -static -ggdb -m32 -fno-omit-frame-pointer test_sin_libc.c -fno-pic -fno-pie

#test_asm.o: test_asm.asm
#	nasm -felf32 test_asm.asm -o test_asm.o 
#test_asm: test_asm.o
#	ld test_asm.o -o test_asm -no-pie -m elf_i386

clean:
	rm *.o loader