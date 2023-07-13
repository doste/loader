#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Este archivo es solo para probar cositas.

char table[40] = {'\0', 't', 'e', 's', 't', '.', 'c', '\0', 
                    'f', '\0', '2', 't', '\0', '\0'};
// idx test.c = 1
// idx f = 7
// idx 2t = 9


int* f() {

    int* ptr = malloc(100000);
    return ptr;
}

int main() {

    int* ptr = f();

    ptr[10] = 272;

    printf("PID: %d\n", getpid());

    while(1) {}

}