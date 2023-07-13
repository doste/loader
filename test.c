#include <stdio.h>

int c;

int w = 27;

void f(int a, int b) {
    c = a+b+w;

    //while(1) {}
}

int main(int argc, char** argv, char** envp) {


    f(0,1);

    printf("hola\n");
    
    return c;
}