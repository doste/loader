#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char table[40] = {'\0', 't', 'e', 's', 't', '.', 'c', '\0', 
                    'f', '\0', '2', 't', '\0', '\0'};
// idx test.c = 1
// idx f = 7
// idx 2t = 9


void f() {

    char** table_ptr = malloc(40);

    memcpy(*table_ptr, table, 40);

    char* s = *table_ptr + 1;

    printf("S: %s\n", s);
}

int main() {

    char* s_test = table + 10;


    printf("S: %s\n", s_test);

    f();

}