#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <elf.h>
#include <unistd.h>
#include <assert.h>
#include <stdio.h>

// estos pushes no modelan tal cual el comportamiento de los push del micro, ya que este al hacer un push(X) lo que hace es:
//  esp = esp = 4
//  [esp] = X
// en cambio aca, por como estamos armando el stack, por conveniencia este push suma 4 y luego coloca
void push_elem(unsigned char** sp, void** value) {
    *sp = *sp - 4;
    memcpy(*sp, value, sizeof(void*));
    //*sp = *sp - 4;

    // TODO resguardar de alguna manera
}

unsigned char* push_elem_ret(unsigned char** sp, void** value) {
    unsigned char* original_value = *sp;
    *sp = *sp - 4;
    memcpy(*sp, value, sizeof(void*));
    //*sp = *sp - 4;

    return original_value;

    // TODO resguardar de alguna manera
}

unsigned char* push_str_elem_ret(unsigned char** sp, void** value) {
    unsigned char* original_value = *sp;
    //*sp = *sp - 4;
    size_t len = strlen(*value);
    len = len + 1; // porque strlen no cuenta el '\0' del final
    *sp = *sp - len;
    strcpy(*sp, *value);
    //*sp = *sp - 4;

    //return original_value;
    return *sp;
    // TODO resguardar de alguna manera
}

void push_int(unsigned char** sp, int* value) {
    *sp = *sp - 4;
    memcpy(*sp, value, sizeof(*value));

}

void push_str(unsigned char** sp, char** value) {
    *sp = *sp - 4;
    memcpy(*sp, *value, sizeof(char*));

}

#define NUM_STACK_PAGES 16

void* setup_stack(int argc, char** argv, char** envp) {
    // allocamos memoria para el stack:
    size_t stack_size = NUM_STACK_PAGES * getpagesize(); 
    void* addr_stack = mmap(NULL, stack_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    unsigned char* stack_ptr = (unsigned char*) addr_stack + stack_size;
    //unsigned char* stack_ptr = (unsigned char*) addr_stack;

    unsigned char* stack_initial = stack_ptr;

    // primero armamos el 'information block' donde residaran los strings a los que se apuntaran desde argv[], env[] y el aux vector

    /*
        0x7fff6c844ff8: 0x0000000000000000
            _  4fec: './stackdump\0'                      <------+
      env  /   4fe2: 'ENVVAR2=2\0'                               |    <----+
           \_  4fd8: 'ENVVAR1=1\0'                               |   <---+ |
           /   4fd4: 'two\0'                                     |       | |     <----+
     args |    4fd0: 'one\0'                                     |       | |    <---+ |
           \_  4fcb: 'zero\0'                                    |       | |   <--+ | |
               3020: random gap padded to 16B boundary           |       | |      | | |
    - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -|
    */

    //primero que nada pusheamos un NULL, para delimitar el final de todo
    void* null_ptr = NULL;
    push_elem(&stack_ptr, &null_ptr);

    int n = 255;
    push_elem(&stack_ptr, &n);

    // las environment vars y los args van todos aca.

    // calculamos cuantos string vamos a tener que guardarnos aca, esto sera argc + envc
    // argc nos viene, envc no, la calculamos:
    //size_t envc = 0;
    //for (char **env = envp; *env; env++) {
    //    envc++;
    //}
    size_t envc = 5; // envc de mentiritas

    size_t number_of_items = argc + envc;

    unsigned char** env_ptrs = malloc(envc * sizeof(unsigned char*));
    memset(env_ptrs, 0, envc * sizeof(unsigned char*));

    size_t k = 0;

    // hay muchas envs, asique para debuggear mas facil por ahora nos quedamos con solo las primeras 5
    size_t cant_env_debug = 5;

    // ponemos primero las envs:
    // OJO. aca solo ponemos en memoria el string en si, es decir los caracteres, luego desde env[i] se apuntaran 

    char**env_ptr;
    for (env_ptr = envp; *env_ptr; env_ptr++) {
        //printf("%s\n", *env);
        unsigned char* ptr_to = push_str_elem_ret(&stack_ptr, env_ptr);
        // tendriamos que tener alguna forma de guardarnos la addr donde quedo almacenado cada string
        // ya que despues de pushear el aux vector, vamos a pushear estas addrs, donde quedaron los strings
        memcpy(env_ptrs+k, &ptr_to, sizeof(unsigned char*));
        
        k++;

        //if (k-1 == cant_env_debug) {
        //    break;
        //}
    }

    printf("se pushearon %zu envs\n", k-1);
    
    push_elem(&stack_ptr, &null_ptr);

    int some_int = 100;
    push_elem(&stack_ptr, &some_int);


    unsigned char** argv_ptrs = malloc(argc * sizeof(unsigned char*));
    memset(argv_ptrs, 0, argc * sizeof(unsigned char*));

    k = 0;

    for (char **argv_ptr = argv; *argv_ptr; argv_ptr++) {
        //printf("%s\n", *env);
        unsigned char* ptr_to = push_str_elem_ret(&stack_ptr, argv_ptr);
        // tendriamos que tener alguna forma de guardarnos la addr donde quedo almacenado cada string
        // ya que despues de pushear el aux vector, vamos a pushear estas addrs, donde quedaron los strings
        memcpy(argv_ptrs+k, &ptr_to, sizeof(unsigned char*));
        
        k++;
    }

    // hasta aca tenemos los valores de los strings de envs y args
    // chequeamos que el stack_ptr haya queda alineadoa 16

    ////////////////////////////////////// TODO

    push_elem(&stack_ptr, &null_ptr);

    some_int = 14;
    push_elem(&stack_ptr, &some_int);

    some_int = 30;
    push_elem(&stack_ptr, &some_int);

    push_elem(&stack_ptr, &null_ptr);


    // elf aux vector:

    Elf32_auxv_t *auxv;
    //while (*envp++ != NULL); // *envp = NULL marks end of envp //
    // env_ptr nos quedo apuntando al final ya
    assert(env_ptr == NULL);
    env_ptr++;
    for (auxv = (Elf32_auxv_t *)env_ptr; auxv->a_type != AT_NULL; auxv++) {

        memcpy(ptr_res+k, &auxv, sizeof(Elf32_auxv_t*));
        
        push_elem(&stack_ptr, ptr_res+k);
        //}   
        k++;
    }


    

    // esto pasaria bien 'abajo'

    // como estamos armando el stack 'desde arriba' tenemos que pushear las cosas en orden inverso.
    // esto se ve mas claro con los argv, primero tenemos argv[0], si la pusheamos primero, nos queda arriba, la idea es que quede
    /*              +
        argv[2]
        argv[1]
        argv[0]
        argc  
                    -
    
    si pusheamos argv[0], luego argv[1] y despues argv[2], en nuestro stack nos quedaria asi:
                
        argv[0]
        argv[1]
        argv[2]
                -
    */        
    for (int j = envc-1; j >= 0; j--) {
        // si j era de tipo size_t rompia ¯\_(ツ)_/¯
        push_elem(&stack_ptr, env_ptrs+j);
    }

    //argv[argc]=(null)
    push_elem(&stack_ptr, &null_ptr);

    for (int j = argc-1; j >=0 ; j--) {
        push_elem(&stack_ptr, argv_ptrs+j);
    }

    int argc_copy = argc;
    push_elem(&stack_ptr, &argc_copy);

    printf("hola\n");

/*

// elf auxiliary vector:
    ////////
    Elf32_auxv_t *auxv;
    while (*envp++ != NULL); // *envp = NULL marks end of envp //

    for (auxv = (Elf32_auxv_t *)envp; auxv->a_type != AT_NULL; auxv++)
    // auxv->a_type = AT_NULL marks the end of auxv 
    {
        push_elem(&stack_ptr, auxv);
    }
    push_elem(&stack_ptr, &null_ptr);
    
     esto esta MAL! esta pusheando de a 4 bytes pero cada Elf32_auxv_t mide 8 bytes, tiene esta pinta:
        typedef struct {
            uint32_t a_type;              
            union
                {
                uint32_t a_val;           // Integer value //
                // We use to have pointer elements added here.  We cannot do that,
                    though, since it does not work when using 32-bit definitions
                    on 64-bit platforms and vice versa.  //
                } a_un;
        } Elf32_auxv_t;
     entonces el codigo que esta arriba lo que esta haciendo es solo pusheando el primer miembro, lo 'recorta'
     solo se queda con los 4 bytes correspondientes a a_type

    hay que pushearle un puntero bien, asi no lo recorta.
    //// /
    Elf32_auxv_t *auxv;
    //Elf32_auxv_t** res = malloc(aux_vector_cant * sizeof(Elf32_auxv_t*));
    //Elf32_auxv_t** ptr_res = malloc(sizeof(Elf32_auxv_t*));
    Elf32_auxv_t** ptr_res = malloc(aux_vector_cant * sizeof(Elf32_auxv_t*));
    memset(ptr_res, 0, aux_vector_cant * sizeof(Elf32_auxv_t*));

    //Elf32_auxv_t* res = malloc(sizeof(Elf32_auxv_t));
    //memset(res, 0, sizeof(Elf32_auxv_t));

    while (*envp++ != NULL); // *envp = NULL marks end of envp //
    size_t k = 0;
    Elf32_auxv_t var;
    for (auxv = (Elf32_auxv_t *)envp; auxv->a_type != AT_NULL; auxv++)
    {
        //push_elem(&stack_ptr, auxv);

        //var = *auxv;
        //memcpy(res + k, &var , sizeof(Elf32_auxv_t));
        //if (k == 2) {
        //if (auxv->a_type == AT_PAGESZ) {
            //memcpy(res, auxv , sizeof(Elf32_auxv_t));
            //memcpy(ptr_res, &res, sizeof(Elf32_auxv_t*));

        memcpy(ptr_res+k, &auxv, sizeof(Elf32_auxv_t*));
        
        push_elem(&stack_ptr, ptr_res+k);
        //}   
        k++;
    }

    //push_elem(&stack_ptr, &null_ptr);
    // pusheamos la null entry del vector, para delimitar donde termina
    assert(auxv->a_type == AT_NULL);
    memcpy(ptr_res+k, &auxv, sizeof(Elf32_auxv_t*));
    push_elem(&stack_ptr, ptr_res+k);

  

    //for (size_t j = 0; j < aux_vector_cant; j++) {

        //printf("va con %d\n", j);
        size_t j = 3;
        //Elf32_auxv_t aux_j = res[j];
        //printf("res[%d] type is: %d\n",j, aux_j.a_type);
        //printf("res[%d] val is: %p\n",j, (void*)aux_j.a_un.a_val);

        Elf32_auxv_t* aux_jj = ptr_res[j];
        printf("ptr_res[%d] type is: %d\n",j, aux_jj->a_type);
        printf("ptr_res[%d] val is: %p\n",j, (void*)aux_jj->a_un.a_val);
    //}

    printf("SALE\n");
    

    // el stack_ptr quedo re abajo por todos los pushes, la ABI dice que
    // el esp tiene que quedar apuntando al 'bottom of the stack' y por como lo usara
    // _start, podemos suponer que esto sera donde esta el argc pusheado.
    // osea lo primero de todo.
    // lo reestablecemos:
    //stack_ptr = (unsigned char*) addr_stack + stack_size;

    printf("finalmente stack_ptr: %p\n", stack_ptr);      
    printf("finalmente stack_ptr_top %p\n", addr_stack);

    */

    return stack_ptr;

}



int main(int argc, char** argv, char** envp) {
    void* esp = setup_stack(argc, argv, envp);

    printf("%p\n", esp);

    for (char **env = envp; *env; ++env) {
        printf("%s\n", *env);
        
    }
}