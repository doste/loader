#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <assert.h>
#include <elf.h>
#include <errno.h>
#include <string.h>

/*
    En elf.h estan definidas estas macros:
    #define ELF32_ST_BIND(i)    ((i) >> 4)
    #define ELF32_ST_TYPE(i)    ((i)&0xf)
    #define ELF32_ST_INFO(b,t)  (((b)<<4)+((t)&0xf))

    nos seran utiles para obtener info de los symbols
*/
enum Type {NoType, File, Func, Object}; // Symbol Types

enum Binding {Local, Global, Weak};     // Types of Binding . A symbol's binding determines the linkage visibility and behavior. 

struct SymbolHelper {
    char* name;                 // este estaria dado por StringTable[st_name]
    unsigned int addr;          // este por st_value
    int size;                   // st_size

    enum Type type;             // estos dos por st_info + Macros 
    enum Binding bind;
};

struct SymbolHandle {
    struct SymbolHelper* symbols;
    size_t number_of_symbols;
};

struct ElfHandle {
    FILE* fptr;
    Elf32_Ehdr header;
    Elf32_Phdr* program_header_table;
    Elf32_Shdr* section_header_table;

    char* string_table_symbols;
    char* string_table_sections;
    
    // helper structure
    struct SymbolHandle* symbol_handle;

    Elf32_Sym* symbol_table;
};

FILE* open_elf_file(const char *pathname, const char *mode) {
    FILE*  fptr = fopen(pathname, mode);
    assert(fptr != NULL);
}

#define MAX_STR_LEN 7
void type_of_symbol_to_string(enum Type type, char** str_dest) {
    switch (type) {
        case NoType:
            *str_dest = "NOTYPE";
            break;
        case File:
            *str_dest = "FILE";
            break;
        case Func:
            *str_dest = "FUNC";
            break;
        case Object:
            *str_dest = "OBJECT";
            break;
    }
}

void print_type_of_symbol(enum Type type) {
     char** type_str = malloc(MAX_STR_LEN * sizeof(char*));
    type_of_symbol_to_string(type, type_str);
    printf("%s\n", *type_str);
    free(type_str);
}

void bind_of_symbol_to_string(enum Binding bind, char** str_dest) {
    switch (bind) {
        case Global:
            *str_dest = "GLOBAL"; 
            break;
        case Local:
            *str_dest = "LOCAL"; 
            break;
        case Weak:
            *str_dest = "WEAK";
            break;
    }
}

void print_bind_of_symbol(enum Binding bind) {
    char** bind_str = malloc(MAX_STR_LEN * sizeof(char*));
    bind_of_symbol_to_string(bind, bind_str);
    printf("%s\n", *bind_str);
    free(bind_str);
}


// Many symbols have associated sizes. For example, a data object's size is the number of bytes
// contained in the object. This member holds 0 if the symbol has no size or an unknown size.

// info debe ser: "size", "addr" o "type"
unsigned int get_info_of_symbol(struct ElfHandle* handle, const char* symbol_name, const char* info) {

    for (size_t i = 0; i < handle->symbol_handle->number_of_symbols; i++) {
        struct SymbolHelper* sym = handle->symbol_handle->symbols + i;
        if (strcmp(sym->name, symbol_name) == 0) {
            if (strcmp(info, "size") == 0) {
                return sym->size;
            } else if (strcmp(info, "addr") == 0) {
                return sym->addr;
            } else if (strcmp(info, "type") == 0) {
                return (unsigned int)sym->type;
            } else if (strcmp(info, "bind") == 0) {
                return (unsigned int)sym->bind;
            } else {
                return 0;
            }
        }
    }
    return 0;
}

void print_elf_header(Elf32_Ehdr* header) {
    printf("ELF Header:\n");
    printf("    Type: ");
       switch(header->e_type) {
        case 0:
              printf("ET_NONE\n");
              break;
        case 1:
              printf("ET_REL\n");
              break;
        case 2:
              printf("ET_EXEC\n");
              break;
        case 3:
              printf("ET_DYN\n");
              break;
        default:
              printf("unknown type\n");
              break;
    }
    printf("    Entry point address: %p\n", header->e_entry);
    printf("    Start of program headers: %u (bytes into file)\n", header->e_phoff);
    printf("    Start of section headers: %u (bytes into file)\n", header->e_shoff);
    printf("    Size of this header: %u (in bytes)\n", header->e_ehsize);
    printf("    Size of program headers: %u (in bytes, all entries are the same size.)\n", header->e_phentsize);
    printf("    Number of program headers: %u\n", header->e_phnum);
    printf("    Size of section headers: %u (in bytes, all entries are the same size.)\n", header->e_shentsize);
    printf("    Number of section headers: %u\n", header->e_shnum);
}

void print_program_header(Elf32_Phdr* ph) {
    printf("Program Headers:\n");
    //printf("Type    Offset      VirtAddr      PhysAddr  FileSiz Flg Align\n");
    printf("    Type: ");
       switch(ph->p_type) {
        case PT_NULL:
              printf("PT_NULL\n");
              break;
        case PT_LOAD:
              printf("PT_LOAD\n");
              break;
        case PT_DYNAMIC:
              printf("PT_DYNAMIC\n");
              break;
        case PT_INTERP:
              printf("PT_INTERP\n");
              break;
        case PT_TLS:
              printf("PT_TLS\n");
              break;
        case PT_GNU_RELRO:
              printf("PT_GNU_RELRO\n");
              break;
        case PT_GNU_STACK:
              printf("PT_GNU_STACK\n");
              break;
        case PT_NOTE:
            printf("PT_NOTE\n");
            break;
        default:
              printf("unknown type\n");
              break;
       }
    printf("    Offset: 0x%08x\n", ph->p_offset);
    printf("    VirtAddr: 0x%08x\n", ph->p_vaddr);
    printf("    PhysAddr: 0x%08x\n", ph->p_paddr);
    printf("    FileSiz: 0x%08x\n", ph->p_filesz);
    printf("    MemSiz: 0x%08x\n", ph->p_memsz);
    printf("    Flg: ");
    if (ph->p_flags & PF_R) {
        printf("R ");
    }
    if (ph->p_flags & PF_X) {
        printf("E ");
    }
    if (ph->p_flags & PF_W) {
        printf("W ");
    }
    printf("\n");

}

void build_string_table_symbols(struct ElfHandle* handle, int idx) {
    for (size_t i = 0; i < handle->header.e_shnum; i++) {
        Elf32_Shdr sh_strtab = handle->section_header_table[i];

        if (sh_strtab.sh_type == SHT_STRTAB && i != handle->header.e_shstrndx && i == idx) {
            
            handle->string_table_symbols = malloc(sh_strtab.sh_size);

            fseek(handle->fptr, sh_strtab.sh_offset, SEEK_SET);

            size_t bytes_read = 0;
            bytes_read = fread(handle->string_table_symbols, sh_strtab.sh_size, 1, handle->fptr);
            assert(bytes_read == 1);
        }
    }
}

void build_string_table_sections(struct ElfHandle* handle) {

    // el header del ELF tiene este campo:
    //      e_shstrndx
    // This member holds the section header table index of the entry associated with
    // the section name string table. 
    // Entonces para obtener los nombres de las sections indexaremos nuestra tabla de sections usando ese valor
    Elf32_Shdr sh_strtab = handle->section_header_table[handle->header.e_shstrndx];
    assert(sh_strtab.sh_type == SHT_STRTAB);
            
    handle->string_table_sections = malloc(sh_strtab.sh_size);

    fseek(handle->fptr, sh_strtab.sh_offset, SEEK_SET);

    size_t bytes_read = 0;
    bytes_read = fread(handle->string_table_sections, sh_strtab.sh_size, 1, handle->fptr);
    assert(bytes_read == 1);
        
}

void build_symbol_table(struct ElfHandle* handle) {

    for (size_t i = 0; i < handle->header.e_shnum; i++) {
        Elf32_Shdr sh = handle->section_header_table[i];

        if (sh.sh_type == SHT_SYMTAB) {

            // para poder armarnos esta section bien con los symbols debemos tener ya armada la String Table correspondiente a esta section
            // la spec nos dice que el field sh_link nos da el indice de su StringTable 
            build_string_table_symbols(handle, sh.sh_link);

            // the .symtab section is simply an array of the Elf32_Sym structs
            // cada entry en esta section (por ser de tipo SymTab) tiene un tamano dado por sh_entsize
            // entonces para saber cuantas entries tenemos en esta section hacemos:
            size_t number_of_entries_in_symbol_table = sh.sh_size / sh.sh_entsize;

            // primero nos tenemos que traer a memoria la section en si
            fseek(handle->fptr, sh.sh_offset, SEEK_SET);

            size_t bytes_read_section = 0;

            handle->symbol_table = malloc(number_of_entries_in_symbol_table * sizeof(Elf32_Sym));

            for (size_t j = 0; j < number_of_entries_in_symbol_table; j++) {
                //bytes_read_section = fread(&symtab[j], sh.sh_entsize, 1, handle->fptr);
                bytes_read_section = fread(handle->symbol_table + j, sh.sh_entsize, 1, handle->fptr);
                assert(bytes_read_section == 1);
            }
            
            handle->symbol_handle = malloc(sizeof(struct SymbolHandle));
            memset(handle->symbol_handle, 0, sizeof(struct SymbolHandle));

            handle->symbol_handle->number_of_symbols = number_of_entries_in_symbol_table;

            handle->symbol_handle->symbols = malloc(sizeof(struct SymbolHelper) * number_of_entries_in_symbol_table);
            memset(handle->symbol_handle->symbols, 0, sizeof(struct SymbolHelper) * number_of_entries_in_symbol_table);

            for (size_t j = 0; j < number_of_entries_in_symbol_table; j++) {
                Elf32_Sym* st_entry = handle->symbol_table + j;

                enum Type type;
                switch (ELF32_ST_TYPE(st_entry->st_info)) {
                    case 0:
                        type = NoType;
                        break;
                    case 1:
                        type = Object;
                        break;
                    case 2:
                        type = Func;
                        break;
                    case 3:
                        printf("SECTION");
                        break;
                    case 4:
                        type = File;
                        break;
                    case 13:
                        printf("LOPROC");
                        break;
                    case 15:
                        printf("HIPROC");
                        break;
                }
                enum Binding bind;
                switch (ELF32_ST_BIND(st_entry->st_info)) {
                    case 0:
                        bind = Local;
                        break;
                    case 1:
                        bind = Global;
                        break;
                    case 2:
                        bind = Weak;
                        break;
                }

                handle->symbol_handle->symbols[j] = (struct SymbolHelper){.name =  handle->string_table_symbols + st_entry->st_name,
                                                                          .addr = st_entry->st_value,
                                                                          .type = type,
                                                                          .bind = bind,
                                                                          .size = st_entry->st_size};



            }


            break;
        }
    }
}


struct ElfHandle* build_elf_handle(FILE* fptr) {
    struct ElfHandle* handle = (struct ElfHandle*)malloc(sizeof(struct ElfHandle));

    handle->fptr = fptr;

    size_t bytes_read = fread(&(handle->header), sizeof(Elf32_Ehdr), 1, fptr);
    if (bytes_read != 1) {
        printf("fread failed.\n");
        exit(1);
    }

// program header table:
    Elf32_Ehdr header = handle->header;

    handle->program_header_table = (Elf32_Phdr*)malloc(header.e_phnum * header.e_phentsize);

    Elf32_Phdr* ph_table = handle->program_header_table;

    // el file position indicator quedo apuntando al final de lo que leyo con el ultimo fread, por como es el elf sabemos que
    // seguramente el program header venga despues del elf header pero por las dudas lo seteamos:
    fseek(fptr, header.e_phoff, SEEK_SET);

    size_t bytes_read_ph = 0;

    for (size_t i = 0; i < header.e_phnum; i++) {
        bytes_read_ph = fread(&ph_table[i], header.e_phentsize, 1, fptr);
        assert(bytes_read_ph == 1);
    }
// section header table:
    handle->section_header_table = (Elf32_Shdr*)malloc(header.e_shnum * header.e_shentsize);

    Elf32_Shdr* sh_table = handle->section_header_table;

    fseek(fptr, header.e_shoff, SEEK_SET);

    size_t bytes_read_sh = 0;

    for (size_t i = 0; i < header.e_shnum; i++) {
        bytes_read_sh = fread(&sh_table[i], header.e_shentsize, 1, fptr);
        assert(bytes_read_sh == 1);
    }

// symbol table:
    build_symbol_table(handle);

// string table de las sections
    build_string_table_sections(handle);


    return handle;
}


void free_elf_handle(struct ElfHandle* handle) {        
    free(handle->program_header_table);
    handle->program_header_table = NULL;
    free(handle->section_header_table);
    handle->section_header_table = NULL;

    free(handle->symbol_table);
    handle->symbol_table = NULL;

    free(handle->symbol_handle->symbols);
    handle->symbol_handle->symbols = NULL;

    free(handle->symbol_handle);
    handle->symbol_handle = NULL;

    free(handle->string_table_symbols);
    handle->string_table_symbols = NULL;

    free(handle->string_table_sections);
    handle->string_table_sections = NULL;

    fclose(handle->fptr);

    free(handle);
    handle = NULL;
}


#define PGSIZE 4096 
#define PGROUNDDOWN(a) (((a)) & ~(PGSIZE - 1))

void* load_segment(Elf32_Phdr* ph, FILE* fptr) {

    //nos interesa cargar solo aquellos segmentos de tipo LOAD
    if (ph->p_type != PT_LOAD) {
        return NULL;
    }

    rewind(fptr);
    int fd = fileno(fptr);

    int prot = 0;

    if (ph->p_flags & PF_X) {
        prot |= PROT_EXEC;
    }
    if (ph->p_flags & PF_W) {
        prot |= PROT_WRITE;
    }
    if (ph->p_flags & PF_R) {        
        prot |= PROT_READ;
    }
    
    /* flags para mmap:
    PROT_NONE  = 0x0
    PROT_READ  = 0x1
    PROT_WRITE = 0x2
    PROT_EXEC  = 0x4

    en cambio los p_flags son:
    PF_X = 0x1 	
    PF_W = 0x2 	
    PF_R = 0x4
    */

    void* addr_to_mmap;
    if ((ph->p_vaddr % PGSIZE) != 0) {
        // si la vaddr no esta alineada, la alineamos, redondeando para abajo. 
        // el mmap que estamos por hacer fallara si le pasamos una addr que no este
        // alineada a PAGESIZE
        addr_to_mmap = (void*)PGROUNDDOWN(ph->p_vaddr);
    } else {
        addr_to_mmap = (void*)ph->p_vaddr;
    }
    // lo mismo debe pasar con el offset
    // man mmap dice: "offset must be a multiple of the page size..."
    long int offset_to_mmap;
    if ((ph->p_offset % PGSIZE) != 0) {
        // si la vaddr no esta alineada, la alineamos, redondeando para abajo. 
        // el mmap que estamos por hacer fallara si le pasamos una addr que no este
        // alineada a PAGESIZE
        offset_to_mmap = PGROUNDDOWN(ph->p_offset);
    } else {
        offset_to_mmap = ph->p_offset;
    }

    void* ptr_to_exec_mem = mmap(addr_to_mmap, ph->p_memsz,
                                prot,
                                MAP_PRIVATE, 
                                fd,
                                offset_to_mmap);

    if (ptr_to_exec_mem == MAP_FAILED) {
        printf("mmap failed: %s\n", strerror(errno));
        printf("(void*)ph->p_vaddr que rompe: %p\n", addr_to_mmap);        
    //} else {
    //    printf("MAP!\n");
    }

    return ptr_to_exec_mem;
}

void load_elf(struct ElfHandle* handle) {
    for (size_t i = 0; i < handle->header.e_phnum; i++) {

        void* ptr_to_segment = load_segment(&(handle->program_header_table[i]), handle->fptr);
        //printf("VOLVIO! %p\n", ptr_to_segment);

        if (ptr_to_segment == NULL) {
            continue;
        }

        // quizas tengamos un segment con memsz > filesz (seguramente para la section .bss), en ese caso
        // nos encargamos de poner todo 0 en esa memoria:
        if (handle->program_header_table[i].p_memsz > handle->program_header_table[i].p_filesz) {
            //void *ptr = (void*)ptr_to_segment + handle->program_header_table[i].p_offset + handle->program_header_table[i].p_filesz;
            //printf("ptr: %p\n", ptr_to_segment + handle->program_header_table[i].p_filesz);
            memset((void*)ptr_to_segment + handle->program_header_table[i].p_filesz,
                     0,
                     handle->program_header_table[i].p_memsz - handle->program_header_table[i].p_filesz);
            
        }
    }
}

/*
Expectativa:

Symbol table '.symtab' contains 8 entries:
   Num:    Value  Size Type    Bind   Vis      Ndx Name
     0: 00000000     0 NOTYPE  LOCAL  DEFAULT  UND 
     1: 00000000     0 FILE    LOCAL  DEFAULT  ABS test.c
     2: 08049000    19 FUNC    GLOBAL DEFAULT    1 f
     3: 0804c000     4 OBJECT  GLOBAL DEFAULT    3 c
     4: 0804c000     0 NOTYPE  GLOBAL DEFAULT    3 __bss_start
     5: 08049013    22 FUNC    GLOBAL DEFAULT    1 main
     6: 0804c000     0 NOTYPE  GLOBAL DEFAULT    3 _edata
     7: 0804c004     0 NOTYPE  GLOBAL DEFAULT    3 _end

Realidad:
*/
void print_symbol_table(struct ElfHandle* handle) {
    struct SymbolHandle* sym_hndle = handle->symbol_handle;

    printf("Symbol table '.symtab' contains %d entries:\n", sym_hndle->number_of_symbols);

    printf(" %-10s%-15s%-10s%-10s%-10s%-10s%-10s%-5s\n", "Num", "Value", "Size", "Type", "Bind", "Vis", "Ndx", "Name"); 
    //printf("%-25s%-20s%-10.2f%-10.2f%-10.2f\n", name.c_str(), title.c_str(), gross, tax, net);

    for (size_t i = 0; i < sym_hndle->number_of_symbols; i++) {
        struct SymbolHelper sym = sym_hndle->symbols[i];

        // Num:
        printf(" %-10d", i); 
        // Value:
        if (sym.addr == 0) {
           printf(" %-15s", "0x00000000"); 
        } else {
            printf(" %-15p", (void*)sym.addr); 
        }
        // Size:
        printf(" %-8d", sym.size); 
        // Type:
        char** type_str = malloc(MAX_STR_LEN * sizeof(char*));
        type_of_symbol_to_string(sym.type, type_str);
        printf(" %-10s", *type_str); 
        free(type_str);
        // Bind:
        char** bind_str = malloc(MAX_STR_LEN * sizeof(char*));
        bind_of_symbol_to_string(sym.bind, bind_str);
        printf(" %-10s", *bind_str); 
        free(bind_str);

        // Vis:
        printf(" %-8s", "-"); 
        // Ndx:
        printf(" %-8s", "-"); 
        // Name:
        printf(" %-5s", sym.name); 
        
        printf("\n");
    }

    printf("\n");
}


#define NUM_STACK_PAGES 16

void push_int(unsigned char** sp, int* value) {
    //printf("SIZE %zu\n", sizeof(value));
    //memset(*sp, 0, sizeof(value));
    //(*sp)--;
    *sp = *sp - 4;
    memcpy(*sp, value, sizeof(*value));
    //**sp = *value;
}

void push_str(unsigned char** sp, char** value) {

    *sp = *sp - 4;
    memcpy(*sp, *value, sizeof(char*));

}

size_t cant_pushes = 0;

void push_elem(unsigned char** sp, void** value) {
    cant_pushes++;

    *sp = *sp - 4;
    memcpy(*sp, value, sizeof(void*));

}

void f(Elf32_auxv_t* aux) {
    size_t stack_size = 2 * getpagesize(); 
    void* addr_stack = mmap(NULL, stack_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    unsigned char* stack_ptr = (unsigned char*) addr_stack + stack_size;

    push_elem(&stack_ptr, &aux);
}

/*
Argument strings, environment strings, and the auxiliary information appear in
no specific order within the information block; the system makes no guarantees
about their arrangement. The system also may leave an unspecified amount of
memory between the null auxiliary vector entry and the beginning of the informa-
tion block.

------------------------------------------------------------- 0x7fff6c845000
     0x7fff6c844ff8: 0x0000000000000000
            _  4fec: './stackdump\0'                      <------+
      env  /   4fe2: 'ENVVAR2=2\0'                               |    <----+
           \_  4fd8: 'ENVVAR1=1\0'                               |   <---+ |
           /   4fd4: 'two\0'                                     |       | |     <----+
     args |    4fd0: 'one\0'                                     |       | |    <---+ |
           \_  4fcb: 'zero\0'                                    |       | |   <--+ | |
               3020: random gap padded to 16B boundary           |       | |      | | |
    - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -|       | |      | | |
               3019: 'x86_64\0'                        <-+       |       | |      | | |
     auxv      3009: random data: ed99b6...2adcc7        | <-+   |       | |      | | |
     data      3000: zero padding to align stack         |   |   |       | |      | | |
    . . . . . . . . . . . . . . . . . . . . . . . . . . .|. .|. .|       | |      | | |
               2ff0: AT_NULL(0)=0                        |   |   |       | |      | | |
               2fe0: AT_PLATFORM(15)=0x7fff6c843019    --+   |   |       | |      | | |
               2fd0: AT_EXECFN(31)=0x7fff6c844fec      ------|---+       | |      | | |
               2fc0: AT_RANDOM(25)=0x7fff6c843009      ------+           | |      | | |
      ELF      2fb0: AT_SECURE(23)=0                                     | |      | | |
    auxiliary  2fa0: AT_EGID(14)=1000                                    | |      | | |
     vector:   2f90: AT_GID(13)=1000                                     | |      | | |
    (id,val)   2f80: AT_EUID(12)=1000                                    | |      | | |
      pairs    2f70: AT_UID(11)=1000                                     | |      | | |
               2f60: AT_ENTRY(9)=0x4010c0                                | |      | | |
               2f50: AT_FLAGS(8)=0                                       | |      | | |
               2f40: AT_BASE(7)=0x7ff6c1122000                           | |      | | |
               2f30: AT_PHNUM(5)=9                                       | |      | | |
               2f20: AT_PHENT(4)=56                                      | |      | | |
               2f10: AT_PHDR(3)=0x400040                                 | |      | | |
               2f00: AT_CLKTCK(17)=100                                   | |      | | |
               2ef0: AT_PAGESZ(6)=4096                                   | |      | | |
               2ee0: AT_HWCAP(16)=0xbfebfbff                             | |      | | |
               2ed0: AT_SYSINFO_EHDR(33)=0x7fff6c86b000                  | |      | | |
    . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .        | |      | | |
               2ec8: environ[2]=(nil)                                    | |      | | |
               2ec0: environ[1]=0x7fff6c844fe2         ------------------|-+      | | |
               2eb8: environ[0]=0x7fff6c844fd8         ------------------+        | | |
               2eb0: argv[3]=(nil)                                                | | |
               2ea8: argv[2]=0x7fff6c844fd4            ---------------------------|-|-+
               2ea0: argv[1]=0x7fff6c844fd0            ---------------------------|-+
               2e98: argv[0]=0x7fff6c844fcb            ---------------------------+
     0x7fff6c842e90: argc=3



        The variable environ points to an array of pointers to strings
       called the "environment".  The last pointer in this array has the
       value NULL.  This array of strings is made available to the
       process by the execve(2) call when a new program is started.
       When a child process is created via fork(2), it inherits a copy
       of its parent's environment.

       By convention, the strings in environ have the form "name=value".
       The name is case-sensitive and may not contain the character "=".
       The value can be anything that can be represented as a string.
       The name and the value may not contain an embedded null byte
       ('\0'), since this is assumed to terminate the string.

       Entonces los env que estan ahi arriba no son mas que strings,
       desde environ[idx] los apuntamos

*/

size_t aux_vector_cant = 0; // global temporaria ahora para safar

Elf32_auxv_t** ptr_globl;

unsigned char* stack_ptr_globl;

void* setup_stack(char* filename, void* entry_addr, int argc, char** argv, char** envp) {
    // allocamos memoria para el stack:
    size_t stack_size = NUM_STACK_PAGES * getpagesize(); 
    void* addr_stack = mmap(NULL, stack_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    unsigned char* stack_ptr = (unsigned char*) addr_stack + stack_size;

    stack_ptr_globl = stack_ptr;

    printf("inicialmente stack_ptr: %p\n", stack_ptr);      // 0xf7f24000
    printf("inicialmente stack_ptr_top %p\n", addr_stack);  // 0xf7f14000

// argc
    int argc_cpy = argc;
    push_int(&stack_ptr, &argc_cpy);

    //printf("argv[0]: %s\n", argv[0]);
    //printf("&argv[0]: %p\n", &argv[0]);
    //push_elem(&stack_ptr, &argv[0]);
// argv
    size_t i = 0;
    while(argc > 0) {
        //printf("intentando con %d\n", i);
        push_elem(&stack_ptr, &argv[i]);
        i++;
        argc--;
    }
    void* null_ptr = NULL;
    push_elem(&stack_ptr, &null_ptr);
    
    //char* str = malloc(5);
    //strcpy(str, "hola");
    char* str = "hola";

    //push_str(&stack_ptr, &str);       // este no funca

    //push_elem(&stack_ptr, &str);      // este funca

// environment vars:
    for (char **env = envp; *env; ++env) {
        //printf("%s\n", *env);
        push_elem(&stack_ptr, env); 
    }
    push_elem(&stack_ptr, &null_ptr);

// elf auxiliary vector:
    /*
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
    */
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

    printf("memcpy no problem %d\n", k);

    ptr_globl = ptr_res;

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
    stack_ptr = (unsigned char*) addr_stack + stack_size;

    printf("finalmente stack_ptr: %p\n", stack_ptr);      
    printf("finalmente stack_ptr_top %p\n", addr_stack);

    return stack_ptr;

}


int main(int argc, char** argv, char** envp) {

    if (argc != 2) {
        printf("Usage: ./loader <elf_to_load>\n");
        exit(1);
    }
    // abrimos el archivo
    FILE* fptr = open_elf_file(argv[1], "rb");

    // lo parseamos y nos construimos el handle
    struct ElfHandle* handle = build_elf_handle(fptr);

    // debuggiemos
    print_elf_header(&handle->header);
    for (size_t i = 0; i < handle->header.e_phnum; i++) {
        print_program_header(&(handle->program_header_table[i]));
    }

    //printf("SYMBOLS:\n");
    //print_symbol_table(handle);

    // lo cargamos
    load_elf(handle);

    size_t cant = 0;
    printf("ENVIRONMENT VARIABLES:\n");
    for (char **env = envp; *env; ++env) {
        cant++;
        printf("%s\n", *env);
        
    }
    printf("cant: %d\n", cant);

    printf("\n\n");
    printf("auxiliary:\n");
    Elf32_auxv_t *auxv;
    cant = 0;

    Elf32_auxv_t* test;

    char** envp_copy = envp;
    while (*envp++ != NULL); 

    for (auxv = (Elf32_auxv_t *)envp; auxv->a_type != AT_NULL; auxv++)
        /* auxv->a_type = AT_NULL marks the end of auxv */
    {
        cant++;
        if (cant == 1) {
            test = auxv;
            printf("it %d is: %p\n",cant, (void*)auxv->a_un.a_val);
        }
    }

    f(test);

    aux_vector_cant = cant;
    printf("cantcant: %d\n", cant);
    //printf("PID: %d\n", getpid());

    //printf("SIZE OF ELF32AUX_V: %zu\n", sizeof(Elf32_auxv_t));
    //printf("a_type: %d\n", test->a_type);
    //printf("a_val: %p\n", test->a_un.a_val);

    //void* addr = (void*)test->a_un.a_val;

    // lo ejecutamos
    //void (*start)(void);
    //start = (void(*)(void))(handle->header.e_entry);
    //start();

    //int (*start)(void);
    //start = (int(*)(void))(handle->header.e_entry);
    //printf("%d\n", start());

    // Setup Stack
    int argc2 = 3;
    char* argv2[] = {"hola", "mundo", "!"};

    printf("&argv[0] en main: %p\n", &argv2[0]);

	void* stack_ptr = setup_stack(argv[1], (void*)handle->header.e_entry, argc2, argv2, envp_copy);
    // uso envp_copy porque envp quedo adelantado, para obtener el aux vector

    //printf("eSP: %p\n", (void*)stack_ptr);

    //printf("PID: %d\n", getpid());
    //while(1) {}

    printf("PUSHES %zu\n", cant_pushes);

    Elf32_auxv_t* aux_jj = ptr_globl[0];
    printf("ptr_globl type is: %d\n", aux_jj->a_type);
    printf("ptr_globl val is: %p\n", (void*)aux_jj->a_un.a_val);


    printf(" stack_ptr ERA: %p\n", stack_ptr);      

    //stack_ptr = stack_ptr - 4;

    printf(" stack_ptr va para esp como %p\n", stack_ptr);

    printf(" stack_ptr_global vale %p\n", stack_ptr_globl);

    asm("movl %0, %%esp\n\t" : "+r" (stack_ptr));
	asm("movl %0, %%eax\n\t" : "+r" (handle->header.e_entry));
	asm("movl $0, %edx");       // estos 2 registros se setean asi por la SYSTEM V APPLICATION BINARY INTERFACE Intel386 seccion 3.28 (pg. 55)
    asm("movl $0, %ebp");
    //printf("por saltar!!! a %p\n", (void*)handle->header.e_entry);
	asm("jmp *%eax\n\t");	

    //int (*start)(void);
    //start = (int(*)(void))(handle->header.e_entry);
    //printf("%d\n", start());
    
    //build_symbol_table(handle);

    //print_symbol_table(handle);

    //printf("sym_hdle: NAME: %s, ADDR: %p\n", sym_hdle.name, (void*)sym_hdle.addr);

    
    // ejecutamos f:
    //void (*f)(int, int);
    // aca estaria bueno tener una estructura de datos que le podamos decir el nombre (en este caso f) y directamente nos diga su address(value) para saltar ahi
    // algo asi: unsigned int addr = get_addr_of_symbol(handle, "f");
/*
    for (size_t i = 0; i < handle->symbol_table; i++) {
        Elf32_Sym* symbol = handle->symbol_table + i;

        if (strcmp(handle->string_table_symbols + symbol->st_name, "f") == 0) {
            f = (void (*)(int, int))(symbol->st_value);
           
            f(2, 1); 
        
        }
    }
    */

    //unsigned int addr = get_addr_of_symbol(handle, "f");

    //f = (void (*)(int, int))(addr);

    //f(2, 1); 

    //printf("-------------------\n");
    //print_symbol_table(handle);

    //build_string_table_sections(handle);
    //for (size_t i = 0; i < handle->header.e_shnum; i++) {
    //    printf("%s\n", handle->string_table_sections + handle->section_header_table[i].sh_name);
    //}




    free_elf_handle(handle);
}