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

void push_elem(unsigned char** sp, void** value) {

    *sp = *sp - 4;
    memcpy(*sp, value, sizeof(void*));

}


void* setup_stack(char* filename, void* entry_addr, int argc, char** argv, char** envp) {
    // allocamos memoria para el stack:
    size_t stack_size = NUM_STACK_PAGES * getpagesize(); 
    void* addr_stack = mmap(NULL, stack_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    unsigned char* stack_ptr = (unsigned char*) addr_stack + stack_size;

    //printf("stack_ptr: %p\n", stack_ptr);      // 0xf7f24000
    //printf("stack_ptr_top %p\n", addr_stack);  // 0xf7f14000

    //int x = 7;
    //push_int(&stack_ptr, &x);
    //x = 5;
    //push_int(&stack_ptr, &x);

    int argc_cpy = argc;
    push_int(&stack_ptr, &argc_cpy);

    //printf("argv[0]: %s\n", argv[0]);
    //printf("&argv[0]: %p\n", &argv[0]);

    //push_elem(&stack_ptr, &argv[0]);

    size_t i = 0;
    while(argc > 0) {
        printf("intentando con %d\n", i);
        push_elem(&stack_ptr, &argv[i]);
        i++;
        argc--;
    }
    void* null_ptr = NULL;
    push_elem(&stack_ptr, &null_ptr);
    printf("sale\n");
    //char* str = malloc(5);
    //strcpy(str, "hola");
    char* str = "hola";

    //push_str(&stack_ptr, &str);

    //push_elem(&stack_ptr, &str);

    //printf("*stack_ptr: %s\n", stack_ptr);
    //printf("*stack_ptr: %d\n", *(stack_ptr+4));    
    //printf("*stack_ptr: %d\n", *(stack_ptr+8)); 

    //printf("stack_ptr DESPUES: %p\n", stack_ptr);      

    //printf("stack_ptr_top DESPUES %p\n", addr_stack); 

/*
    char** char_ptr = (char**) stack_ptr;
    // Add argv to stack
	{
		memset(--char_ptr, 0, sizeof(char**));
		for(int i = argc - 1; i > 0; --i)
		{
			*(--char_ptr) = argv[i];
		}
	}
	long* long_ptr = (long*) char_ptr;
	*(--long_ptr) = argc - 1;

	return (void*) long_ptr;
*/
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

    printf("se carga bien\n");

    //printf("PID: %d\n", getpid());

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

	void* stack_ptr = setup_stack(argv[1], (void*)handle->header.e_entry, argc2, argv2, envp);

    //printf("eSP: %p\n", (void*)stack_ptr);

    asm("movl %0, %%esp\n\t" : "+r" (stack_ptr));
	asm("movl %0, %%eax\n\t" : "+r" (handle->header.e_entry));
	//asm("movl $0, %edx");       // estos 2 registros se setean asi por la SYSTEM V APPLICATION BINARY INTERFACE Intel386 seccion 3.28 (pg. 55)
	//asm("movl $0, %ebp");
	asm("jmp *%eax\n\t");	
    
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