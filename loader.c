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

struct SymbolHelper {
    char* name;                 // este estaria dado por StringTable[st_name]
    unsigned int addr;          // este por st_value

    enum Type type;
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


unsigned int get_addr_of_symbol(struct ElfHandle* handle, const char* symbol_name) {
    for (size_t i = 0; i < handle->symbol_handle->number_of_symbols; i++) {
        struct SymbolHelper* sym = handle->symbol_handle->symbols + i;
        if (strcmp(sym->name, symbol_name) == 0) {
            return sym->addr;
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

            //printf("number_of_entries_in_symbol_table: %zu\n", number_of_entries_in_symbol_table);

            // primero nos tenemos que traer a memoria la section en si
            fseek(handle->fptr, sh.sh_offset, SEEK_SET);

            size_t bytes_read_section = 0;

            //Elf32_Sym symtab[number_of_entries_in_symbol_table];
            handle->symbol_table = malloc(number_of_entries_in_symbol_table * sizeof(Elf32_Sym));

            for (size_t j = 0; j < number_of_entries_in_symbol_table; j++) {
                //bytes_read_section = fread(&symtab[j], sh.sh_entsize, 1, handle->fptr);
                bytes_read_section = fread(handle->symbol_table + j, sh.sh_entsize, 1, handle->fptr);
                assert(bytes_read_section == 1);
            }
            
            //ahora podemos iterar sobre las entries de la section (cada una sera de tipo Elf32_Sym)
            /*
            for (size_t j = 0; j < number_of_entries_in_symbol_table; j++) {
                Elf32_Sym* st_entry = handle->symbol_table + j;
                printf("st_name: %s\n", handle->string_table_symbols + st_entry->st_name);
                printf("st_value: %p\n", (void*)st_entry->st_value);
                printf("---------\n");
            }
            */

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

                handle->symbol_handle->symbols[j] = (struct SymbolHelper){.name =  handle->string_table_symbols + st_entry->st_name,
                                                                          .addr = st_entry->st_value,
                                                                          .type = type};



            }


            break;
        }
    }
}
/*
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
*/

struct SymbolHandle sym_hdle;


void print_symbol_table(struct ElfHandle* handle) {
    printf("Symbol table '.symtab' contains %d entries:\n",8);
    printf("Num:       Value         Size      Type      Bind     Vis      Ndx    Name\n");
    // the first entry is reserved, and it looks like this:
    printf("0   0x00000000    0    NOTYPE     LOCAL    DEFAULT   UND\n");
    for(size_t i = 1; i < 8; i++) {
        Elf32_Sym* st_entry = handle->symbol_table + i;
        printf("%d", i);
/*
        if (i == 2) {
            size_t len = strlen(handle->string_table_symbols + st_entry->st_name);
            char* name = malloc(len+1);
            memcpy(name, handle->string_table_symbols + st_entry->st_name, len);
            sym_hdle = (struct SymbolHandle){.name = name , .addr = st_entry->st_value};
        }
        */

        if (st_entry->st_value == 0) {
            printf("     0x00000000");
        } else {
            printf("     %p", st_entry->st_value);
        }

        printf("                %d", st_entry->st_size);

        switch (ELF32_ST_BIND(st_entry->st_info)) {
            case 0:
                printf("            LOCAL");
                break;
            case 1:
                printf("            GLOBAL");
                break;
            case 2:
                printf("            WEAK");
                break;
            case 13:
                printf("            LOPROC");
                break;
            case 15:
                printf("            HIPROC");
                break;
        }

        switch (ELF32_ST_TYPE(st_entry->st_info)) {
            case 0:
                printf("            NOTYPE");
                break;
            case 1:
                printf("            OBJECT");
                break;
            case 2:
                printf("            FUNC");
                break;
            case 3:
                printf("            SECTION");
                break;
            case 4:
                printf("            FILE");
                break;
            case 13:
                printf("            LOPROC");
                break;
            case 15:
                printf("            HIPROC");
                break;
        }

        switch (st_entry->st_shndx) {
            case 0:
                printf("                    UND");
                break;
            case 0xfff1:
                printf("                    ABS");
                break;
            case 0xfff2:
                printf("                    COMMON");
                break;
            default:
                printf("                    %d", st_entry->st_shndx);
        }

        printf("              %s", handle->string_table_symbols + st_entry->st_name);

        printf("\n");
    }
    printf("\n");
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


    return handle;
}

void free_elf_handle(struct ElfHandle* handle) {        // TODO: fclose y free symbol table
    free(handle->program_header_table);
    handle->program_header_table = NULL;
    free(handle->section_header_table);
    handle->section_header_table = NULL;
    free(handle);
    handle = NULL;
}

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

    void* ptr_to_exec_mem = mmap((void*)ph->p_vaddr, ph->p_memsz,
                                prot,
                                MAP_PRIVATE, 
                                fd,
                                ph->p_offset);

    if (ptr_to_exec_mem == MAP_FAILED) {
        printf("mmap failed: %s\n", strerror(errno));
        //printf("(void*)ph->p_vaddr que rompe: %p\n", (void*)ph->p_vaddr);
    }

    return ptr_to_exec_mem;
}

void load_elf(struct ElfHandle* handle) {
    for (size_t i = 0; i < handle->header.e_phnum; i++) {
        load_segment(&(handle->program_header_table[i]), handle->fptr);
    }
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

    // lo cargamos
    load_elf(handle);

    //printf("PID: %d\n", getpid());

    // lo ejecutamos

    //void (*start)(void);
    //start = (void(*)(void))(handle->header.e_entry);
    //start();
    
    build_symbol_table(handle);

    print_symbol_table(handle);

    //printf("sym_hdle: NAME: %s, ADDR: %p\n", sym_hdle.name, (void*)sym_hdle.addr);

    
    // ejecutamos f:
    void (*f)(int, int);
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

    unsigned int addr = get_addr_of_symbol(handle, "f");

    f = (void (*)(int, int))(addr);
           
    //f(2, 1); 

    unsigned int addr_c = get_addr_of_symbol(handle, "c");

    printf("ADDR of c : %p\n", (void*)addr_c);
    




    free_elf_handle(handle);
}