#include <elf.h>
#include <stdio.h>
#include <stdlib.h>
#include <ucontext.h>
#include <sys/mman.h>
#include <unistd.h>


const int STANDARD_LOAD_ADDRESS = 0x8048000;
const int STACK_TOP_ADDRESS = 0x8000000;
volatile int context_changed = 0;
ucontext_t context;


void exit_with_error(const char *reason)
{
    fprintf(stderr, "%s", reason);
    exit(EXIT_FAILURE);
}

void read_pt_load_section(Elf32_Phdr *program_header)
{

}

void read_pt_note_section(Elf32_Phdr *program_header)
{

}

void read_elf_header(FILE *core_file, Elf32_Ehdr *elf_header)
{
    if (fread(elf_header, sizeof(Elf32_Ehdr), 1, core_file) != 1) {
        exit_with_error("Error while reading ELF header\n");
    }
    if (elf_header->e_type != ET_CORE) {
        exit_with_error("Error: not a CORE file\n");
    }
}

void read_core_file(char *file_path)
{
    FILE *core_file = fopen(file_path, "r");
    if (core_file == NULL) {
        exit_with_error("Error while opening core file\n");
    }


    Elf32_Ehdr elf_header;
    Elf32_Phdr program_header;
    unsigned int i;

    read_elf_header(core_file, &elf_header);

    for (i = 0; i < elf_header.e_phnum; ++i) {
        if (fread(&program_header, sizeof(Elf32_Phdr), 1, core_file) != 1) {
            exit_with_error("Error while reading program header\n");
        }
        switch (program_header.p_type) {
            case PT_LOAD:
                read_pt_load_section(&program_header);
                break;
            case PT_NOTE:
                read_pt_note_section(&program_header);
                break;
            default:
                break;
        }
    }

    fclose(core_file);
}

int main(int argc, char *argv[])
{
    getcontext(&context);
    if (!context_changed) {
        context_changed = 1;
        int stack_size = 2 * getpagesize();
        void *stack_bottom = (void *) (STACK_TOP_ADDRESS - stack_size);
        mmap(stack_bottom, stack_size, PROT_READ | PROT_WRITE,
             MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
        // TODO: check for error
        context.uc_mcontext.gregs[REG_ESP] = STACK_TOP_ADDRESS - 16;
        setcontext(&context);
    }

    if (argc != 2) {
        exit_with_error("Usage: ./raise <core-file>\n");
    }

    read_core_file(argv[1]);

    printf("OK!\n");
    return 0;
}