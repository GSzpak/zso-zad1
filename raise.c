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

void read_elf_header(FILE *core_file, Elf32_Ehdr *elf_header)
{
    if (fread(elf_header, sizeof(Elf32_Ehdr), 1, core_file) != 1) {
        exit_with_error("Error while reading ELF header\n");
    }
    if (elf_header->e_type != ET_CORE) {
        exit_with_error("Error: not a CORE file\n");
    }
}

FILE *open_core_file(char *file_path)
{
    FILE *core_file = fopen(file_path, "r");
    if (core_file == NULL) {
        exit_with_error("Error while opening core file\n");
    }
    return core_file;
}

void read_pt_note_section(FILE *core_file, Elf32_Phdr *program_header)
{

}

void read_pt_load_section(File *core_file, Elf32_Phdr *program_header)
{
    void *memory_adress = program_header->p_addr;
    size_t memory_size = program_header->p_memsz;
    if (memory_size % getpagesize() != 0) {
        exit_with_error("No kurwa...\n");
    }
    int flags = program_header->p_flags;
    void *allocated_memory = mmap(memory_adress, memory_size, flags,
                                  MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    if (allocated_memory == MAP_FAILED) {
        exit_with_error("Error in mmap\n");
    }
    fseek(core_file, program_header->p_offset, SEEK_SET);
    fread(allocated_memory, memory_size, 1, core_file);
}

void read_core_file(char *file_path)
{
    FILE *core_file = open_core_file(file_path);
    File *core_file_copy = open_core_file(file_path);

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
                read_pt_load_section(core_file_copy, &program_header);
                break;
            case PT_NOTE:
                read_pt_note_section(core_file_copy, &program_header);
                break;
            default:
                break;
        }
    }

    fclose(core_file);
    fclose(core_file_copy);
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