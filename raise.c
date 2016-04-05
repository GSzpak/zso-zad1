#include <elf.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ucontext.h>
#include <sys/mman.h>
#include <unistd.h>
#include <fcntl.h>


const int STANDARD_LOAD_ADDRESS = 0x8048000;
const int STACK_TOP_ADDRESS = 0x8000000;
volatile int context_changed = 0;
ucontext_t context;


void exit_with_error(const char *reason)
{
    fprintf(stderr, "%s", reason);
    exit(EXIT_FAILURE);
}

void read_elf_header(int core_file_descriptor, Elf32_Ehdr *elf_header)
{
    if (read(core_file_descriptor, elf_header, sizeof(Elf32_Ehdr)) == -1) {
        exit_with_error("Error while reading ELF header\n");
    }
    if (elf_header->e_type != ET_CORE) {
        exit_with_error("Error: not a CORE file\n");
    }
}

int open_core_file(char *file_path)
{
    int core_file_descriptor = open(file_path, O_RDONLY);
    if (core_file_descriptor == -1) {
        exit_with_error("Error while opening core file\n");
    }
    return core_file_descriptor;
}

void print(const char *text)
{
    char buf[256] = {0x0};
    int len = strlen(text);
    strcpy(buf, text);
    write(1, buf, len);
}

void read_pt_note_section(int core_file_descriptor, Elf32_Phdr *program_header)
{
    //print("Reading note section\n");
}

void read_pt_load_section(int core_file_descriptor, Elf32_Phdr *program_header)
{
    //print("Reading load section\n");
    void *memory_adress = (void *) program_header->p_vaddr;
    size_t memory_size = program_header->p_memsz;
    if (memory_size % getpagesize() != 0) {
        exit_with_error("No kurwa...\n");
    }
    int flags = program_header->p_flags;
    // TODO: add MAP_FIXED
    void *allocated_memory = mmap(memory_adress, memory_size, flags,
                                  MAP_FIXED | MAP_ANONYMOUS | MAP_PRIVATE,
                                  -1, 0);
    //printf("Requested: %p, received: %p\n", memory_adress, allocated_memory);
    if (allocated_memory == MAP_FAILED) {
        exit_with_error("Error in mmap\n");
    }
    lseek(core_file_descriptor, program_header->p_offset, SEEK_SET);
    read(core_file_descriptor, allocated_memory, memory_size);
}

void read_core_file(char *file_path)
{
    int core_file_descriptor_1 = open_core_file(file_path);
    int core_file_descriptor_2 = open_core_file(file_path);

    Elf32_Ehdr elf_header;
    Elf32_Phdr program_header;
    unsigned int i;

    read_elf_header(core_file_descriptor_1, &elf_header);

    for (i = 0; i < elf_header.e_phnum; ++i) {
        int read_result = read(core_file_descriptor_1,
                               &program_header, sizeof(Elf32_Phdr));
        if (read_result == -1) {
            exit_with_error("Error while reading program header\n");
        }
        switch (program_header.p_type) {
            case PT_LOAD:
                read_pt_load_section(core_file_descriptor_2, &program_header);
                break;
            case PT_NOTE:
                read_pt_note_section(core_file_descriptor_2, &program_header);
                break;
            default:
                break;
        }
    }

    close(core_file_descriptor_1);
    close(core_file_descriptor_2);
}

int main(int argc, char *argv[])
{
    getcontext(&context);
    if (!context_changed) {
        context_changed = 1;
        int stack_size = 2 * getpagesize();
        void *stack_bottom = (void *) (STACK_TOP_ADDRESS - stack_size);
        if (mmap(stack_bottom, stack_size, PROT_READ | PROT_WRITE,
             MAP_FIXED | MAP_ANONYMOUS | MAP_PRIVATE, -1, 0) == MAP_FAILED) {
            exit_with_error("Error in mmap\n");
        }
        context.uc_mcontext.gregs[REG_ESP] = STACK_TOP_ADDRESS - 16;
        setcontext(&context);
    }

    if (argc != 2) {
        exit_with_error("Usage: ./raise <core-file>\n");
    }

    read_core_file(argv[1]);

    //print("OK!\n");
    return 0;
}