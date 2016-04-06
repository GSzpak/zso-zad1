#include <elf.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ucontext.h>
#include <sys/mman.h>
#include <sys/procfs.h>
#include <unistd.h>
#include <fcntl.h>
#include <assert.h>


const int STANDARD_LOAD_ADDRESS = 0x8048000;
const int STACK_TOP_ADDRESS = 0x8000000;
volatile int context_changed = 0;
ucontext_t context;

typedef struct {
    size_t name_size;
    size_t desc_size;
    int type;
} note_entry_header_t;

typedef unsigned int addr_t;

typedef struct {
    int number_of_entries;
    size_t page_size;
} nt_file_header;

typedef struct {
    addr_t start;
    addr_t end;
    off_t file_offset;
} nt_file_entry_header_t;


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



unsigned int aligned_to_4(unsigned int val)
{
    unsigned int val_mod_4 = val % 4;
    return val_mod_4 == 0 ? val : val + (4 - val_mod_4);
}

void skip_note_entry_name(int core_file_descriptor, size_t name_size,
                          off_t *current_offset)
{
    off_t name_aligned_to_4_bytes = aligned_to_4(name_size);
    lseek(core_file_descriptor, name_aligned_to_4_bytes, SEEK_CUR);
    *current_offset += name_aligned_to_4_bytes;
}

void read_descriptor_aligned_to_4(int core_file_descriptor,
                                  off_t *current_offset,
                                  void *buffer, size_t descriptor_size)
{
    if (read(core_file_descriptor, buffer, descriptor_size) == -1) {
        exit_with_error("Error while reading NOTE section descriptor\n");
    }

    *current_offset += desc_size_aligned_to_4;
}

void read_nt_file_section(int core_file_descriptor, off_t *current_offset)
{
    nt_file_header_t nt_file_header;
    
}

void read_note_descriptor(int core_file_descriptor, off_t *current_offset,
                          note_entry_header_t *entry_header)
{
    off_t offset_before_reading_note_section = *current_offset;
    switch (entry_header->type) {
        case NT_FILE:
            print("NT_FILE found\n");
            read_nt_file_section(core_file_descriptor, current_offset);
            break;
        case NT_PRSTATUS:
            print("NT_PRSTATUS found\n");
            //struct elf_prstatus process_status;
            break;
        case NT_386_TLS:
            print("NT_386_TLS found\n");
            break;
        default:
            break;
    }
    // TODO: remove
    size_t nt_descriptor_size = *current_offset - offset_before_reading_note_section;
    assert(nt_descriptor_size == entry_header->desc_size);
    size_t descriptor_size = entry_header->desc_size;
    size_t desc_size_aligned_to_4 = aligned_to_4(descriptor_size);
    if (desc_size_aligned_to_4 > descriptor_size) {
        off_t to_seek = desc_size_aligned_to_4 - descriptor_size
        lseek(core_file_descriptor, to_seek, SEEK_CUR);
        *current_offset += to_seek;
    }
}

// TODO: Check for lseek error
void read_note_entry(int core_file_descriptor, off_t *current_offset)
{
    note_entry_header_t entry_header;
    if (read(core_file_descriptor, &entry_header, sizeof(entry_header)) == -1) {
        exit_with_error("Error while reading NOTE entry\n");
    }
    *current_offset += sizeof(entry_header);
    skip_note_entry_name(core_file_descriptor, entry_header.name_size,
                         current_offset);
    read_note_descriptor(core_file_descriptor, current_offset, &entry_header);
}

void read_pt_note_section(int core_file_descriptor, Elf32_Phdr *program_header)
{
    print("Reading note section\n");
    lseek(core_file_descriptor, program_header->p_offset, SEEK_SET);
    off_t current_offset = 0;
    size_t note_section_size = program_header->p_filesz;
    while (current_offset < note_section_size) {
        read_note_entry(core_file_descriptor, &current_offset);
    }
}

void read_pt_load_section(int core_file_descriptor, Elf32_Phdr *program_header)
{
    print("Reading load section\n");
    if (program_header->p_filesz == 0) {
        // Read-only mapped file - read from PT_NOTE section
        return;
    }
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
            case PT_NOTE:
                read_pt_note_section(core_file_descriptor_2, &program_header);
                break;
            case PT_LOAD:
                read_pt_load_section(core_file_descriptor_2, &program_header);
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