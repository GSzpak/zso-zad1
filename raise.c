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
#include <stdbool.h>
#include <asm/ldt.h>
#include <sys/syscall.h>
#include <sys/user.h>


#define MAX_CHAR_BUF_SIZE 80
#define MAX_NT_FILE_ENTRIES_NUM 1000
#define STACK_TOP_ADDRESS 0x8000000
#define INITIAL_STACK_SIZE_IN_PAGES 33



typedef struct {
    size_t name_size;
    size_t desc_size;
    int type;
} note_entry_header_t;

typedef struct {
    int number_of_entries;
    size_t page_size;
} nt_file_header_t;

typedef unsigned int addr_t;

typedef struct {
    addr_t start;
    addr_t end;
    off_t file_offset;
} nt_file_entry_header_t;

typedef struct {
    nt_file_entry_header_t header;
    char file_path[MAX_CHAR_BUF_SIZE];
} nt_file_entry_t;

typedef struct {
    nt_file_header_t header;
    nt_file_entry_t entries[MAX_NT_FILE_ENTRIES_NUM];
} nt_file_info_t;

typedef struct {
    struct elf_prstatus process_status;
    bool nt_prstatus_found;
    nt_file_info_t nt_file_info;
    struct user_desc *user_info;
    bool nt_386_tls_found;
} pt_note_info_t;


void exit_with_error(const char *reason)
{
    fprintf(stderr, "%s", reason);
    exit(EXIT_FAILURE);
}

static ucontext_t context;

void read_and_check_elf_header(int core_file_descriptor, Elf32_Ehdr *elf_header)
{
    //print("Checking file\n");
    if (read(core_file_descriptor, elf_header, sizeof(Elf32_Ehdr)) == -1) {
        exit_with_error("Error while reading ELF header\n");
    }
    if (elf_header->e_ident[EI_MAG0] != ELFMAG0 ||
            elf_header->e_ident[EI_MAG1] != ELFMAG1 ||
            elf_header->e_ident[EI_MAG2] != ELFMAG2 ||
            elf_header->e_ident[EI_MAG3] != ELFMAG3) {
        exit_with_error("Error: not an ELF file\n");
    }
    if (elf_header->e_machine != EM_386) {
        exit_with_error("Error: architecture different than Intel 80386\n");
    }
    if (elf_header->e_type != ET_CORE) {
        exit_with_error("Error: not a CORE file\n");
    }
    //print("Core file OK!\n");
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
    char buf[MAX_CHAR_BUF_SIZE] = {0x0};
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

size_t read_c_string(int file_descriptor, char *buffer)
{
    // Assumes, that buffer is big enough to fit the whole name
    size_t current_char_pos = 0;
    if (read(file_descriptor, buffer, sizeof(char)) == -1) {
        exit_with_error("Error while reading file name\n");
    }
    while (buffer[current_char_pos] != '\0') {
        ++current_char_pos;
        if (read(file_descriptor, buffer + current_char_pos, sizeof(char)) == -1) {
            exit_with_error("Error while reading file name\n");
        }
    }
    return current_char_pos;
}

void read_nt_file_section_entries(int core_file_descriptor,
                                  off_t *current_offset,
                                  nt_file_header_t *nt_file_header,
                                  nt_file_entry_t *nt_file_entries)
{
    int num_of_entries = nt_file_header->number_of_entries;
    //printf("num of entries: %d\n", num_of_entries);
    for (int i = 0; i < num_of_entries; ++i) {
        nt_file_entry_t *current_entry = nt_file_entries + i;
        int read_result = read(core_file_descriptor,
                               &current_entry->header,
                               sizeof(nt_file_entry_header_t));
        if (read_result == -1) {
            exit_with_error("Error while reading NT_FILE entry\n");
        }
        *current_offset += sizeof(nt_file_entry_header_t);
    }
    for (int i = 0; i < num_of_entries; ++i) {
        size_t name_length = read_c_string(core_file_descriptor,
                                           (nt_file_entries + i)->file_path);
        // Add one for trailing '\0' character
        *current_offset += (name_length + 1);
    }
}

void read_nt_file_section(int core_file_descriptor, off_t *current_offset,
                          nt_file_info_t *nt_file_info)
{
    nt_file_header_t *header = &nt_file_info->header;
    nt_file_entry_t *entries = nt_file_info->entries;
    int read_result = read(core_file_descriptor, header,
                           sizeof(nt_file_header_t));
    if (read_result == -1) {
        exit_with_error("Error while reading NT_FILE section header\n");
    }
    *current_offset += sizeof(nt_file_header_t);
    assert(header->page_size = getpagesize());
    read_nt_file_section_entries(core_file_descriptor, current_offset,
                                 header, entries);
}

void read_nt_prstatus_section(int core_file_descriptor, off_t *current_offset,
                              pt_note_info_t *pt_note_info)
{
    int read_result = read(core_file_descriptor, &pt_note_info->process_status,
                           sizeof(struct elf_prstatus));
    if (read_result == -1) {
        exit_with_error("Error while reading NT_PRSTATUS section\n");
    }
    *current_offset += sizeof(struct elf_prstatus);
    pt_note_info->nt_prstatus_found = true;
}

void read_nt_386_tls_section(int core_file_descriptor, off_t *current_offset,
                             pt_note_info_t *pt_note_info)
{
    int read_result = read(core_file_descriptor, &pt_note_info->user_info,
                           sizeof(struct user_desc));
    if (read_result == -1) {
        exit_with_error("Error while reading NT_386_TLS section\n");
    }
    // TODO: check on i386
    //*current_offset += sizeof(struct user_desc);
    pt_note_info->nt_386_tls_found = true;
}

void read_note_entry_descriptor(int core_file_descriptor, off_t *current_offset,
                                pt_note_info_t *pt_note_info,
                                note_entry_header_t *entry_header)
{
    off_t offset_before_reading_note_section = *current_offset;
    switch (entry_header->type) {
        case NT_FILE:
            //print("NT_FILE found\n");
            //printf("NT_FILE size: %p\n", entry_header->desc_size);
            read_nt_file_section(core_file_descriptor, current_offset,
                                 &pt_note_info->nt_file_info);
            break;
        case NT_PRSTATUS:
            //print("NT_PRSTATUS found\n");
            read_nt_prstatus_section(core_file_descriptor, current_offset,
                                     pt_note_info);
            break;
        case NT_386_TLS:
            //print("NT_386_TLS found\n");
            read_nt_386_tls_section(core_file_descriptor, current_offset,
                                    pt_note_info);
            // TODO: check on i386
            lseek(core_file_descriptor, entry_header->desc_size, SEEK_CUR);
            *current_offset += entry_header->desc_size;
            break;
        default:
            lseek(core_file_descriptor, entry_header->desc_size, SEEK_CUR);
            *current_offset += entry_header->desc_size;
            break;
    }
    // TODO: remove
    size_t nt_descriptor_size = *current_offset - offset_before_reading_note_section;
    assert(nt_descriptor_size == entry_header->desc_size);

    size_t descriptor_size = entry_header->desc_size;
    size_t desc_size_aligned_to_4 = aligned_to_4(descriptor_size);
    if (desc_size_aligned_to_4 > descriptor_size) {
        off_t to_seek = desc_size_aligned_to_4 - descriptor_size;
        lseek(core_file_descriptor, to_seek, SEEK_CUR);
        *current_offset += to_seek;
    }
}

// TODO: Check for lseek error

void read_note_entry(int core_file_descriptor, off_t *current_offset,
                     pt_note_info_t *pt_note_info)
{
    note_entry_header_t entry_header;
    if (read(core_file_descriptor, &entry_header, sizeof(entry_header)) == -1) {
        exit_with_error("Error while reading NOTE entry\n");
    }
    *current_offset += sizeof(entry_header);
    skip_note_entry_name(core_file_descriptor, entry_header.name_size,
                         current_offset);
    read_note_entry_descriptor(core_file_descriptor, current_offset,
                               pt_note_info, &entry_header);
}

void read_pt_note_segment(int core_file_descriptor, Elf32_Phdr *program_header,
                          pt_note_info_t *pt_note_info)
{
    //print("Reading note segment\n");
    lseek(core_file_descriptor, program_header->p_offset, SEEK_SET);
    off_t current_offset = 0;
    size_t note_section_size = program_header->p_filesz;
    while (current_offset < note_section_size) {
        read_note_entry(core_file_descriptor, &current_offset, pt_note_info);
    }
}

// TODO: files not entirely in PT_LOAD?
void map_files_in_interval(nt_file_info_t *nt_file_info,
                           Elf32_Phdr *pt_load_header)
{
    size_t page_size = nt_file_info->header.page_size;
    int number_of_files = nt_file_info->header.number_of_entries;
    nt_file_entry_t *file_entries = nt_file_info->entries;
    addr_t start_addr = (addr_t) pt_load_header->p_vaddr;
    addr_t end_addr = start_addr + pt_load_header->p_memsz;
    //printf("%p, %p\n", start_addr, end_addr);
    for (int i = 0; i < number_of_files; ++i) {
        nt_file_entry_header_t *current_file_info = &((file_entries + i)->header);
        if (current_file_info->start >= start_addr &&
                current_file_info->start < end_addr) {
            //printf("\t%p, %p\n", current_file_info->start, current_file_info->end);
            //puts((file_entries + i)->file_path);
            assert(current_file_info->end <= end_addr);
            int file_descriptor = open((file_entries + i)->file_path, O_RDONLY);
            if (file_descriptor == -1) {
                // TODO: support passing many arguments
                print((file_entries + i)->file_path);
                exit_with_error("Error while opening file\n");
            }
            size_t memory_size = current_file_info->end - current_file_info->start;
            int protection_flags = pt_load_header->p_flags;
            int flags = MAP_FIXED | MAP_PRIVATE;
            off_t file_offset = page_size * current_file_info->file_offset;
            void *result_addr = mmap((void *) current_file_info->start,
                                     memory_size, protection_flags, flags,
                                     file_descriptor, file_offset);
            if (result_addr == MAP_FAILED) {
                exit_with_error("Error in mmap\n");
            }
            // TODO: remove
            if (result_addr != (void *) current_file_info->start) {
                exit_with_error("No kurwa\n");
            }
        }
    }
}

void read_pt_load_segment(int core_file_descriptor, Elf32_Phdr *pt_load_header,
                          nt_file_info_t *nt_file_info)
{
    //print("Reading load segment\n");
    void *memory_adress = (void *) pt_load_header->p_vaddr;
    size_t memory_size = pt_load_header->p_memsz;

    // TODO: remove
    if (memory_size % getpagesize() != 0) {
        exit_with_error("No kurwa...\n");
    }

    int flags = MAP_FIXED | MAP_ANONYMOUS | MAP_PRIVATE;
    void *allocated_memory = mmap(memory_adress, memory_size,
                                  pt_load_header->p_flags, flags,
                                  -1, 0);
    //printf("Requested: %p, received: %p\n", memory_adress, allocated_memory);
    if (allocated_memory == MAP_FAILED) {
        exit_with_error("Error in mmap\n");
    }
    map_files_in_interval(nt_file_info, pt_load_header);
    if (pt_load_header->p_filesz == 0) {
        // Read-only mapped file - already read from PT_NOTE section
        return;
    }
    // TODO: check lseek and read
    lseek(core_file_descriptor, pt_load_header->p_offset, SEEK_SET);
    read(core_file_descriptor, allocated_memory, memory_size);
}

void set_register_values_and_change_context(struct user_regs_struct *user_regs)
{
    /*
    getcontext(&context);
    //printf("%p\n", context.uc_mcontext.gregs[REG_EBX]);
    //printf("%p\n", context.uc_mcontext.gregs[REG_EBX]);
    context.uc_mcontext.gregs[REG_EAX] = user_regs->eax;
    context.uc_mcontext.gregs[REG_ECX] = user_regs->ecx;
    context.uc_mcontext.gregs[REG_EDX] = user_regs->edx;
    context.uc_mcontext.gregs[REG_EBX] = user_regs->ebx;
    context.uc_mcontext.gregs[REG_ESP] = user_regs->esp;
    context.uc_mcontext.gregs[REG_EBP] = user_regs->ebp;
    context.uc_mcontext.gregs[REG_ESI] = user_regs->esi;
    context.uc_mcontext.gregs[REG_EDI] = user_regs->edi;
    context.uc_mcontext.gregs[REG_EIP] = user_regs->eip;
    context.uc_mcontext.gregs[REG_EFL] = user_regs->eflags;
    setcontext(&context);
     */
}

void read_core_file(char *file_path)
{
    int core_file_descriptor = open_core_file(file_path);

    Elf32_Ehdr elf_header;
    Elf32_Phdr program_header;
    pt_note_info_t pt_note_info = {
            .nt_prstatus_found = false,
            .nt_386_tls_found = false,
            .nt_file_info.header.number_of_entries = 0
        };
    int read_result;
    off_t current_offset;
    bool pt_note_successfully_read = false;

    read_and_check_elf_header(core_file_descriptor, &elf_header);

    for (int i = 0; i < elf_header.e_phnum; ++i) {
        read_result = read(core_file_descriptor,
                           &program_header, sizeof(Elf32_Phdr));
        if (read_result == -1) {
            exit_with_error("Error while reading program header\n");
        }
        current_offset = lseek(core_file_descriptor, 0, SEEK_CUR);
        switch (program_header.p_type) {
            case PT_NOTE:
                read_pt_note_segment(core_file_descriptor, &program_header,
                                     &pt_note_info);
                pt_note_successfully_read = true;
                break;
            case PT_LOAD:
                if (!pt_note_successfully_read) {
                    exit_with_error("PT_LOAD occured before PT_NOTE\n");
                }
                read_pt_load_segment(core_file_descriptor, &program_header,
                                     &pt_note_info.nt_file_info);
                break;
            default:
                break;
        }
        lseek(core_file_descriptor, current_offset, SEEK_SET);
    }

    close(core_file_descriptor);

    if (!pt_note_info.nt_prstatus_found) {
        exit_with_error("NT_PRSTATUS section not found in core file\n");
    }
    if (!pt_note_info.nt_386_tls_found) {
        exit_with_error("NT_386_TLS section not found in core file\n");
    }
    if (syscall(SYS_set_thread_area, &pt_note_info.user_info) == -1) {
        exit_with_error("Error while calling set_thread_area\n");
    }

    // TODO: small refactor
    assert(sizeof(struct user_regs_struct) == sizeof(pt_note_info.process_status.pr_reg));
    struct user_regs_struct user_regs;
    // TODO: check result
    memcpy(&user_regs, pt_note_info.process_status.pr_reg,
           sizeof(struct user_regs_struct));
    //printf("%p %p\n", user_regs.ebx, pt_note_info.process_status.pr_reg[0]);
    set_register_values_and_change_context(&user_regs);

    //print("OK!\n");
}

int main(int argc, char *argv[])
{
    if (argc != 2) {
        exit_with_error("Usage: ./raise <core-file>\n");
    }
    // TODO: sizeofs
    getcontext(&context);
    context.uc_stack.ss_sp = mmap(
            (void *) (STACK_TOP_ADDRESS - INITIAL_STACK_SIZE_IN_PAGES * getpagesize()),
            INITIAL_STACK_SIZE_IN_PAGES * getpagesize(),
            PROT_READ | PROT_WRITE,
            MAP_GROWSDOWN | MAP_FIXED | MAP_ANONYMOUS | MAP_PRIVATE,
            -1, 0);
    if (context.uc_stack.ss_sp == MAP_FAILED) {
        exit_with_error("Error in mmap\n");
    }
    context.uc_stack.ss_size = INITIAL_STACK_SIZE_IN_PAGES * getpagesize();
    context.uc_link = NULL;
    makecontext(&context, (void (*)()) read_core_file, 1, argv[1]);
    setcontext(&context);

    return 0;
}