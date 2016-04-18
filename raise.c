#include <asm/ldt.h>
#include <assert.h>
#include <fcntl.h>
#include <elf.h>
#include <stdbool.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/procfs.h>
#include <sys/syscall.h>
#include <sys/user.h>
#include <ucontext.h>

#include "raise_utils.h"


#define DEFAULT_LOAD_ADDRESS 0x8048000
#define USER_SPACE_END 0xc0000000
#define MAX_CHAR_BUF_SIZE 128
#define MAX_NT_FILE_ENTRIES_NUM 1000
#define STACK_TOP_ADDRESS 0x8000000
#define INITIAL_STACK_SIZE_IN_PAGES 33
#define SET_REGISTERS_CODE_ADDRESS 0x8001000


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
    struct user_desc user_info;
    bool nt_386_tls_found;
} pt_note_info_t;


unsigned char set_registers_template[] = {
    0xb8, 0x0, 0x0, 0x0, 0x0,       // mov eax,<val>
    0xb9, 0x0, 0x0, 0x0, 0x0,       // mov ecx,<val>
    0xba, 0x0, 0x0, 0x0, 0x0,       // mov edx,<val>
    0xbb, 0x0, 0x0, 0x0, 0x0,       // mov ebx,<val>
    0xbc, 0x0, 0x0, 0x0, 0x0,       // mov esp,<val>
    0xbd, 0x0, 0x0, 0x0, 0x0,       // mov ebp,<val>
    0xbe, 0x0, 0x0, 0x0, 0x0,       // mov esi,<val>
    0xbf, 0x0, 0x0, 0x0, 0x0,       // mov edi,<val>
    0x68, 0x0, 0x0, 0x0, 0x0,       // push <val>
    0x9d,                           // popf
    0x68, 0x0, 0x0, 0x0, 0x0,       // push <val>
    0xc3                            // ret
};

static ucontext_t context;
static char core_file_path[MAX_CHAR_BUF_SIZE];


void read_and_check_elf_header(int core_file_descriptor, Elf32_Ehdr *elf_header)
{
    checked_read(core_file_descriptor, elf_header, sizeof(Elf32_Ehdr));
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
}

int open_core_file(char *file_path)
{
    int core_file_descriptor = open(file_path, O_RDONLY);
    if (core_file_descriptor == -1) {
        exit_with_error("Error while opening core file\n");
    }
    return core_file_descriptor;
}

size_t read_nt_file_section_entries(int core_file_descriptor,
                                    nt_file_header_t *nt_file_header,
                                    nt_file_entry_t *nt_file_entries)
{
    int num_of_entries = nt_file_header->number_of_entries;
    size_t bytes_read = 0;

    for (int i = 0; i < num_of_entries; ++i) {
        nt_file_entry_t *current_entry = nt_file_entries + i;
        checked_read(core_file_descriptor, &current_entry->header,
                     sizeof(nt_file_entry_header_t));
        bytes_read += sizeof(nt_file_entry_header_t);
    }
    for (int i = 0; i < num_of_entries; ++i) {
        size_t name_length = read_c_string(core_file_descriptor,
                                           (nt_file_entries + i)->file_path);
        // Add one for trailing '\0' character
        bytes_read += (name_length + 1);
    }
    return bytes_read;
}

size_t read_nt_file_section(int core_file_descriptor,
                            nt_file_info_t *nt_file_info)
{
    size_t bytes_read = 0;
    nt_file_header_t *header = &nt_file_info->header;
    nt_file_entry_t *entries = nt_file_info->entries;
    checked_read(core_file_descriptor, header, sizeof(nt_file_header_t));
    bytes_read += sizeof(nt_file_header_t);
    bytes_read += read_nt_file_section_entries(core_file_descriptor, header, entries);
    return bytes_read;
}

size_t read_nt_prstatus_section(int core_file_descriptor,
                                pt_note_info_t *pt_note_info)
{
    size_t bytes_read = 0;
    checked_read(core_file_descriptor, &pt_note_info->process_status,
                 sizeof(struct elf_prstatus));
    bytes_read += sizeof(struct elf_prstatus);
    pt_note_info->nt_prstatus_found = true;
    return bytes_read;
}

size_t read_nt_386_tls_section(int core_file_descriptor,
                               pt_note_info_t *pt_note_info,
                               size_t section_size)
{
    size_t bytes_read = 0;
    checked_read(core_file_descriptor, &pt_note_info->user_info,
                 sizeof(struct user_desc));
    bytes_read += sizeof(struct user_desc);
    pt_note_info->nt_386_tls_found = true;
    // As there was only one thread, skip the rest of the section
    size_t to_seek = section_size - sizeof(struct user_desc);
    checked_lseek(core_file_descriptor, to_seek, SEEK_CUR);
    bytes_read += to_seek;
    return bytes_read;
}

size_t read_note_entry_descriptor(int core_file_descriptor,
                                  pt_note_info_t *pt_note_info,
                                  note_entry_header_t *entry_header)
{
    size_t bytes_read = 0;
    switch (entry_header->type) {
        case NT_FILE:
            bytes_read += read_nt_file_section(core_file_descriptor,
                                               &pt_note_info->nt_file_info);
            break;
        case NT_PRSTATUS:
            bytes_read += read_nt_prstatus_section(core_file_descriptor,
                                                   pt_note_info);
            break;
        case NT_386_TLS:
            bytes_read += read_nt_386_tls_section(core_file_descriptor,
                                                  pt_note_info,
                                                  entry_header->desc_size);
            break;
        default:
            // Skip the section
            checked_lseek(core_file_descriptor, entry_header->desc_size, SEEK_CUR);
            bytes_read += entry_header->desc_size;
            break;
    }
    size_t descriptor_size = entry_header->desc_size;
    size_t desc_size_aligned_to_4 = aligned_to_4(descriptor_size);
    if (desc_size_aligned_to_4 > descriptor_size) {
        off_t to_seek = desc_size_aligned_to_4 - descriptor_size;
        checked_lseek(core_file_descriptor, to_seek, SEEK_CUR);
        bytes_read += to_seek;
    }
    return bytes_read;
}

size_t skip_note_entry_name(int core_file_descriptor, size_t name_size)
{
    off_t name_aligned_to_4_bytes = aligned_to_4(name_size);
    checked_lseek(core_file_descriptor, name_aligned_to_4_bytes, SEEK_CUR);
    return (size_t) name_aligned_to_4_bytes;
}


size_t read_note_entry(int core_file_descriptor, pt_note_info_t *pt_note_info)
{
    size_t bytes_read = 0;
    note_entry_header_t entry_header;
    checked_read(core_file_descriptor, &entry_header,
                 sizeof(note_entry_header_t));
    bytes_read += sizeof(note_entry_header_t);
    bytes_read += skip_note_entry_name(core_file_descriptor,
                                       entry_header.name_size);
    bytes_read += read_note_entry_descriptor(core_file_descriptor, pt_note_info,
                                             &entry_header);
    return bytes_read;
}

void read_pt_note_segment(int core_file_descriptor, Elf32_Phdr *program_header,
                          pt_note_info_t *pt_note_info)
{
    checked_lseek(core_file_descriptor, program_header->p_offset, SEEK_SET);
    off_t current_offset = 0;
    size_t note_section_size = program_header->p_filesz;
    while (current_offset < note_section_size) {
         current_offset += read_note_entry(core_file_descriptor,
                                           pt_note_info);
    }
}

void map_files_in_interval(nt_file_info_t *nt_file_info,
                           Elf32_Phdr *pt_load_header)
{
    size_t page_size = nt_file_info->header.page_size;
    int number_of_files = nt_file_info->header.number_of_entries;
    nt_file_entry_t *file_entries = nt_file_info->entries;
    addr_t start_addr = (addr_t) pt_load_header->p_vaddr;
    addr_t end_addr = start_addr + pt_load_header->p_memsz;
    for (int i = 0; i < number_of_files; ++i) {
        nt_file_entry_header_t *current_file_info = &((file_entries + i)->header);
        if (current_file_info->start >= start_addr &&
                current_file_info->start < end_addr) {
            assert(current_file_info->end <= end_addr);
            int file_descriptor = open((file_entries + i)->file_path, O_RDONLY);
            if (file_descriptor == -1) {
                exit_with_error("Error while opening mapped file\n");
            }
            size_t memory_size = current_file_info->end - current_file_info->start;
            off_t file_offset = page_size * current_file_info->file_offset;
            checked_mmap((void *) current_file_info->start,
                         memory_size, PROT_WRITE,
                         MAP_FIXED | MAP_PRIVATE,
                         file_descriptor, file_offset);
            close(file_descriptor);
        }
    }
}

void set_memory_protection(void *address, size_t size, int flags_from_pt_load)
{
    int flags = PROT_NONE;
    // OS- and processor-specific flags
    flags |= flags_from_pt_load & (PF_MASKOS | PF_MASKPROC);
    if (flags_from_pt_load & PF_R) {
        flags |= PROT_READ;
    }
    if (flags_from_pt_load & PF_W) {
        flags |= PROT_WRITE;
    }
    if (flags_from_pt_load & PF_X) {
        flags |= PROT_EXEC;
    }
    if (mprotect(address, size, flags) != 0) {
        exit_with_error("Error in mprotect\n");
    }
}

void read_pt_load_segment(int core_file_descriptor, Elf32_Phdr *pt_load_header,
                          nt_file_info_t *nt_file_info)
{
    void *memory_adress = (void *) pt_load_header->p_vaddr;
    size_t memory_size = pt_load_header->p_memsz;
    size_t size_to_copy = pt_load_header->p_filesz;

    void *allocated_memory = checked_mmap(memory_adress, memory_size,
                                          PROT_WRITE,
                                          MAP_FIXED | MAP_ANONYMOUS | MAP_PRIVATE,
                                          -1, 0);
    map_files_in_interval(nt_file_info, pt_load_header);
    if (size_to_copy != 0) {
        checked_lseek(core_file_descriptor, pt_load_header->p_offset, SEEK_SET);
        checked_read(core_file_descriptor, allocated_memory, size_to_copy);
    }
    set_memory_protection(memory_adress, memory_size, pt_load_header->p_flags);
}

void copy_register_val(long int *reg, void *base_address, off_t offset)
{
    void *destination_address = (void *) ((unsigned char *) base_address + offset);
    memcpy(destination_address, reg, sizeof(long int));
}

void set_register_values_and_jump(struct elf_prstatus *process_status)
{
    struct user_regs_struct user_regs;

    assert(sizeof(struct user_regs_struct) == sizeof(process_status->pr_reg));
    // Just to make the code slightly more readable
    memcpy(&user_regs, process_status->pr_reg, sizeof(struct user_regs_struct));
    void *set_registers_addr = checked_mmap((void *) SET_REGISTERS_CODE_ADDRESS,
                                            getpagesize(),
                                            PROT_READ | PROT_WRITE | PROT_EXEC,
                                            MAP_FIXED | MAP_ANONYMOUS | MAP_PRIVATE,
                                            -1, 0);
    memcpy(set_registers_addr, set_registers_template,
           sizeof(set_registers_template));
    copy_register_val(&user_regs.eax, set_registers_addr, 1);
    copy_register_val(&user_regs.ecx, set_registers_addr, 6);
    copy_register_val(&user_regs.edx, set_registers_addr, 11);
    copy_register_val(&user_regs.ebx, set_registers_addr, 16);
    copy_register_val(&user_regs.esp, set_registers_addr, 21);
    copy_register_val(&user_regs.ebp, set_registers_addr, 26);
    copy_register_val(&user_regs.esi, set_registers_addr, 31);
    copy_register_val(&user_regs.edi, set_registers_addr, 36);
    copy_register_val(&user_regs.eflags, set_registers_addr, 41);
    copy_register_val(&user_regs.eip, set_registers_addr, 47);
    void (*set_registers)(void) = (void (*)(void)) set_registers_addr;
    set_registers();
}

bool find_and_read_pt_note(int core_file_descriptor, Elf32_Ehdr *elf_header,
                           pt_note_info_t *pt_note_info)
{
    // Returns true iff PT_NOTE segment was read successfully
    Elf32_Phdr program_header;
    for (int i = 0; i < elf_header->e_phnum; ++i) {
        checked_read(core_file_descriptor, &program_header, sizeof(Elf32_Phdr));
        if (program_header.p_type == PT_NOTE) {
            read_pt_note_segment(core_file_descriptor, &program_header,
                                 pt_note_info);
            return true;
        }
    }
    return false;
}

void read_core_file()
{
    // Clear memory above default load address
    munmap((void *) DEFAULT_LOAD_ADDRESS, USER_SPACE_END - DEFAULT_LOAD_ADDRESS);

    int core_file_descriptor = open_core_file(core_file_path);

    Elf32_Ehdr elf_header;
    Elf32_Phdr program_header;
    pt_note_info_t pt_note_info = {
            .nt_prstatus_found = false,
            .nt_386_tls_found = false,
            .nt_file_info.header.number_of_entries = 0
        };
    off_t current_offset;

    read_and_check_elf_header(core_file_descriptor, &elf_header);

    current_offset = checked_lseek(core_file_descriptor, 0, SEEK_CUR);
    if (!find_and_read_pt_note(core_file_descriptor, &elf_header, &pt_note_info)) {
        exit_with_error("PT_NOTE not found in core file\n");
    }
    checked_lseek(core_file_descriptor, current_offset, SEEK_SET);

    for (int i = 0; i < elf_header.e_phnum; ++i) {
        checked_read(core_file_descriptor, &program_header, sizeof(Elf32_Phdr));
        current_offset = checked_lseek(core_file_descriptor, 0, SEEK_CUR);
        if (program_header.p_type == PT_LOAD) {
            read_pt_load_segment(core_file_descriptor, &program_header,
                                 &pt_note_info.nt_file_info);
        }
        checked_lseek(core_file_descriptor, current_offset, SEEK_SET);
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
    set_register_values_and_jump(&pt_note_info.process_status);
}

int main(int argc, char *argv[])
{
    if (argc != 2) {
        exit_with_error("Usage: ./raise <core-file>\n");
    }
    strcpy(core_file_path, argv[1]);

    getcontext(&context);
    // Prepare new stack
    context.uc_stack.ss_sp = checked_mmap(
            (void *) (STACK_TOP_ADDRESS - INITIAL_STACK_SIZE_IN_PAGES * getpagesize()),
            INITIAL_STACK_SIZE_IN_PAGES * getpagesize(),
            PROT_READ | PROT_WRITE,
            MAP_GROWSDOWN | MAP_FIXED | MAP_ANONYMOUS | MAP_PRIVATE,
            -1, 0);
    context.uc_stack.ss_size = INITIAL_STACK_SIZE_IN_PAGES * getpagesize();
    context.uc_link = NULL;
    makecontext(&context, read_core_file, 0);
    setcontext(&context);

    return 0;
}