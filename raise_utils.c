#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>


void exit_with_error(const char *reason)
{
    write(STDERR_FILENO, reason, strlen(reason));
    exit(EXIT_FAILURE);
}

void *checked_mmap(void *addr, size_t length, int prot, int flags,
                   int fd, off_t offset)
{
    void *result = mmap(addr, length, prot, flags, fd, offset);
    if (result == MAP_FAILED) {
        exit_with_error("Error while calling mmap\n");
    }
    return result;
}

void checked_read(int fd, void *buf, size_t count)
{
    if (read(fd, buf, count) != count) {
        exit_with_error("Error while calling read\n");
    }
}

off_t checked_lseek(int fd, off_t offset, int whence)
{
    off_t result = lseek(fd, offset, whence);
    if (result == (off_t) -1) {
        exit_with_error("Error in lseek\n");
    }
    return result;
}

unsigned int aligned_to_4(unsigned int val)
{
    unsigned int val_mod_4 = val % 4;
    return val_mod_4 == 0 ? val : val + (4 - val_mod_4);
}

size_t read_c_string(int file_descriptor, char *buffer)
{
    // Assumes, that buffer is big enough to fit the whole name
    // Returns length of read string
    size_t current_char_pos = 0;
    checked_read(file_descriptor, buffer, sizeof(char));
    while (buffer[current_char_pos] != '\0') {
        ++current_char_pos;
        checked_read(file_descriptor, buffer + current_char_pos, sizeof(char));
    }
    return current_char_pos;
}
