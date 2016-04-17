#ifndef RAISE_UTILS_H
#define RAISE_UTILS_H


void exit_with_error(const char *reason);
void *checked_mmap(void *addr, size_t length, int prot, int flags,
                   int fd, off_t offset);
void checked_read(int fd, void *buf, size_t count);
off_t checked_lseek(int fd, off_t offset, int whence);
unsigned int aligned_to_4(unsigned int val);
size_t read_c_string(int file_descriptor, char *buffer);

#endif // RAISE_UTILS_H
