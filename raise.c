#include <elf.h>
#include <stdio.h>
#include <stdlib.h>
#include <ucontext.h>
#include <sys/mman.h>
#include <unistd.h>


const int STANDARD_LOAD_ADDRESS = 0x8048000;
const int STACK_TOP_ADDRESS = 0x8000000;
volatile int contextChanged = 0;
ucontext_t context;


void exitWithError(const char *reason)
{
    fprintf(stderr, "%s", reason);
    exit(EXIT_FAILURE);
}

int main(int argc, char *argv[])
{
    getcontext(&context);
    if (!contextChanged) {
        printf("Changing context\n");
        contextChanged = 1;
        int stackSize = 2 * getpagesize();
        void *stackBottom = (void *) (STACK_TOP_ADDRESS - stackSize);
        void *_addr = mmap(stackBottom, stackSize,
                           PROT_READ | PROT_WRITE,
                           MAP_ANONYMOUS | MAP_PRIVATE,
                           -1, 0);
        // TODO: check for error
        context.uc_mcontext.gregs[REG_ESP] = STACK_TOP_ADDRESS - 16;
        setcontext(&context);
    }
    printf("Context changed! %s\n", argv[1]);

    if (argc != 2) {
        exitWithError("Usage: ./raise <core-file>\n");
    }
    /*
    FILE *coreFile = fopen(argv[1], "r");

    if (coreFile == NULL) {
        exitWithError("Error while opening core file\n");
    }

    fclose(coreFile);
    */
    return 0;
}