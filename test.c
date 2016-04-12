#include <signal.h>
#include <stdio.h>

int main() {
    //register int x asm("eax");
    //register int y asm("edx");
    //printf("%p %p\n", x, y);
    raise(SIGQUIT);
    return 42;
}