#include <signal.h>
#include <stdio.h>

int main() {
    int x = 5;
    char c = 'a';
    printf("Before sigquit\n");
    raise(SIGQUIT);
    printf("After sigquit\n");
    return 0;
}