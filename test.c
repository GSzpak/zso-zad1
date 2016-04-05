#include <signal.h>
#include <stdio.h>

int main() {
    int x = 5;
    char c = 'a';
    printf("Before sigquit\n");
    raise(SIGQUIT);
    printf("After sigquit\n");
    printf("%d\n", x);
    printf("%c\n", c);
    return 0;
}