#include <stdio.h>
#include <stdlib.h>

__attribute__((noinline)) void win(void) {
    const char *flag = getenv("PWNPROOF_FLAG");
    if (flag != NULL) {
        puts(flag);
    }
}

int main(void) {
    char buffer[64];
    setbuf(stdout, NULL);
    puts("=== PwnProof local ret2win ===");
    printf("payload > ");
    gets(buffer);
    puts("bye");
    return 0;
}

