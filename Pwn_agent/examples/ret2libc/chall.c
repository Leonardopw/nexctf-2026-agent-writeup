#include <stdio.h>
#include <stdlib.h>

__asm__(
    ".pushsection .text\n"
    ".global pwnproof_pop_rdi_ret\n"
    ".type pwnproof_pop_rdi_ret,@function\n"
    "pwnproof_pop_rdi_ret:\n"
    "pop %rdi\n"
    "ret\n"
    ".size pwnproof_pop_rdi_ret, .-pwnproof_pop_rdi_ret\n"
    ".popsection\n");

__attribute__((noinline)) static void vulnerable(void) {
    char buffer[64];

    puts("=== PwnProof local ret2libc ===");
    printf("payload > ");
    gets(buffer);
    puts("bye");
}

int main(void) {
    setbuf(stdout, NULL);
    if (getenv("PWNPROOF_USE_SYSTEM") != NULL) {
        system("true");
    }
    vulnerable();
    return 0;
}
