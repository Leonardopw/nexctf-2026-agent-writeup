#include <stdio.h>

int main(void) {
    char buffer[64];

    setbuf(stdout, NULL);
    puts("=== PwnProof local format string ===");
    printf("input > ");
    fgets(buffer, sizeof(buffer), stdin);
    printf(buffer);
    puts("done");
    return 0;
}
