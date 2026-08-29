#include <stdio.h>
#include "elf_suite.h"

const char *elf_suite_target(void) {
#if defined(__ANDROID__)
    return "Android Bionic AArch64";
#elif defined(__MUSL__)
    return "Linux musl AArch64";
#else
    return "Linux glibc AArch64";
#endif
}

int main(void) {
    printf("Real ELF executable: %s\n", elf_suite_target());
    return 0;
}

