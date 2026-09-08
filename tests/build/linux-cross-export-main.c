#include <dlfcn.h>
#include <stdio.h>

int aos_cross_exported_symbol(void)
{
    return 73;
}

int main(int argc, char **argv)
{
    void *module;

    if (argc != 2) {
        fprintf(stderr, "usage: %s MODULE\n", argv[0]);
        return 64;
    }

    module = dlopen(argv[1], RTLD_NOW);
    if (module == NULL) {
        fprintf(stderr, "dlopen: %s\n", dlerror());
        return 1;
    }

    return 0;
}
