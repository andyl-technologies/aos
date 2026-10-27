/* Reports the domain of a same-named, different-store-root inspector binary. */

#include <stdio.h>

int main(void)
{
    FILE *context = fopen("/proc/self/attr/current", "r");
    char label[256];

    if (context == NULL)
        return 1;
    if (fgets(label, sizeof(label), context) == NULL) {
        fclose(context);
        return 1;
    }
    if (fclose(context) != 0)
        return 1;
    if (printf("AOS_LOOKALIKE_CONTEXT=%s", label) < 0)
        return 1;

    return 0;
}
