#include "probe.h"

#include <stdio.h>

int main(void) {
    int answer = native_library_probe();
    printf("native-libraries=%d\n", answer);
    return answer == 42 ? 0 : 1;
}
