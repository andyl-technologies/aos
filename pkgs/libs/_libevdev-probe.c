#include <errno.h>
#include <linux/input.h>
#include <stdio.h>
#include <string.h>
#include <libevdev/libevdev.h>

int main(int argc, char **argv) {
    if (argc > 1 && strcmp(argv[1], "invalid") == 0) {
        struct libevdev *invalid = NULL;
        int result = libevdev_new_from_fd(-1, &invalid);
        if (invalid != NULL) libevdev_free(invalid);
        if (result != -EBADF || invalid != NULL) return 1;
        puts("libevdev rejected invalid file descriptor");
        return 0;
    }

    struct libevdev *device = libevdev_new();
    if (device == NULL) return 2;
    libevdev_set_name(device, "AOS probe");

    int result = libevdev_enable_event_code(device, EV_KEY, KEY_A, NULL);
    int good = result == 0
        && libevdev_has_event_code(device, EV_KEY, KEY_A)
        && strcmp(libevdev_get_name(device), "AOS probe") == 0;
    libevdev_free(device);
    if (!good) return 3;

    puts("libevdev event descriptor passed");
    return 0;
}
