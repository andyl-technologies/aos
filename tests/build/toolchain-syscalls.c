/* Exercises syscall wrappers that must remain distinct under parallel builds. */
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/vfs.h>
#include <unistd.h>

static int fail(const char *operation) {
    perror(operation);
    return 1;
}

int main(void) {
    int descriptors[2];
    int duplicate;
    int directory;
    char data[4];
    char before[4096];
    char after[4096];
    struct statfs path_filesystem;
    struct statfs descriptor_filesystem;

    if (pipe(descriptors) != 0) {
        return fail("pipe");
    }

    duplicate = dup(descriptors[0]);
    if (duplicate < 0 || close(descriptors[0]) != 0) {
        return fail("dup/close");
    }

    if (write(descriptors[1], "abc", 3) != 3 || read(duplicate, data, 3) != 3) {
        return fail("pipe read/write");
    }
    if (memcmp(data, "abc", 3) != 0) {
        fputs("pipe data mismatch\n", stderr);
        return 1;
    }

    if (dup2(duplicate, descriptors[0]) != descriptors[0]) {
        return fail("dup2");
    }
    if (close(duplicate) != 0 || close(descriptors[0]) != 0 || close(descriptors[1]) != 0) {
        return fail("close pipe descriptors");
    }

    errno = 0;
    if (close(descriptors[1]) != -1 || errno != EBADF) {
        fputs("close did not reject an invalid descriptor\n", stderr);
        return 1;
    }

    directory = open(".", O_RDONLY);
    if (directory < 0 || getcwd(before, sizeof(before)) == NULL) {
        return fail("open/getcwd");
    }
    if (chdir("/") != 0 || fchdir(directory) != 0 || getcwd(after, sizeof(after)) == NULL) {
        return fail("chdir/fchdir");
    }
    if (strcmp(before, after) != 0) {
        fputs("fchdir did not restore the working directory\n", stderr);
        return 1;
    }

    if (statfs(".", &path_filesystem) != 0 || fstatfs(directory, &descriptor_filesystem) != 0) {
        return fail("statfs/fstatfs");
    }
    if (path_filesystem.f_type != descriptor_filesystem.f_type
        || path_filesystem.f_bsize != descriptor_filesystem.f_bsize) {
        fputs("statfs and fstatfs disagree\n", stderr);
        return 1;
    }
    if (close(directory) != 0) {
        return fail("close directory");
    }

    puts("syscall contracts passed");
    return 0;
}
