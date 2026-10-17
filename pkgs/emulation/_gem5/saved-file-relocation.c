/* SPDX-License-Identifier: MIT */
/* Relocates original checkpoint copies beneath authenticated private custody.
 * The Apache launcher supplies this binding only from a sealed image closure;
 * this helper does not confer authority on caller-provided paths or digests. */
#include <dmtcp.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <openssl/evp.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define MAX_FILES 4096
#define MAX_ROSTER_BYTES (2 * 1024 * 1024)
#define MAX_SAVED_BYTES (UINT64_C(64) * 1024 * 1024 * 1024)

struct saved_file_record {
    char name[NAME_MAX + 1];
    unsigned char sha256[32];
    uint64_t bytes;
    int seen;
};

static void
refuse_saved_copy(const char *reason)
{
    const char prefix[] = "invalid native saved-copy relocation: ";
    ssize_t written = write(STDERR_FILENO, prefix, sizeof(prefix) - 1);
    written = write(STDERR_FILENO, reason, strlen(reason));
    written = write(STDERR_FILENO, "\n", 1);
    (void)written;
    _exit(125);
}

static int
safe_absolute_path(const char *path)
{
    if (path[0] != '/' || path[1] == '\0')
        return 0;
    const char *component = path + 1;
    while (*component) {
        const char *end = strchr(component, '/');
        size_t length = end ? (size_t)(end - component) : strlen(component);
        if (length == 0 || (length == 1 && component[0] == '.') ||
            (length == 2 && component[0] == '.' && component[1] == '.') ||
            memchr(component, '\t', length) || memchr(component, '\n', length))
            return 0;
        if (!end)
            return 1;
        component = end + 1;
    }
    return 0;
}

static int
hex_digit(char byte)
{
    if (byte >= '0' && byte <= '9')
        return byte - '0';
    if (byte >= 'a' && byte <= 'f')
        return byte - 'a' + 10;
    return -1;
}

static void
parse_record(char *line, struct saved_file_record *record)
{
    char *length = strchr(line, '\t');
    char *name = length ? strchr(length + 1, '\t') : NULL;
    if (!length || !name || (size_t)(length - line) != 64 || strchr(name + 1, '\t'))
        refuse_saved_copy("malformed artifact roster record");
    *length++ = '\0';
    *name++ = '\0';
    size_t name_length = strlen(name);
    if (!name_length || name_length > NAME_MAX || strchr(name, '/') ||
        strcmp(name, ".") == 0 || strcmp(name, "..") == 0)
        refuse_saved_copy("saved-copy leaf is not a bounded basename");
    strcpy(record->name, name);
    for (unsigned index = 0; index < 32; ++index) {
        int high = hex_digit(line[index * 2]);
        int low = hex_digit(line[index * 2 + 1]);
        if (high < 0 || low < 0)
            refuse_saved_copy("artifact SHA-256 is not canonical");
        record->sha256[index] = (unsigned char)((high << 4) | low);
    }
    if (!*length || (*length == '0' && length[1]))
        refuse_saved_copy("artifact length is not canonical");
    record->bytes = 0;
    for (const char *digit = length; *digit; ++digit) {
        if (*digit < '0' || *digit > '9' ||
            record->bytes > (MAX_SAVED_BYTES - (unsigned)(*digit - '0')) / 10)
            refuse_saved_copy("artifact length exceeds its bound");
        record->bytes = record->bytes * 10 + (unsigned)(*digit - '0');
    }
}

static int
same_file(const struct stat *before, const struct stat *after)
{
    return before->st_dev == after->st_dev && before->st_ino == after->st_ino &&
        before->st_size == after->st_size && before->st_mtim.tv_sec == after->st_mtim.tv_sec &&
        before->st_mtim.tv_nsec == after->st_mtim.tv_nsec;
}

static void
verify_saved_file(int root_fd, const struct saved_file_record *record)
{
    int descriptor = openat(root_fd, record->name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    struct stat before, after;
    if (descriptor < 0 || fstat(descriptor, &before) != 0 ||
        !S_ISREG(before.st_mode) || before.st_uid != geteuid() || before.st_nlink != 1 ||
        before.st_size < 0 || (uint64_t)before.st_size != record->bytes)
        refuse_saved_copy("saved-copy descriptor identity differs");

    EVP_MD_CTX *digest = EVP_MD_CTX_new();
    if (!digest || EVP_DigestInit_ex(digest, EVP_sha256(), NULL) != 1)
        refuse_saved_copy("cannot initialize artifact digest");
    unsigned char buffer[65536];
    ssize_t count;
    while ((count = read(descriptor, buffer, sizeof(buffer))) > 0) {
        if (EVP_DigestUpdate(digest, buffer, (size_t)count) != 1)
            refuse_saved_copy("cannot digest artifact bytes");
    }
    unsigned char actual[EVP_MAX_MD_SIZE];
    unsigned actual_length;
    if (count < 0 || EVP_DigestFinal_ex(digest, actual, &actual_length) != 1 ||
        actual_length != 32 || memcmp(actual, record->sha256, 32) != 0 ||
        fstat(descriptor, &after) != 0 || !same_file(&before, &after))
        refuse_saved_copy("saved-copy content differs or changed during inspection");
    EVP_MD_CTX_free(digest);
    close(descriptor);
}

void
dmtcp_get_new_checkpoint_file_path(const char *original, char *resolved, size_t capacity)
{
    if (capacity == 0)
        refuse_saved_copy("missing output path credit");
    resolved[0] = '\0';
    char source_root[PATH_MAX], target_root[PATH_MAX], manifest_path[PATH_MAX];
    DmtcpGetRestartEnvErr_t source = dmtcp_get_restart_env(
        "CRUCIBLE_RESTORE_SAVED_FILES_SOURCE_ROOT", source_root, sizeof(source_root));
    DmtcpGetRestartEnvErr_t target = dmtcp_get_restart_env(
        "CRUCIBLE_RESTORE_SAVED_FILES_TARGET_ROOT", target_root, sizeof(target_root));
    DmtcpGetRestartEnvErr_t manifest = dmtcp_get_restart_env(
        "CRUCIBLE_RESTORE_SAVED_FILES_MANIFEST", manifest_path, sizeof(manifest_path));
    if (source == RESTART_ENV_NOTFOUND && target == RESTART_ENV_NOTFOUND &&
        manifest == RESTART_ENV_NOTFOUND)
        return;
    if (source != RESTART_ENV_SUCCESS || target != RESTART_ENV_SUCCESS ||
        manifest != RESTART_ENV_SUCCESS || !safe_absolute_path(source_root) ||
        !safe_absolute_path(target_root) || !safe_absolute_path(manifest_path))
        refuse_saved_copy("incomplete original/imported artifact binding");

    size_t source_length = strlen(source_root);
    if (strncmp(original, source_root, source_length) != 0 || original[source_length] != '/')
        refuse_saved_copy("original saved path is outside its authenticated root");
    const char *leaf = original + source_length + 1;
    size_t target_length = strlen(target_root);
    if (!*leaf || strchr(leaf, '/') || strcmp(source_root, target_root) == 0 ||
        (strncmp(source_root, target_root, target_length) == 0 && source_root[target_length] == '/') ||
        (strncmp(target_root, source_root, source_length) == 0 && target_root[source_length] == '/'))
        refuse_saved_copy("saved-copy path or reconstruction root is not isolated");
    char canonical[PATH_MAX];
    if (!realpath(target_root, canonical) || strcmp(canonical, target_root) != 0)
        refuse_saved_copy("imported root is not canonical");
    int root_fd = open(target_root, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    struct stat root_metadata;
    if (root_fd < 0 || fstat(root_fd, &root_metadata) != 0 ||
        root_metadata.st_uid != geteuid() || (root_metadata.st_mode & 077) != 0)
        refuse_saved_copy("imported root is not private owned custody");

    if (!realpath(manifest_path, canonical) || strcmp(canonical, manifest_path) != 0)
        refuse_saved_copy("artifact roster is not canonical");
    int manifest_fd = open(manifest_path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    struct stat manifest_before, manifest_after;
    if (manifest_fd < 0 || fstat(manifest_fd, &manifest_before) != 0 ||
        !S_ISREG(manifest_before.st_mode) || manifest_before.st_uid != geteuid() ||
        manifest_before.st_nlink != 1 || (manifest_before.st_mode & 0222) != 0 ||
        manifest_before.st_size < 0 || manifest_before.st_size > MAX_ROSTER_BYTES)
        refuse_saved_copy("artifact roster is not immutable bounded custody");
    FILE *stream = fdopen(manifest_fd, "r");
    struct saved_file_record *records = calloc(MAX_FILES, sizeof(*records));
    if (!stream || !records)
        refuse_saved_copy("cannot inspect artifact roster");
    char line[PATH_MAX * 2 + 32];
    const char *headers[] = {"crucible-saved-files-v1", source_root, target_root};
    for (unsigned index = 0; index < 3; ++index) {
        if (!fgets(line, sizeof(line), stream) || !strchr(line, '\n'))
            refuse_saved_copy("artifact roster header is truncated");
        line[strlen(line) - 1] = '\0';
        if (strcmp(line, headers[index]) != 0)
            refuse_saved_copy("artifact roster has another original/imported binding");
    }
    unsigned record_count = 0;
    int found = 0;
    while (fgets(line, sizeof(line), stream)) {
        size_t length = strlen(line);
        if (!length || line[length - 1] != '\n' || record_count == MAX_FILES)
            refuse_saved_copy("artifact roster record exceeds its credit");
        line[length - 1] = '\0';
        parse_record(line, &records[record_count]);
        if (record_count && strcmp(records[record_count - 1].name, records[record_count].name) >= 0)
            refuse_saved_copy("artifact roster is reordered or duplicates a leaf");
        verify_saved_file(root_fd, &records[record_count]);
        found |= strcmp(leaf, records[record_count].name) == 0;
        ++record_count;
    }
    if (ferror(stream) || !found || fstat(manifest_fd, &manifest_after) != 0 ||
        !same_file(&manifest_before, &manifest_after))
        refuse_saved_copy("original saved leaf is absent or artifact roster changed");
    fclose(stream);

    DIR *directory = fdopendir(root_fd);
    if (!directory)
        refuse_saved_copy("cannot census imported artifact directory");
    struct dirent *entry;
    errno = 0;
    while ((entry = readdir(directory)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
            continue;
        unsigned index;
        for (index = 0; index < record_count; ++index) {
            if (strcmp(entry->d_name, records[index].name) == 0) {
                records[index].seen = 1;
                break;
            }
        }
        if (index == record_count)
            refuse_saved_copy("imported artifact directory has an unpinned leaf");
        errno = 0;
    }
    if (errno != 0)
        refuse_saved_copy("cannot complete imported artifact census");
    for (unsigned index = 0; index < record_count; ++index) {
        if (!records[index].seen)
            refuse_saved_copy("imported artifact census omitted a pinned leaf");
    }
    closedir(directory);
    free(records);

    int length = snprintf(resolved, capacity, "%s/%s", target_root, leaf);
    if (length < 0 || (size_t)length >= capacity)
        refuse_saved_copy("translated saved-copy path exceeds its credit");
}
