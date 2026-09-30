/* Package-owned native kernel-module operation handler. */

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <jansson.h>
#include <limits.h>
#include <openssl/evp.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define INPUT_LIMIT (256U * 1024U)
#define SHA256_BYTES 32U

struct module_state {
    json_t *loaded;
    json_t *unavailable;
};

static void fail(const char *message)
{
    fprintf(stderr, "aos-kmod-handler: %s\n", message);
    exit(2);
}

static json_t *required_object(json_t *object, const char *name)
{
    json_t *value = json_object_get(object, name);

    if (!json_is_object(value))
        fail(name);
    return value;
}

static json_t *required_array(json_t *object, const char *name)
{
    json_t *value = json_object_get(object, name);

    if (!json_is_array(value))
        fail(name);
    return value;
}

static const char *required_string(json_t *object, const char *name)
{
    json_t *value = json_object_get(object, name);

    if (!json_is_string(value))
        fail(name);
    return json_string_value(value);
}

static bool required_boolean(json_t *object, const char *name)
{
    json_t *value = json_object_get(object, name);

    if (!json_is_boolean(value))
        fail(name);
    return json_is_true(value);
}

static json_t *read_request(void)
{
    char *bytes = malloc(INPUT_LIMIT + 1);
    size_t length = 0;
    json_error_t error;
    json_t *document;

    if (bytes == NULL)
        fail("allocating request buffer failed");

    while (length < INPUT_LIMIT) {
        size_t count = fread(bytes + length, 1, INPUT_LIMIT - length, stdin);

        length += count;
        if (count == 0)
            break;
    }
    if (ferror(stdin) || length == INPUT_LIMIT)
        fail("request exceeds its byte bound");

    bytes[length] = '\0';
    document = json_loadb(bytes, length, JSON_REJECT_DUPLICATES, &error);
    free(bytes);
    if (!json_is_object(document))
        fail("request is not a JSON object");
    return document;
}

static void write_response(json_t *response)
{
    char *encoded = json_dumps(response, JSON_COMPACT | JSON_SORT_KEYS);

    if (encoded == NULL)
        fail("encoding response failed");
    if (fwrite(encoded, 1, strlen(encoded), stdout) != strlen(encoded)) {
        free(encoded);
        fail("writing response failed");
    }
    free(encoded);
}

static bool valid_module_name(const char *name)
{
    size_t length = strlen(name);

    if (length == 0 || length > 128)
        return false;
    for (size_t index = 0; index < length; ++index) {
        char character = name[index];

        if ((character >= 'a' && character <= 'z') ||
            (character >= 'A' && character <= 'Z') ||
            (character >= '0' && character <= '9') ||
            character == '.' || character == '_' || character == '-')
            continue;
        return false;
    }
    return true;
}

static void validate_parameters(json_t *parameters)
{
    json_t *modules = required_array(parameters, "modules");
    size_t count = json_array_size(modules);

    (void)required_boolean(parameters, "required");
    if (count == 0 || count > 256)
        fail("kernel-module request has an invalid module count");

    for (size_t index = 0; index < count; ++index) {
        json_t *entry = json_array_get(modules, index);
        const char *name;

        if (!json_is_string(entry))
            fail("kernel-module name is not a string");
        name = json_string_value(entry);
        if (!valid_module_name(name))
            fail("kernel-module name is invalid");
        for (size_t prior = 0; prior < index; ++prior) {
            if (strcmp(name, json_string_value(json_array_get(modules, prior))) == 0)
                fail("kernel-module request contains a duplicate name");
        }
    }
}

static void normalized_module_name(const char *name, char *normalized, size_t capacity)
{
    size_t length = strlen(name);

    if (length + 1 > capacity)
        fail("normalized module name exceeds its buffer");
    for (size_t index = 0; index < length; ++index)
        normalized[index] = name[index] == '-' ? '_' : name[index];
    normalized[length] = '\0';
}

static bool module_loaded(const char *name)
{
    char normalized[129];
    char path[PATH_MAX];
    int written;

    normalized_module_name(name, normalized, sizeof(normalized));
    written = snprintf(path, sizeof(path), "/sys/module/%s", normalized);
    if (written < 0 || (size_t)written >= sizeof(path))
        fail("module observation path exceeds its buffer");
    return access(path, F_OK) == 0;
}

static struct module_state observe_modules(json_t *modules)
{
    struct module_state state = {
        .loaded = json_array(),
        .unavailable = json_array(),
    };
    size_t count = json_array_size(modules);

    if (state.loaded == NULL || state.unavailable == NULL)
        fail("allocating module observation failed");
    for (size_t index = 0; index < count; ++index) {
        json_t *name = json_array_get(modules, index);
        json_t *copy = json_deep_copy(name);

        if (copy == NULL)
            fail("copying module observation failed");
        if (json_array_append_new(module_loaded(json_string_value(name)) ? state.loaded
                                                                        : state.unavailable,
                                  copy) != 0)
            fail("recording module observation failed");
    }
    return state;
}

static void resource_digest(json_t *resource, char digest[SHA256_BYTES * 2 + 1])
{
    EVP_MD_CTX *context;
    unsigned char bytes[EVP_MAX_MD_SIZE];
    unsigned int digest_length;
    char *encoded = json_dumps(resource, JSON_COMPACT | JSON_SORT_KEYS);

    if (encoded == NULL)
        fail("encoding resource identity failed");
    context = EVP_MD_CTX_new();
    if (context == NULL ||
        EVP_DigestInit_ex(context, EVP_sha256(), NULL) != 1 ||
        EVP_DigestUpdate(context, encoded, strlen(encoded)) != 1 ||
        EVP_DigestFinal_ex(context, bytes, &digest_length) != 1 ||
        digest_length != SHA256_BYTES) {
        EVP_MD_CTX_free(context);
        free(encoded);
        fail("hashing resource identity failed");
    }
    EVP_MD_CTX_free(context);
    free(encoded);
    for (size_t index = 0; index < SHA256_BYTES; ++index)
        snprintf(digest + index * 2, 3, "%02x", bytes[index]);
    digest[SHA256_BYTES * 2] = '\0';
}

static void marker_path(json_t *target, char path[PATH_MAX])
{
    char digest[SHA256_BYTES * 2 + 1];
    int written;

    resource_digest(target, digest);
    written = snprintf(path, PATH_MAX, "/run/aos-kmod/%s.revision", digest);
    if (written < 0 || written >= PATH_MAX)
        fail("marker path exceeds its buffer");
}

static bool marker_matches(json_t *target, const char *revision)
{
    char path[PATH_MAX];
    char stored[128];
    ssize_t count;
    int descriptor;

    marker_path(target, path);
    descriptor = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (descriptor < 0)
        return false;
    count = read(descriptor, stored, sizeof(stored) - 1);
    close(descriptor);
    if (count < 0)
        return false;
    stored[count] = '\0';
    return strcmp(stored, revision) == 0;
}

static void record_marker(json_t *target, const char *revision)
{
    char path[PATH_MAX];
    char temporary[PATH_MAX];
    int descriptor;
    int written;
    size_t length = strlen(revision);
    size_t offset = 0;

    if (mkdir("/run/aos-kmod", 0700) != 0 && errno != EEXIST)
        fail("creating kmod state directory failed");
    marker_path(target, path);
    written = snprintf(temporary, sizeof(temporary), "%s.tmp.%ld", path, (long)getpid());
    if (written < 0 || (size_t)written >= sizeof(temporary))
        fail("temporary marker path exceeds its buffer");

    descriptor = open(temporary, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (descriptor < 0)
        fail("creating module marker failed");
    while (offset < length) {
        ssize_t count = write(descriptor, revision + offset, length - offset);

        if (count < 0 && errno == EINTR)
            continue;
        if (count <= 0) {
            close(descriptor);
            unlink(temporary);
            fail("writing module marker failed");
        }
        offset += (size_t)count;
    }
    if (fsync(descriptor) != 0) {
        close(descriptor);
        unlink(temporary);
        fail("writing module marker failed");
    }
    if (close(descriptor) != 0 || rename(temporary, path) != 0) {
        unlink(temporary);
        fail("publishing module marker failed");
    }
}

static void executable_path(char path[PATH_MAX])
{
    ssize_t length = readlink("/proc/self/exe", path, PATH_MAX - 1);
    const char suffix[] = "/bin/aos-kmod-handler";
    size_t suffix_length = sizeof(suffix) - 1;
    int written;

    if (length < 0 || length >= PATH_MAX - 1)
        fail("resolving handler executable failed");
    path[length] = '\0';
    if ((size_t)length <= suffix_length ||
        strcmp(path + length - (ssize_t)suffix_length, suffix) != 0)
        fail("handler executable is outside the kmod package layout");
    path[length - (ssize_t)suffix_length] = '\0';
    written = snprintf(path + length - (ssize_t)suffix_length,
                       PATH_MAX - (size_t)length + suffix_length,
                       "/sbin/modprobe");
    if (written < 0 || (size_t)written >= PATH_MAX - (size_t)length + suffix_length)
        fail("modprobe path exceeds its buffer");
}

static bool load_module(const char *name)
{
    char executable[PATH_MAX];
    pid_t child;
    int status;

    executable_path(executable);
    child = fork();
    if (child < 0)
        fail("forking modprobe failed");
    if (child == 0) {
        char *const arguments[] = {executable, "--", (char *)name, NULL};

        execv(executable, arguments);
        _exit(127);
    }
    while (waitpid(child, &status, 0) < 0) {
        if (errno != EINTR)
            fail("waiting for modprobe failed");
    }
    return WIFEXITED(status) && WEXITSTATUS(status) == 0;
}


/* Module removal releases ownership; it must never unload shared kernel code. */
int main(int argc, char **argv)
{
    json_t *invocation;
    json_t *parameters;
    json_t *modules;
    json_t *identity;
    json_t *effect;
    json_t *response;
    struct module_state state;
    const char *revision;
    const char *action;
    bool required;
    bool completed;

    if (argc != 2 || (strcmp(argv[1], "apply") != 0 &&
                      strcmp(argv[1], "remove") != 0 &&
                      strcmp(argv[1], "observe") != 0))
        fail("usage: aos-kmod-handler <apply|remove|observe>");

    invocation = read_request();
    parameters = required_object(invocation, "input");
    effect = required_object(invocation, "effect");
    identity = required_array(effect, "identity");
    revision = required_string(invocation, "revision");
    action = required_string(invocation, "action");
    validate_parameters(parameters);
    modules = required_array(parameters, "modules");
    required = required_boolean(parameters, "required");

    if (strcmp(argv[1], "observe") != 0 && strcmp(argv[1], action) != 0)
        fail("invocation action differs from argv");
    if (strcmp(action, "apply") != 0 && strcmp(action, "remove") != 0)
        fail("invalid invocation action");

    if (strcmp(argv[1], "remove") == 0) {
        char path[PATH_MAX];

        marker_path(identity, path);
        if (unlink(path) != 0 && errno != ENOENT)
            fail("releasing module marker failed");
        response = json_object();
    } else {
        if (strcmp(argv[1], "apply") == 0) {
            size_t count = json_array_size(modules);

            for (size_t index = 0; index < count; ++index) {
                const char *name = json_string_value(json_array_get(modules, index));

                if (!module_loaded(name) && !load_module(name) && required)
                    fail("loading a required kernel module failed");
            }
            record_marker(identity, revision);
        }

        state = observe_modules(modules);
        completed = marker_matches(identity, revision) &&
                    (!required || json_array_size(state.unavailable) == 0);
        if (strcmp(argv[1], "observe") == 0 && strcmp(action, "remove") == 0) {
            char path[PATH_MAX];

            marker_path(identity, path);
            response = json_pack("{s:s}", "status",
                                 access(path, F_OK) != 0 && errno == ENOENT
                                     ? "absent" : "retry-safe");
        } else {
            json_t *outputs = json_pack("{s:o,s:o}",
                                        "loaded", json_deep_copy(state.loaded),
                                        "unavailable", json_deep_copy(state.unavailable));

            if (strcmp(argv[1], "observe") == 0) {
                response = completed
                    ? json_pack("{s:s,s:o}", "status", "current", "outputs", outputs)
                    : json_pack("{s:s}", "status", "retry-safe");
                if (!completed)
                    json_decref(outputs);
            } else {
                response = outputs;
            }
        }
        json_decref(state.loaded);
        json_decref(state.unavailable);
    }

    if (response == NULL)
        fail("allocating response failed");
    write_response(response);
    json_decref(response);
    json_decref(invocation);
    return 0;
}
