/* Package-owned runtime handler for the aos.kernel.modules ability. */

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

#define ADMISSION_REQUEST_SCHEMA "aos.primitive.command-handler-admission-request/v1"
#define ADMISSION_SCHEMA "aos.primitive.command-handler-admission/v1"
#define INVOCATION_SCHEMA "aos.primitive.command-handler-invocation/v1"
#define REQUEST_SCHEMA "aos.primitive.command-handler-request/v1"
#define RESULT_SCHEMA "aos.primitive.command-handler-result/v1"
#define NATIVE_CONTEXT_SCHEMA "aos.kmod.native-context/v1"
#define OBSERVATION_SCHEMA "aos.ability.kernel-modules-observation/v1"
#define REALIZATION_SCHEMA "aos.kmod.module-set-realization/v1"
#define INPUT_LIMIT (4U * 1024U * 1024U)
#define SHA256_BYTES 32U

struct request_view {
    json_t *expected;
    json_t *modules;
    json_t *target;
    const char *revision;
    const char *method;
    const char *native_context_digest;
    bool required;
};

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

static void require_schema(json_t *object, const char *expected)
{
    if (strcmp(required_string(object, "schema"), expected) != 0)
        fail("unexpected message schema");
}

static void validate_realization(json_t *realization, const struct request_view *view)
{
    require_schema(realization, REALIZATION_SCHEMA);
    if (!json_equal(json_object_get(realization, "modules"), view->modules) ||
        !json_equal(json_object_get(realization, "required"),
                    json_object_get(view->expected, "required")))
        fail("kernel-module realization differs from desired value");
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

static json_t *resource_from_reference(json_t *reference)
{
    return required_object(reference, "resource");
}

static json_t *target_context(json_t *resources, json_t *target)
{
    json_t *target_resource = resource_from_reference(target);
    size_t count = json_array_size(resources);

    for (size_t index = 0; index < count; ++index) {
        json_t *context = json_array_get(resources, index);
        json_t *reference;

        if (!json_is_object(context))
            fail("resource context is not an object");
        reference = required_object(context, "reference");
        if (json_equal(resource_from_reference(reference), target_resource))
            return context;
    }
    fail("target resource has no admitted context");
    return NULL;
}

static void admission_view(json_t *request, struct request_view *view)
{
    json_t *method;
    json_t *resource_spec;
    json_t *realization;

    require_schema(request, ADMISSION_REQUEST_SCHEMA);
    method = required_object(request, "method");
    resource_spec = required_object(request, "resource_spec");
    realization = required_object(resource_spec, "realization");

    view->method = required_string(method, "method");
    view->target = required_object(request, "target");
    view->expected = required_object(resource_spec, "value");
    view->modules = required_array(view->expected, "modules");
    view->required = required_boolean(view->expected, "required");
    view->revision = required_string(resource_spec, "revision");
    view->native_context_digest = NULL;

    validate_parameters(view->expected);
    validate_realization(realization, view);
    if (strcmp(view->method, "load") != 0 && strcmp(view->method, "observe") != 0)
        fail("unsupported kernel-module method");
}

static void invocation_view(json_t *invocation, const char *purpose,
                            struct request_view *view)
{
    json_t *request;
    json_t *method;
    json_t *context;
    json_t *native_context;
    json_t *resource_spec;
    json_t *provider_context;

    require_schema(invocation, INVOCATION_SCHEMA);
    if (strcmp(required_string(invocation, "purpose"), purpose) != 0)
        fail("argv purpose differs from invocation purpose");

    request = required_object(invocation, "request");
    require_schema(request, REQUEST_SCHEMA);
    method = required_object(request, "method");
    view->method = required_string(method, "method");
    view->target = required_object(request, "target");
    view->native_context_digest = required_string(request, "native_context_digest");

    context = target_context(required_array(request, "resources"), view->target);
    native_context = required_object(context, "native_context");
    resource_spec = required_object(native_context, "resource_spec");
    provider_context = required_object(native_context, "provider_context");
    view->expected = required_object(resource_spec, "value");
    view->modules = required_array(view->expected, "modules");
    view->required = required_boolean(view->expected, "required");
    view->revision = required_string(context, "revision");

    validate_parameters(view->expected);
    validate_realization(required_object(resource_spec, "realization"), view);
    require_schema(provider_context, NATIVE_CONTEXT_SCHEMA);
    if (!json_equal(json_object_get(request, "inputs"), view->expected))
        fail("kernel-module method input differs from admitted desired value");
    if (strcmp(view->method, "load") != 0 && strcmp(view->method, "observe") != 0)
        fail("unsupported kernel-module method");
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

    resource_digest(resource_from_reference(target), digest);
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

static bool completion_matches(const struct request_view *view,
                               const struct module_state *state)
{
    if (view->required)
        return json_array_size(state->unavailable) == 0;
    return marker_matches(view->target, view->revision);
}

static json_t *observation(const struct request_view *view,
                           const struct module_state *state,
                           bool completed)
{
    const char *status;
    size_t loaded = json_array_size(state->loaded);
    size_t unavailable = json_array_size(state->unavailable);

    if (completed)
        status = "ready";
    else if (loaded == 0)
        status = "absent";
    else if (unavailable == 0)
        status = "unknown";
    else
        status = "partial";

    return json_pack("{s:s,s:o,s:o,s:o,s:s}",
                     "schema", OBSERVATION_SCHEMA,
                     "expected", json_deep_copy(view->expected),
                     "loaded", json_deep_copy(state->loaded),
                     "unavailable", json_deep_copy(state->unavailable),
                     "state", status);
}

static json_t *revision_state(const struct request_view *view, bool completed)
{
    if (!completed)
        return json_pack("{s:s}", "state", "absent");
    return json_pack("{s:s,s:s}", "state", "present", "revision", view->revision);
}

static json_t *native_context(void)
{
    return json_pack("{s:s}", "schema", NATIVE_CONTEXT_SCHEMA);
}

static void respond_admission(const struct request_view *view)
{
    struct module_state state = observe_modules(view->modules);
    bool completed = completion_matches(view, &state);
    json_t *response = json_pack("{s:s,s:s,s:o,s:n,s:o,s:o}",
                                 "schema", ADMISSION_SCHEMA,
                                 "disposition", "admitted",
                                 "revision", revision_state(view, completed),
                                 "incarnation",
                                 "observation", observation(view, &state, completed),
                                 "native_context", native_context());

    if (response == NULL)
        fail("building admission response failed");
    write_response(response);
    json_decref(response);
    json_decref(state.loaded);
    json_decref(state.unavailable);
}

static void executable_path(char path[PATH_MAX])
{
    ssize_t length = readlink("/proc/self/exe", path, PATH_MAX - 1);
    const char suffix[] = "/libexec/aos-kmod-handler";
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

static json_t *outputs_for(const struct request_view *view, bool completed)
{
    json_t *outputs = json_object();

    if (outputs == NULL)
        fail("allocating method outputs failed");
    if (completed && strcmp(view->method, "load") == 0 &&
        json_object_set(outputs, "retained-resource", view->target) != 0)
        fail("recording retained resource failed");
    return outputs;
}

static void respond_invocation(const struct request_view *view, const char *disposition,
                               const struct module_state *state, bool completed)
{
    json_t *response = json_pack("{s:s,s:s,s:o,s:o,s:s}",
                                 "schema", RESULT_SCHEMA,
                                 "disposition", disposition,
                                 "evidence", observation(view, state, completed),
                                 "outputs", outputs_for(view, completed),
                                 "native_context_digest", view->native_context_digest);

    if (response == NULL)
        fail("building invocation response failed");
    write_response(response);
    json_decref(response);
}

static void invoke_observe(const struct request_view *view)
{
    struct module_state state = observe_modules(view->modules);
    bool completed = completion_matches(view, &state);

    respond_invocation(view, "completed", &state, completed);
    json_decref(state.loaded);
    json_decref(state.unavailable);
}

static void invoke_load(const struct request_view *view, const char *purpose,
                        bool cancelled)
{
    struct module_state before = observe_modules(view->modules);
    bool before_complete = completion_matches(view, &before);

    if (strcmp(purpose, "cancel") == 0 || cancelled) {
        const char *disposition = before_complete ? "completed" :
                                  json_array_size(before.loaded) == 0
                                      ? "rejected-before-effect"
                                      : "indeterminate";

        respond_invocation(view, disposition, &before, before_complete);
        json_decref(before.loaded);
        json_decref(before.unavailable);
        return;
    }

    if (strcmp(purpose, "reconcile") == 0) {
        respond_invocation(view, before_complete ? "completed" : "safe-to-retry",
                           &before, before_complete);
        json_decref(before.loaded);
        json_decref(before.unavailable);
        return;
    }

    for (size_t index = 0; index < json_array_size(view->modules); ++index) {
        const char *name = json_string_value(json_array_get(view->modules, index));

        if (!module_loaded(name))
            (void)load_module(name);
    }

    struct module_state after = observe_modules(view->modules);
    bool completed = json_array_size(after.unavailable) == 0 || !view->required;
    bool changed = !json_equal(before.loaded, after.loaded);
    const char *disposition;

    if (completed) {
        record_marker(view->target, view->revision);
        disposition = "completed";
    } else {
        disposition = changed ? "indeterminate" : "rejected-before-effect";
    }
    respond_invocation(view, disposition, &after, completed);

    json_decref(before.loaded);
    json_decref(before.unavailable);
    json_decref(after.loaded);
    json_decref(after.unavailable);
}

int main(int argc, char **argv)
{
    json_t *document;
    struct request_view view;

    if (argc != 3 || strcmp(argv[1], "--aos-primitive-v1") != 0)
        fail("expected --aos-primitive-v1 and one purpose");
    document = read_request();

    if (strcmp(argv[2], "admit") == 0) {
        admission_view(document, &view);
        respond_admission(&view);
    } else if (strcmp(argv[2], "effect") == 0 ||
               strcmp(argv[2], "reconcile") == 0 ||
               strcmp(argv[2], "cancel") == 0) {
        json_t *control;
        bool cancelled;

        invocation_view(document, argv[2], &view);
        control = required_object(document, "control");
        cancelled = required_boolean(control, "cancelled");
        if (strcmp(view.method, "observe") == 0)
            invoke_observe(&view);
        else
            invoke_load(&view, argv[2], cancelled);
    } else {
        fail("unsupported handler purpose");
    }

    json_decref(document);
    return 0;
}
