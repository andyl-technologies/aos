#define _GNU_SOURCE

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <systemd/sd-bus.h>

#define MANAGER_DESTINATION "org.freedesktop.systemd1"
#define MANAGER_PATH "/org/freedesktop/systemd1"
#define MANAGER_INTERFACE "org.freedesktop.systemd1.Manager"
#define UNIT_INTERFACE "org.freedesktop.systemd1.Unit"

static void fail_bus(const char *operation, int result, const sd_bus_error *error) {
    fprintf(stderr,
            "%s failed: result=%d name=%s message=%s\n",
            operation,
            result,
            error != NULL && error->name != NULL ? error->name : "none",
            error != NULL && error->message != NULL ? error->message : "none");
    exit(EXIT_FAILURE);
}

static char *get_unit_path(sd_bus *bus, const char *unit) {
    sd_bus_error error = SD_BUS_ERROR_NULL;
    sd_bus_message *reply = NULL;
    const char *path = NULL;
    int result = sd_bus_call_method(bus,
                                    MANAGER_DESTINATION,
                                    MANAGER_PATH,
                                    MANAGER_INTERFACE,
                                    "GetUnit",
                                    &error,
                                    &reply,
                                    "s",
                                    unit);
    if (result < 0)
        fail_bus("GetUnit", result, &error);
    result = sd_bus_message_read(reply, "o", &path);
    if (result < 0 || path == NULL)
        fail_bus("read GetUnit reply", result, &error);

    char *owned = strdup(path);
    if (owned == NULL) {
        perror("strdup unit path");
        exit(EXIT_FAILURE);
    }
    sd_bus_message_unref(reply);
    sd_bus_error_free(&error);
    return owned;
}

static int call_operation(sd_bus *bus,
                          const char *operation,
                          const char *unit,
                          sd_bus_error *error) {
    sd_bus_message *reply = NULL;
    char *unit_path = NULL;
    int result;

    if (strcmp(operation, "manager-ref") == 0 ||
        strcmp(operation, "manager-unref") == 0) {
        const char *member = strcmp(operation, "manager-ref") == 0 ? "RefUnit" : "UnrefUnit";
        result = sd_bus_call_method(bus,
                                    MANAGER_DESTINATION,
                                    MANAGER_PATH,
                                    MANAGER_INTERFACE,
                                    member,
                                    error,
                                    &reply,
                                    "s",
                                    unit);
    } else if (strcmp(operation, "unit-ref") == 0 ||
               strcmp(operation, "unit-unref") == 0) {
        unit_path = get_unit_path(bus, unit);
        const char *member = strcmp(operation, "unit-ref") == 0 ? "Ref" : "Unref";
        result = sd_bus_call_method(bus,
                                    MANAGER_DESTINATION,
                                    unit_path,
                                    UNIT_INTERFACE,
                                    member,
                                    error,
                                    &reply,
                                    NULL);
    } else if (strcmp(operation, "start") == 0 ||
               strcmp(operation, "restart") == 0 ||
               strcmp(operation, "stop") == 0) {
        const char *member = strcmp(operation, "start") == 0
                                 ? "StartUnit"
                                 : strcmp(operation, "restart") == 0 ? "RestartUnit" : "StopUnit";
        result = sd_bus_call_method(bus,
                                    MANAGER_DESTINATION,
                                    MANAGER_PATH,
                                    MANAGER_INTERFACE,
                                    member,
                                    error,
                                    &reply,
                                    "ss",
                                    unit,
                                    "replace");
    } else if (strcmp(operation, "start-transient") == 0) {
        sd_bus_message *request = NULL;
        result = sd_bus_message_new_method_call(bus,
                                                &request,
                                                MANAGER_DESTINATION,
                                                MANAGER_PATH,
                                                MANAGER_INTERFACE,
                                                "StartTransientUnit");
        if (result >= 0)
            result = sd_bus_message_append(request, "ss", unit, "replace");
        if (result >= 0)
            result = sd_bus_message_open_container(request, 'a', "(sv)");
        if (result >= 0)
            result = sd_bus_message_open_container(request, 'r', "sv");
        if (result >= 0)
            result = sd_bus_message_append(request, "s", "Description");
        if (result >= 0)
            result = sd_bus_message_open_container(request, 'v', "s");
        if (result >= 0)
            result = sd_bus_message_append(request, "s", "policy denial probe");
        if (result >= 0)
            result = sd_bus_message_close_container(request);
        if (result >= 0)
            result = sd_bus_message_close_container(request);
        if (result >= 0)
            result = sd_bus_message_close_container(request);
        if (result >= 0)
            result = sd_bus_message_open_container(request, 'a', "(sa(sv))");
        if (result >= 0)
            result = sd_bus_message_close_container(request);
        if (result >= 0)
            result = sd_bus_call(bus, request, 0, error, &reply);
        sd_bus_message_unref(request);
    } else {
        fprintf(stderr, "unknown operation: %s\n", operation);
        exit(EXIT_FAILURE);
    }

    free(unit_path);
    sd_bus_message_unref(reply);
    return result;
}

static void require_access_denied(sd_bus *bus, const char *operation, const char *unit) {
    sd_bus_error error = SD_BUS_ERROR_NULL;
    int result = call_operation(bus, operation, unit, &error);
    if (result >= 0 || !sd_bus_error_has_name(&error, SD_BUS_ERROR_ACCESS_DENIED))
        fail_bus(operation, result, &error);

    printf("ACCESS_DENIED %s %s\n", operation, error.name);
    sd_bus_error_free(&error);
}

static void require_call(sd_bus *bus,
                         const char *path,
                         const char *interface,
                         const char *member,
                         const char *signature,
                         const char *unit) {
    sd_bus_error error = SD_BUS_ERROR_NULL;
    sd_bus_message *reply = NULL;
    int result;
    if (signature == NULL)
        result = sd_bus_call_method(bus,
                                    MANAGER_DESTINATION,
                                    path,
                                    interface,
                                    member,
                                    &error,
                                    &reply,
                                    NULL);
    else
        result = sd_bus_call_method(bus,
                                    MANAGER_DESTINATION,
                                    path,
                                    interface,
                                    member,
                                    &error,
                                    &reply,
                                    signature,
                                    unit);
    if (result < 0)
        fail_bus(member, result, &error);
    sd_bus_message_unref(reply);
    sd_bus_error_free(&error);
}

static void require_collection(sd_bus *bus, const char *unit) {
    char *path = get_unit_path(bus, unit);
    require_call(bus, MANAGER_PATH, MANAGER_INTERFACE, "RefUnit", "s", unit);
    require_call(bus, path, UNIT_INTERFACE, "Ref", NULL, NULL);
    require_call(bus, path, UNIT_INTERFACE, "Unref", NULL, NULL);

    sd_bus_error stop_error = SD_BUS_ERROR_NULL;
    sd_bus_message *stop_reply = NULL;
    int result = sd_bus_call_method(bus,
                                    MANAGER_DESTINATION,
                                    MANAGER_PATH,
                                    MANAGER_INTERFACE,
                                    "StopUnit",
                                    &stop_error,
                                    &stop_reply,
                                    "ss",
                                    unit,
                                    "replace");
    if (result < 0)
        fail_bus("StopUnit", result, &stop_error);
    sd_bus_message_unref(stop_reply);
    sd_bus_error_free(&stop_error);

    bool inactive = false;
    for (unsigned attempt = 0; attempt < 500; ++attempt) {
        char *state = NULL;
        result = sd_bus_get_property_string(bus,
                                            MANAGER_DESTINATION,
                                            path,
                                            UNIT_INTERFACE,
                                            "ActiveState",
                                            NULL,
                                            &state);
        if (result >= 0 && state != NULL && strcmp(state, "inactive") == 0)
            inactive = true;
        free(state);
        if (inactive)
            break;
        usleep(10000);
    }
    if (!inactive) {
        fprintf(stderr, "referenced unit did not reach inactive state\n");
        exit(EXIT_FAILURE);
    }

    char *held_path = get_unit_path(bus, unit);
    if (strcmp(held_path, path) != 0) {
        fprintf(stderr, "referenced unit object path changed\n");
        exit(EXIT_FAILURE);
    }
    free(held_path);
    require_call(bus, MANAGER_PATH, MANAGER_INTERFACE, "UnrefUnit", "s", unit);

    bool collected = false;
    for (unsigned attempt = 0; attempt < 500; ++attempt) {
        sd_bus_error error = SD_BUS_ERROR_NULL;
        sd_bus_message *reply = NULL;
        result = sd_bus_call_method(bus,
                                    MANAGER_DESTINATION,
                                    MANAGER_PATH,
                                    MANAGER_INTERFACE,
                                    "GetUnit",
                                    &error,
                                    &reply,
                                    "s",
                                    unit);
        sd_bus_message_unref(reply);
        if (result < 0 && sd_bus_error_has_name(&error,
                                                "org.freedesktop.systemd1.NoSuchUnit"))
            collected = true;
        else if (result < 0)
            fail_bus("GetUnit after UnrefUnit", result, &error);
        sd_bus_error_free(&error);
        if (collected)
            break;
        usleep(10000);
    }
    free(path);
    if (!collected) {
        fprintf(stderr, "unit remained loaded after final UnrefUnit\n");
        exit(EXIT_FAILURE);
    }
    puts("ROOT_REFERENCE_COLLECTION_OK");
}

int main(int argc, char **argv) {
    if (argc != 3) {
        fprintf(stderr, "usage: %s deny-operation|root-collection unit\n", argv[0]);
        return EXIT_FAILURE;
    }

    sd_bus *bus = NULL;
    int result = sd_bus_open_system(&bus);
    if (result < 0)
        fail_bus("sd_bus_open_system", result, NULL);

    if (strcmp(argv[1], "root-collection") == 0)
        require_collection(bus, argv[2]);
    else
        require_access_denied(bus, argv[1], argv[2]);
    sd_bus_unref(bus);
    return EXIT_SUCCESS;
}
