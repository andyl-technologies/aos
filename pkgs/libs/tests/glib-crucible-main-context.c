/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include <glib/gcrucible-main-context.h>
#include <poll.h>
#include <unistd.h>
#include <sys/wait.h>

static guint callbacks;

static void release_context(GCrucibleMainContextHold *hold)
{
    gint64 deadline = g_get_monotonic_time() + 5000000;

    while (!g_crucible_main_context_release(hold)) {
        g_assert_nonnull(hold->context);
        g_assert_cmpint(g_get_monotonic_time(), <, deadline);
        g_thread_yield();
    }
}

static void release_registry(GCrucibleMainContextRegistryHold *hold)
{
    gint64 deadline = g_get_monotonic_time() + 5000000;

    while (!g_crucible_main_context_registry_release(hold)) {
        g_assert_cmpint(hold->generation, >, 0);
        g_assert_cmpint(g_get_monotonic_time(), <, deadline);
        g_thread_yield();
    }
}


static gboolean count_callback(gpointer opaque)
{
    callbacks++;
    return G_SOURCE_CONTINUE;
}

static void test_library_sources(void)
{
    GMainContext *context = g_main_context_default();
    GCrucibleMainContextHold hold = { 0 };
    GCrucibleMainContextObservation observation;
    GCrucibleSourceObservation sources[8];
    guint idle = g_idle_add(count_callback, NULL);
    guint timeout = g_timeout_add(100000, count_callback, NULL);
    guint unknown = 0;

    g_assert_true(g_crucible_main_context_try_hold(context, &hold));
    g_assert_true(g_crucible_main_context_inventory(&hold, sources, 8,
                                                   &observation));
    for (guint i = 0; i < observation.sources; i++) {
        unknown += sources[i].role == G_CRUCIBLE_SOURCE_UNKNOWN;
    }
    g_assert_cmpuint(observation.sources, ==, 2);
    g_assert_cmpuint(unknown, ==, 2);
    g_assert_cmpuint(observation.active_callbacks, ==, 0);
    g_assert_false(g_main_context_iteration(context, FALSE));
    g_assert_cmpuint(callbacks, ==, 0);
    g_assert_true(g_crucible_main_context_current(&hold));

    release_context(&hold);
    g_assert_false(g_crucible_main_context_current(&hold));
    g_assert_true(g_source_remove(idle));
    g_assert_true(g_source_remove(timeout));
}

static void test_rearm_and_role_stale(void)
{
    GMainContext *context = g_main_context_new();
    GSource *source = g_timeout_source_new(100000);
    GCrucibleMainContextHold hold = { 0 };
    GCrucibleSourceObservation sources[2];
    GCrucibleMainContextObservation observation;

    g_crucible_source_set_role(source, G_CRUCIBLE_SOURCE_NATIVE_AIO, source);
    g_source_set_callback(source, count_callback, NULL, NULL);
    g_source_attach(source, context);
    g_assert_true(g_crucible_main_context_try_hold(context, &hold));
    g_assert_true(g_crucible_main_context_inventory(&hold, sources, 2,
                                                   &observation));
    g_assert_true(sources[0].source == source && sources[0].owner == source);
    g_source_set_ready_time(source, 0);
    g_assert_false(g_crucible_main_context_current(&hold));
    observation.sources = 123;
    g_assert_false(g_crucible_main_context_inventory(&hold, sources, 2,
                                                    &observation));
    g_assert_cmpuint(observation.sources, ==, 123);
    g_assert_false(g_main_context_iteration(context, FALSE));
    g_assert_cmpuint(callbacks, ==, 0);
    release_context(&hold);

    g_assert_true(g_crucible_main_context_try_hold(context, &hold));
    g_crucible_source_set_role(source, G_CRUCIBLE_SOURCE_UNKNOWN, NULL);
    g_assert_false(g_crucible_main_context_current(&hold));
    release_context(&hold);
    g_source_destroy(source);
    g_source_unref(source);
    g_main_context_unref(context);
}

typedef struct Mutation {
    GMainContext *context;
    GSource *source;
    gboolean destroy;
    gboolean create_context;
    gint started;
    gint finished;
} Mutation;

static gpointer foreign_mutation(gpointer opaque)
{
    Mutation *mutation = opaque;

    g_atomic_int_set(&mutation->started, 1);
    if (mutation->create_context) {
        GMainContext *context = g_main_context_new();
        GSource *idle = g_idle_source_new();
        g_source_set_callback(idle, count_callback, NULL, NULL);
        g_source_attach(idle, context);
        g_atomic_int_set(&mutation->finished, 1);
        g_source_destroy(idle);
        g_source_unref(idle);
        g_main_context_unref(context);
    } else if (mutation->destroy) {
        g_source_destroy(mutation->source);
        g_atomic_int_set(&mutation->finished, 1);
    } else {
        g_source_attach(mutation->source, mutation->context);
        g_atomic_int_set(&mutation->finished, 1);
    }
    return NULL;
}

static void wait_until_stale(const GCrucibleMainContextHold *hold)
{
    /* Wall time bounds a test failure; it never certifies source quiescence. */
    gint64 deadline = g_get_monotonic_time() + 5000000;

    while (g_crucible_main_context_current(hold) &&
           g_get_monotonic_time() < deadline) {
        g_thread_yield();
    }
    g_assert_false(g_crucible_main_context_current(hold));
}

static void test_foreign_source_fence(void)
{
    GMainContext *context = g_main_context_new();
    GSource *source = g_idle_source_new();
    GCrucibleMainContextHold hold = { 0 };
    Mutation mutation = { .context = context, .source = source };
    GThread *thread;

    g_source_set_callback(source, count_callback, NULL, NULL);
    g_assert_true(g_crucible_main_context_try_hold(context, &hold));
    thread = g_thread_new("foreign-attach", foreign_mutation, &mutation);
    wait_until_stale(&hold);
    g_assert_cmpint(g_atomic_int_get(&mutation.finished), ==, 0);
    g_assert_cmpuint(callbacks, ==, 0);
    release_context(&hold);
    g_thread_join(thread);
    g_assert_cmpint(g_atomic_int_get(&mutation.finished), ==, 1);

    mutation = (Mutation) { .context = context, .source = source,
                            .destroy = TRUE };
    g_assert_true(g_crucible_main_context_try_hold(context, &hold));
    thread = g_thread_new("foreign-destroy", foreign_mutation, &mutation);
    wait_until_stale(&hold);
    g_assert_cmpint(g_atomic_int_get(&mutation.finished), ==, 0);
    g_assert_false(g_source_is_destroyed(source));
    release_context(&hold);
    g_thread_join(thread);
    g_assert_true(g_source_is_destroyed(source));
    g_source_unref(source);
    g_main_context_unref(context);
}

static void test_new_context_fence(void)
{
    GCrucibleMainContextRegistryHold registry = { 0 };
    GMainContext *contexts[16];
    guint count;
    Mutation mutation = { .create_context = TRUE };
    GThread *thread;
    gint64 deadline;

    g_assert_true(g_crucible_main_context_registry_try_hold(&registry,
                                                           contexts, 16, &count));
    thread = g_thread_new("foreign-new-context", foreign_mutation, &mutation);
    deadline = g_get_monotonic_time() + 5000000;
    while (g_crucible_main_context_registry_current(&registry) &&
           g_get_monotonic_time() < deadline) {
        g_thread_yield();
    }
    g_assert_false(g_crucible_main_context_registry_current(&registry));
    g_assert_cmpint(g_atomic_int_get(&mutation.finished), ==, 0);
    g_assert_cmpuint(callbacks, ==, 0);
    for (guint i = 0; i < count; i++) {
        g_main_context_unref(contexts[i]);
    }
    release_registry(&registry);
    g_thread_join(thread);
    g_assert_cmpint(g_atomic_int_get(&mutation.finished), ==, 1);
}

typedef struct MainLoopOwner {
    GMainContext *context;
    GMutex bql;
    gint acquired;
    gint parked;
    int pipe_fds[2];
} MainLoopOwner;

static gpointer physical_main_loop(gpointer opaque)
{
    MainLoopOwner *owner = opaque;
    struct pollfd fd = { .fd = owner->pipe_fds[0], .events = POLLIN };
    char byte;

    g_assert_true(g_main_context_acquire(owner->context));
    g_atomic_int_set(&owner->acquired, 1);
    g_assert_cmpint(poll(&fd, 1, 5000), ==, 1);
    g_assert_cmpint(read(fd.fd, &byte, 1), ==, 1);
    /* Matches the real main-loop seam: context ownership ends BEFORE BQL. */
    g_main_context_release(owner->context);
    g_assert_false(g_mutex_trylock(&owner->bql));
    g_atomic_int_set(&owner->parked, 1);
    g_mutex_lock(&owner->bql);
    g_mutex_unlock(&owner->bql);
    return NULL;
}

static void test_context_owner_bql_order(void)
{
    MainLoopOwner owner = { .context = g_main_context_new() };
    GCrucibleMainContextHold hold = { 0 };
    GThread *thread;
    gint64 deadline;

    g_mutex_init(&owner.bql);
    g_mutex_lock(&owner.bql);
    g_assert_cmpint(pipe(owner.pipe_fds), ==, 0);
    thread = g_thread_new("physical-main-loop", physical_main_loop, &owner);
    deadline = g_get_monotonic_time() + 5000000;
    while (!g_atomic_int_get(&owner.acquired) &&
           g_get_monotonic_time() < deadline) {
        g_thread_yield();
    }
    g_assert_cmpint(g_atomic_int_get(&owner.acquired), ==, 1);
    g_assert_false(g_crucible_main_context_try_hold(owner.context, &hold));
    g_assert_cmpint(write(owner.pipe_fds[1], "x", 1), ==, 1);
    while (!g_atomic_int_get(&owner.parked) &&
           g_get_monotonic_time() < deadline) {
        g_thread_yield();
    }
    g_assert_cmpint(g_atomic_int_get(&owner.parked), ==, 1);
    g_assert_true(g_crucible_main_context_try_hold(owner.context, &hold));
    g_assert_true(g_crucible_main_context_current(&hold));
    release_context(&hold);
    g_mutex_unlock(&owner.bql);
    g_thread_join(thread);
    close(owner.pipe_fds[0]);
    close(owner.pipe_fds[1]);
    g_mutex_clear(&owner.bql);
    g_main_context_unref(owner.context);
}

static gboolean active_callback(gpointer opaque)
{
    GCrucibleMainContextHold hold = { 0 };

    g_assert_false(g_crucible_main_context_try_hold(opaque, &hold));
    return G_SOURCE_REMOVE;
}

static void test_active_handler_refusal(void)
{
    GMainContext *context = g_main_context_new();
    GSource *source = g_idle_source_new();

    g_source_set_callback(source, active_callback, context, NULL);
    g_source_attach(source, context);
    g_assert_true(g_main_context_iteration(context, FALSE));
    g_source_unref(source);
    g_main_context_unref(context);
}

static void test_atomic_all_context_hold(void)
{
    GMainContext *context = g_main_context_new();
    GCrucibleMainContextRegistryHold registry = { 0 };
    GMainContext *contexts[16];
    GCrucibleMainContextHold holds[16] = { 0 };
    guint count = 99;

    g_assert_true(g_main_context_acquire(context));
    g_assert_false(g_crucible_main_contexts_try_hold(&registry, contexts,
                                                    holds, 16, &count));
    g_assert_cmpint(registry.generation, ==, 0);
    g_assert_false(g_crucible_main_context_dispatch_fenced());
    g_assert_cmpuint(count, ==, 99);
    g_main_context_release(context);
    g_assert_true(g_crucible_main_contexts_try_hold(&registry, contexts,
                                                   holds, 16, &count));
    g_assert_true(g_crucible_main_context_registry_current(&registry));
    for (guint i = 0; i < count; i++) {
        g_assert_true(g_crucible_main_context_current(&holds[i]));
        g_assert_false(g_main_context_iteration(contexts[i], FALSE));
        release_context(&holds[i]);
    }
    /* Even after individual contexts release, the real global fence prevents
     * Guest dispatch until its final release succeeds.
     */
    g_assert_false(g_main_context_iteration(context, FALSE));
    g_assert_true(g_crucible_main_context_dispatch_fenced());
    release_registry(&registry);
    g_assert_false(g_crucible_main_context_dispatch_fenced());
    for (guint i = 0; i < count; i++) {
        g_main_context_unref(contexts[i]);
    }
    g_main_context_unref(context);
}

static void test_holder_new_context_fence(void)
{
    GCrucibleMainContextRegistryHold registry = { 0 };
    GMainContext *contexts[16];
    GCrucibleMainContextHold holds[16] = { 0 };
    GMainContext *added;
    GSource *idle;
    guint count;

    callbacks = 0;
    g_assert_true(g_crucible_main_contexts_try_hold(&registry, contexts, holds,
                                                  G_N_ELEMENTS(holds), &count));
    added = g_main_context_new();
    idle = g_idle_source_new();
    g_source_set_callback(idle, count_callback, NULL, NULL);
    g_source_attach(idle, added);

    g_assert_false(g_crucible_main_context_registry_current(&registry));
    g_assert_false(g_main_context_iteration(added, FALSE));
    g_assert_cmpuint(callbacks, ==, 0);
    g_assert_false(g_crucible_main_context_registry_refresh(&registry,
                                                           contexts, holds, count));
    for (guint index = 0; index < count; index++) {
        release_context(&holds[index]);
        g_main_context_unref(contexts[index]);
    }
    g_assert_false(g_main_context_iteration(added, FALSE));
    g_assert_cmpuint(callbacks, ==, 0);
    release_registry(&registry);
    g_assert_true(g_main_context_iteration(added, FALSE));
    g_assert_cmpuint(callbacks, ==, 1);

    g_source_destroy(idle);
    g_source_unref(idle);
    g_main_context_unref(added);
}

static void test_registry_capacity_bound(void)
{
    GCrucibleMainContextRegistryHold registry = { 0 };
    GMainContext *added[105];
    GMainContext *observed[128];
    GMainContext *unchanged[128];
    guint count = 37;

    for (guint index = 0; index < G_N_ELEMENTS(added); index++) {
        added[index] = g_main_context_new();
    }
    for (guint index = 0; index < G_N_ELEMENTS(observed); index++) {
        observed[index] = GINT_TO_POINTER(1);
    }
    memcpy(unchanged, observed, sizeof(observed));

    /* Storage beyond the advertised capacity is guarded too: a capped size
     * estimate must never authorize an unbounded registry enumeration.
     */
    g_assert_false(g_crucible_main_context_registry_try_hold(&registry,
                                                            observed, 100, &count));
    g_assert_cmpuint(count, ==, 37);
    g_assert_cmpint(registry.generation, ==, 0);
    g_assert_cmpmem(observed, sizeof(observed), unchanged, sizeof(unchanged));
    g_assert_false(g_crucible_main_context_registry_try_hold(&registry,
                                                            observed, 65, &count));
    g_assert_false(g_crucible_main_context_registry_try_hold(&registry,
                                                            observed, 64, &count));
    g_assert_cmpuint(count, ==, 37);
    g_assert_cmpint(registry.generation, ==, 0);
    g_assert_cmpmem(observed, sizeof(observed), unchanged, sizeof(unchanged));

    for (guint index = 0; index < G_N_ELEMENTS(added); index++) {
        g_assert_true(g_main_context_acquire(added[index]));
        g_main_context_release(added[index]);
        g_main_context_unref(added[index]);
    }
}

static void test_after_fork_holder(void)
{
    GCrucibleMainContextRegistryHold registry = { 0 };
    GMainContext *contexts[16];
    GCrucibleMainContextHold holds[16] = { 0 };
    guint count;
    pid_t child;
    int status;

    g_assert_true(g_crucible_main_context_registry_try_hold(&registry,
                                                           contexts, 16, &count));
    for (guint i = 0; i < count; i++) {
        g_assert_true(g_crucible_main_context_try_hold(contexts[i], &holds[i]));
    }
    child = fork();
    g_assert_cmpint(child, >=, 0);
    if (!child) {
        GCrucibleMainContextRegistryHold stale = registry;
        stale.generation++;
        g_assert_false(g_crucible_main_context_registry_current(&registry));
        g_assert_false(g_crucible_main_context_registry_after_fork_child(
            &stale, contexts, holds, count));
        g_assert_true(g_crucible_main_context_registry_after_fork_child(
            &registry, contexts, holds, count));
        g_assert_true(g_crucible_main_context_registry_current(&registry));
        for (guint i = 0; i < count; i++) {
            g_assert_true(g_crucible_main_context_current(&holds[i]));
            g_assert_false(g_main_context_iteration(contexts[i], FALSE));
        }
        g_assert_false(g_crucible_main_context_registry_after_fork_child(
            &registry, contexts, holds, count));
        for (guint i = 0; i < count; i++) {
            release_context(&holds[i]);
            g_main_context_unref(contexts[i]);
        }
        release_registry(&registry);
        _exit(0);
    }
    g_assert_cmpint(waitpid(child, &status, 0), ==, child);
    g_assert_true(WIFEXITED(status));
    g_assert_cmpint(WEXITSTATUS(status), ==, 0);
    g_assert_true(g_crucible_main_context_registry_current(&registry));
    for (guint i = 0; i < count; i++) {
        g_assert_true(g_crucible_main_context_current(&holds[i]));
        release_context(&holds[i]);
        g_main_context_unref(contexts[i]);
    }
    release_registry(&registry);
}

int main(int argc, char **argv)
{
    g_test_init(&argc, &argv, NULL);
    g_test_add_func("/crucible/library-sources", test_library_sources);
    g_test_add_func("/crucible/rearm-role-stale", test_rearm_and_role_stale);
    g_test_add_func("/crucible/foreign-source-fence", test_foreign_source_fence);
    g_test_add_func("/crucible/new-context-fence", test_new_context_fence);
    g_test_add_func("/crucible/context-owner-bql-order", test_context_owner_bql_order);
    g_test_add_func("/crucible/active-handler-refusal", test_active_handler_refusal);
    g_test_add_func("/crucible/after-fork-holder", test_after_fork_holder);
    g_test_add_func("/crucible/registry-capacity-bound", test_registry_capacity_bound);
    g_test_add_func("/crucible/holder-new-context-fence", test_holder_new_context_fence);
    g_test_add_func("/crucible/atomic-all-context-hold", test_atomic_all_context_hold);
    return g_test_run();
}
