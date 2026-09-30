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

/* Package-only cohort tests: role tags supply fixture classifications, not
 * QEMU reader/Source authority. Native tests independently join actual owners.
 */
typedef struct ControlFixture {
    GMainContext *context;
    GCrucibleMainContextControlHold control;
    GMutex mutex;
    GCond cond;
    gboolean run;
    gboolean entered;
    gboolean resume;
    gboolean finished;
    gboolean invoke_unknown;
    guint controls;
    guint parked_prepare;
    guint parked_check;
    guint parked_dispatch;
    guint unknown_callbacks;
} ControlFixture;

typedef struct ParkedSource {
    GSource source;
    ControlFixture *fixture;
} ParkedSource;

static gboolean parked_prepare(GSource *source, gint *timeout)
{
    ((ParkedSource *)source)->fixture->parked_prepare++;
    *timeout = 0;
    return TRUE;
}

static gboolean parked_check(GSource *source)
{
    ((ParkedSource *)source)->fixture->parked_check++;
    return TRUE;
}

static gboolean parked_dispatch(GSource *source, GSourceFunc callback,
                                gpointer data)
{
    ((ParkedSource *)source)->fixture->parked_dispatch++;
    return G_SOURCE_CONTINUE;
}

static GSourceFuncs parked_source_funcs = {
    parked_prepare, parked_check, parked_dispatch, NULL, NULL, NULL,
};

static gboolean unknown_control_invoke(gpointer opaque)
{
    ((ControlFixture *)opaque)->unknown_callbacks++;
    return G_SOURCE_REMOVE;
}

static void wait_control_fixture(ControlFixture *fixture, gboolean *condition)
{
    gint64 deadline = g_get_monotonic_time() + 5000000;

    while (!*condition) {
        g_assert_true(g_cond_wait_until(&fixture->cond, &fixture->mutex,
                                        deadline));
    }
}

static gboolean bounded_control_callback(gpointer opaque)
{
    ControlFixture *fixture = opaque;

    g_assert_true(g_main_context_is_owner(fixture->context));
    g_assert_true(g_main_context_get_thread_default() == fixture->context);
    fixture->controls++;
    if (fixture->invoke_unknown) {
        fixture->invoke_unknown = FALSE;
        g_main_context_invoke(fixture->context, unknown_control_invoke, fixture);
        g_assert_cmpuint(fixture->unknown_callbacks, ==, 0);
    }
    g_mutex_lock(&fixture->mutex);
    fixture->entered = TRUE;
    g_cond_broadcast(&fixture->cond);
    wait_control_fixture(fixture, &fixture->resume);
    g_mutex_unlock(&fixture->mutex);
    return G_SOURCE_CONTINUE;
}

static gpointer control_reader(gpointer opaque)
{
    ControlFixture *fixture = opaque;

    g_mutex_lock(&fixture->mutex);
    wait_control_fixture(fixture, &fixture->run);
    g_mutex_unlock(&fixture->mutex);
    g_crucible_main_context_control_iteration(&fixture->control);
    g_mutex_lock(&fixture->mutex);
    fixture->finished = TRUE;
    g_cond_broadcast(&fixture->cond);
    g_mutex_unlock(&fixture->mutex);
    return NULL;
}

static void test_closed_control_cohort(gconstpointer opaque)
{
    gboolean invoke_unknown = GPOINTER_TO_INT(opaque);
    ControlFixture fixture = { .invoke_unknown = invoke_unknown };
    GCrucibleMainContextRegistryHold registry = { 0 };
    GMainContext *contexts[64];
    GCrucibleMainContextHold holds[64] = { 0 };
    GCrucibleSourceObservation observations[8];
    GCrucibleMainContextObservation observation;
    GCrucibleMainContextControlHold copied;
    GSource *control_source = g_idle_source_new();
    GSource *parked_source = g_source_new(&parked_source_funcs,
                                         sizeof(ParkedSource));
    GSource *unknown = g_idle_source_new();
    GThread *reader;
    guint count = 0;
    guint control_context = G_MAXUINT;

    g_mutex_init(&fixture.mutex);
    g_cond_init(&fixture.cond);
    fixture.context = g_main_context_new();
    ((ParkedSource *)parked_source)->fixture = &fixture;
    g_crucible_source_set_role(control_source, G_CRUCIBLE_SOURCE_CONTROL,
                               &fixture);
    g_crucible_source_set_role(parked_source, G_CRUCIBLE_SOURCE_NATIVE_AIO,
                               parked_source);
    g_source_set_callback(control_source, bounded_control_callback, &fixture,
                          NULL);
    g_source_attach(control_source, fixture.context);
    g_source_attach(parked_source, fixture.context);
    g_source_attach(unknown, fixture.context);
    reader = g_thread_new("closed-control-reader", control_reader, &fixture);

    g_assert_true(g_crucible_main_contexts_try_hold(&registry, contexts, holds,
                                                   64, &count));
    for (guint index = 0; index < count; index++) {
        if (contexts[index] == fixture.context) {
            control_context = index;
        }
    }
    g_assert_cmpuint(control_context, !=, G_MAXUINT);
    g_assert_true(g_crucible_main_context_inventory(&holds[control_context],
        observations, 8, &observation));
    g_assert_false(g_crucible_main_context_control_try_arm(&registry,
        &holds[control_context], observations, observation.sources, reader,
        &fixture.control));
    g_assert_null(fixture.control.context);

    g_source_destroy(unknown);
    g_source_unref(unknown);
    unknown = NULL;
    g_assert_true(g_crucible_main_context_registry_refresh(&registry, contexts,
                                                          holds, count));
    g_assert_true(g_crucible_main_context_inventory(&holds[control_context],
        observations, 8, &observation));
    g_assert_true(g_crucible_main_context_control_try_arm(&registry,
        &holds[control_context], observations, observation.sources, reader,
        &fixture.control));
    g_assert_true(g_crucible_main_context_control_current(&fixture.control));
    copied = fixture.control;
    g_assert_false(g_crucible_main_context_control_current(&copied));
    g_assert_false(g_crucible_main_context_control_iteration(&fixture.control));
    g_assert_false(g_crucible_main_context_control_iteration(&copied));
    g_assert_false(g_crucible_main_context_registry_release(&registry));
    g_assert_false(g_crucible_main_context_release(&holds[control_context]));
    g_assert_true(g_crucible_main_context_dispatch_fenced());

    g_mutex_lock(&fixture.mutex);
    fixture.run = TRUE;
    g_cond_broadcast(&fixture.cond);
    wait_control_fixture(&fixture, &fixture.entered);
    g_mutex_unlock(&fixture.mutex);
    g_assert_cmpuint(fixture.parked_prepare, ==, 0);
    g_assert_cmpuint(fixture.parked_check, ==, 0);
    g_assert_cmpuint(fixture.parked_dispatch, ==, 0);
    g_assert_false(g_crucible_main_context_control_try_release(&fixture.control));
    g_assert_nonnull(fixture.control.context);
    g_assert_false(g_crucible_main_context_release(&holds[control_context]));
    g_assert_false(g_crucible_main_context_registry_release(&registry));

    g_mutex_lock(&fixture.mutex);
    fixture.resume = TRUE;
    g_cond_broadcast(&fixture.cond);
    wait_control_fixture(&fixture, &fixture.finished);
    g_mutex_unlock(&fixture.mutex);
    g_thread_join(reader);
    g_assert_cmpuint(fixture.controls, ==, 1);
    g_assert_cmpuint(fixture.parked_prepare, ==, 0);
    g_assert_cmpuint(fixture.parked_check, ==, 0);
    g_assert_cmpuint(fixture.parked_dispatch, ==, 0);
    g_assert_cmpuint(fixture.unknown_callbacks, ==, 0);
    g_assert_false(g_crucible_main_context_control_current(&fixture.control));
    g_assert_true(g_crucible_main_context_control_try_release(&fixture.control));
    g_assert_null(fixture.control.context);
    g_assert_true(g_crucible_main_context_dispatch_fenced());
    for (guint index = 0; index < count; index++) {
        release_context(&holds[index]);
        g_main_context_unref(contexts[index]);
    }
    release_registry(&registry);
    g_assert_false(g_crucible_main_context_dispatch_fenced());
    g_assert_true(g_main_context_iteration(fixture.context, FALSE));
    g_assert_cmpuint(fixture.parked_prepare, >, 0);
    g_assert_cmpuint(fixture.parked_dispatch, >, 0);
    if (invoke_unknown) {
        g_assert_cmpuint(fixture.unknown_callbacks, ==, 1);
    }

    g_source_destroy(control_source);
    g_source_destroy(parked_source);
    g_source_unref(control_source);
    g_source_unref(parked_source);
    if (unknown) {
        g_source_unref(unknown);
    }
    g_main_context_unref(fixture.context);
    g_cond_clear(&fixture.cond);
    g_mutex_clear(&fixture.mutex);
}

typedef struct ControlEntryRace {
    GCrucibleMainContextControlHold control;
    gint run;
    gint stop;
    gint probes;
    gint callbacks;
} ControlEntryRace;

static gboolean entry_race_callback(gpointer opaque)
{
    ControlEntryRace *race = opaque;

    g_assert_true(g_main_context_is_owner(race->control.context));
    g_atomic_int_inc(&race->callbacks);
    return G_SOURCE_CONTINUE;
}

static gpointer entry_race_reader(gpointer opaque)
{
    ControlEntryRace *race = opaque;

    while (!g_atomic_int_get(&race->run)) {
        g_thread_yield();
    }
    while (!g_atomic_int_get(&race->stop)) {
        /* Both public current and entry overlap release before/after active
         * publication. The token storage stays alive until this thread joins.
         */
        g_crucible_main_context_control_current(&race->control);
        g_crucible_main_context_control_iteration(&race->control);
        g_atomic_int_inc(&race->probes);
    }
    return NULL;
}

static void test_control_entry_release_race(void)
{
    ControlEntryRace race = { 0 };
    GMainContext *context = g_main_context_new();
    GMainContext *contexts[64];
    GCrucibleMainContextHold holds[64] = { 0 };
    GCrucibleMainContextRegistryHold registry = { 0 };
    GCrucibleSourceObservation sources[8];
    GCrucibleMainContextObservation observation;
    GSource *source = g_idle_source_new();
    GThread *reader;
    guint count = 0;
    guint selected = G_MAXUINT;
    gint64 deadline;

    g_crucible_source_set_role(source, G_CRUCIBLE_SOURCE_CONTROL, &race);
    g_source_set_callback(source, entry_race_callback, &race, NULL);
    g_source_attach(source, context);
    reader = g_thread_new("control-entry-race", entry_race_reader, &race);
    g_assert_true(g_crucible_main_contexts_try_hold(&registry, contexts, holds,
                                                   64, &count));
    for (guint index = 0; index < count; index++) {
        if (contexts[index] == context) {
            selected = index;
        }
    }
    g_assert_cmpuint(selected, !=, G_MAXUINT);
    g_assert_true(g_crucible_main_context_inventory(&holds[selected], sources,
                                                    8, &observation));
    g_assert_true(g_crucible_main_context_control_try_arm(&registry,
        &holds[selected], sources, observation.sources, reader, &race.control));
    g_atomic_int_set(&race.run, 1);
    deadline = g_get_monotonic_time() + 5000000;
    while (g_atomic_int_get(&race.probes) < 1000) {
        g_assert_cmpint(g_get_monotonic_time(), <, deadline);
        g_thread_yield();
    }
    while (!g_crucible_main_context_control_try_release(&race.control)) {
        g_assert_cmpint(g_get_monotonic_time(), <, deadline);
        g_assert_true(g_crucible_main_context_dispatch_fenced());
        g_thread_yield();
    }
    /* Keep the actual reader probing the cleared token before releasing the
     * context references: every public path must reject without dereferencing
     * ordinary identity fields cleared by the acknowledged release.
     */
    g_assert_false(g_crucible_main_context_control_current(&race.control));
    g_atomic_int_set(&race.stop, 1);
    g_thread_join(reader);
    for (guint index = 0; index < count; index++) {
        release_context(&holds[index]);
        g_main_context_unref(contexts[index]);
    }
    release_registry(&registry);
    g_source_destroy(source);
    g_source_unref(source);
    g_main_context_unref(context);
}

static void test_control_after_fork_membership(void)
{
    ControlFixture fixture = { 0 };
    GCrucibleMainContextRegistryHold registry = { 0 };
    GMainContext *contexts[64];
    GCrucibleMainContextHold holds[64] = { 0 };
    GCrucibleSourceObservation observations[8];
    GCrucibleMainContextObservation observation;
    GSource *source = g_idle_source_new();
    GThread *reader;
    guint count = 0;
    guint selected = G_MAXUINT;
    guint source_id;
    pid_t child;
    int status;

    g_mutex_init(&fixture.mutex);
    g_cond_init(&fixture.cond);
    fixture.context = g_main_context_new();
    g_crucible_source_set_role(source, G_CRUCIBLE_SOURCE_CONTROL, &fixture);
    g_source_set_callback(source, bounded_control_callback, &fixture, NULL);
    source_id = g_source_attach(source, fixture.context);
    reader = g_thread_new("parent-control-reader", control_reader, &fixture);
    g_assert_true(g_crucible_main_contexts_try_hold(&registry, contexts, holds,
                                                   64, &count));
    for (guint index = 0; index < count; index++) {
        if (contexts[index] == fixture.context) {
            selected = index;
        }
    }
    g_assert_cmpuint(selected, !=, G_MAXUINT);
    g_assert_true(g_crucible_main_context_inventory(&holds[selected],
        observations, 8, &observation));
    g_assert_true(g_crucible_main_context_control_try_arm(&registry,
        &holds[selected], observations, observation.sources, reader,
        &fixture.control));
    child = fork();
    g_assert_cmpint(child, >=, 0);
    if (!child) {
        GCrucibleMainContextControlHold copied = fixture.control;
        GCrucibleMainContextRegistryHold stale = registry;

        stale.generation++;
        g_assert_false(g_crucible_main_context_control_current(&fixture.control));
        g_assert_false(g_crucible_main_context_registry_after_fork_child(
            &stale, contexts, holds, count));
        g_assert_true(g_crucible_main_context_registry_after_fork_child(
            &registry, contexts, holds, count));
        g_assert_null(fixture.control.context);
        g_assert_false(g_crucible_main_context_control_current(&copied));
        g_assert_false(g_crucible_main_context_control_iteration(&copied));
        g_assert_true(g_source_get_context(source) == fixture.context);
        g_assert_cmpuint(g_source_get_id(source), ==, source_id);
        g_assert_true(g_crucible_main_context_inventory(&holds[selected],
            observations, 8, &observation));
        g_assert_cmpuint(observation.sources, ==, 1);
        g_assert_true(observations[0].source == source);
        g_assert_cmpuint(observations[0].source_id, ==, source_id);
        g_assert_false(g_main_context_iteration(fixture.context, FALSE));
        for (guint index = 0; index < count; index++) {
            g_assert_true(g_crucible_main_context_current(&holds[index]));
            release_context(&holds[index]);
            g_main_context_unref(contexts[index]);
        }
        release_registry(&registry);
        g_source_destroy(source);
        g_source_unref(source);
        g_main_context_unref(fixture.context);
        _exit(0);
    }
    g_assert_cmpint(waitpid(child, &status, 0), ==, child);
    g_assert_true(WIFEXITED(status));
    g_assert_cmpint(WEXITSTATUS(status), ==, 0);
    g_assert_true(g_crucible_main_context_control_current(&fixture.control));
    g_assert_true(g_source_get_context(source) == fixture.context);
    g_assert_cmpuint(g_source_get_id(source), ==, source_id);
    g_assert_true(g_crucible_main_context_control_try_release(&fixture.control));
    for (guint index = 0; index < count; index++) {
        release_context(&holds[index]);
        g_main_context_unref(contexts[index]);
    }
    release_registry(&registry);
    g_mutex_lock(&fixture.mutex);
    fixture.run = TRUE;
    fixture.resume = TRUE;
    g_cond_broadcast(&fixture.cond);
    g_mutex_unlock(&fixture.mutex);
    g_thread_join(reader);
    g_source_destroy(source);
    g_source_unref(source);
    g_main_context_unref(fixture.context);
    g_cond_clear(&fixture.cond);
    g_mutex_clear(&fixture.mutex);
}

typedef struct ForeignInventoryFixture {
    GCrucibleMainContextRegistryHold registry;
    GMainContext *contexts[64];
    GCrucibleMainContextHold holds[64];
    GCrucibleMainContextObservation observations[64];
    guint count;
    gboolean current;
} ForeignInventoryFixture;

static gpointer foreign_inventory_current(gpointer opaque)
{
    ForeignInventoryFixture *fixture = opaque;

    g_assert_true(fixture->registry.thread != g_thread_self());
    fixture->current = g_crucible_main_contexts_inventory_current(
        &fixture->registry, fixture->contexts, fixture->holds,
        fixture->observations, fixture->count);
    return NULL;
}

static gboolean foreign_inventory_probe(ForeignInventoryFixture *fixture)
{
    GThread *reader = g_thread_new("foreign-census", foreign_inventory_current,
                                   fixture);

    g_thread_join(reader);
    return fixture->current;
}

static void test_foreign_inventory_freshness(void)
{
    ForeignInventoryFixture fixture = { 0 };
    GMainContext *context = g_main_context_new();
    GSource *source = g_timeout_source_new(1000);
    GSource *attached;
    GCrucibleSourceObservation sources[8];
    guint selected = G_MAXUINT;

    g_source_set_callback(source, count_callback, NULL, NULL);
    g_source_attach(source, context);
    g_assert_true(g_crucible_main_contexts_try_hold(&fixture.registry,
        fixture.contexts, fixture.holds, 64, &fixture.count));
    for (guint index = 0; index < fixture.count; index++) {
        g_assert_true(g_crucible_main_context_inventory(&fixture.holds[index],
            sources, 8, &fixture.observations[index]));
        if (fixture.contexts[index] == context) {
            selected = index;
        }
    }
    g_assert_cmpuint(selected, !=, G_MAXUINT);
    g_assert_true(foreign_inventory_probe(&fixture));
    fixture.observations[selected].sources++;
    g_assert_false(foreign_inventory_probe(&fixture));
    fixture.observations[selected].sources--;
    g_assert_true(foreign_inventory_probe(&fixture));
    g_source_set_ready_time(source, 0);
    g_assert_false(foreign_inventory_probe(&fixture));
    g_assert_true(g_crucible_main_context_registry_refresh(&fixture.registry,
        fixture.contexts, fixture.holds, fixture.count));
    for (guint index = 0; index < fixture.count; index++) {
        g_assert_true(g_crucible_main_context_inventory(&fixture.holds[index],
            sources, 8, &fixture.observations[index]));
    }
    g_assert_true(foreign_inventory_probe(&fixture));
    attached = g_idle_source_new();
    g_source_set_callback(attached, count_callback, NULL, NULL);
    g_source_attach(attached, context);
    g_assert_false(foreign_inventory_probe(&fixture));
    g_assert_false(g_main_context_iteration(context, FALSE));
    for (guint index = 0; index < fixture.count; index++) {
        release_context(&fixture.holds[index]);
    }
    release_registry(&fixture.registry);
    g_assert_false(foreign_inventory_probe(&fixture));
    for (guint index = 0; index < fixture.count; index++) {
        g_main_context_unref(fixture.contexts[index]);
    }
    g_source_destroy(attached);
    g_source_unref(attached);
    g_source_destroy(source);
    g_source_unref(source);
    g_main_context_unref(context);
}

#if GLIB_CHECK_VERSION(2, 89, 0)
static void test_nanosecond_ready_time_fence(void)
{
    GMainContext *context = g_main_context_new();
    GSource *source = g_timeout_source_new(100000);
    GCrucibleMainContextHold hold = { 0 };
    GCrucibleSourceObservation sources[1];
    GCrucibleMainContextObservation observation;
    uint64_t ready_time;

    g_source_set_callback(source, count_callback, NULL, NULL);
    g_source_attach(source, context);
    g_source_clear_ready_time(source);
    g_assert_true(g_crucible_main_context_try_hold(context, &hold));
    g_assert_true(g_crucible_main_context_inventory(&hold, sources, 1,
                                                   &observation));
    g_assert_false(sources[0].armed);

    g_source_set_ready_time_ns(source, 7);
    g_assert_false(g_crucible_main_context_current(&hold));
    g_assert_true(g_source_get_ready_time_ns(source, &ready_time));
    g_assert_cmpuint(ready_time, ==, 7);
    release_context(&hold);

    g_assert_true(g_crucible_main_context_try_hold(context, &hold));
    g_assert_true(g_crucible_main_context_inventory(&hold, sources, 1,
                                                   &observation));
    g_assert_true(sources[0].armed);

    /* Both values ceil to the same public microsecond coordinate. A genuine
     * nanosecond mutation must still revoke the exact physical inventory.
     */
    g_source_set_ready_time_ns(source, 8);
    g_assert_false(g_crucible_main_context_current(&hold));
    g_assert_true(g_source_get_ready_time_ns(source, &ready_time));
    g_assert_cmpuint(ready_time, ==, 8);
    release_context(&hold);

    g_assert_true(g_crucible_main_context_try_hold(context, &hold));
    g_source_clear_ready_time(source);
    g_assert_false(g_crucible_main_context_current(&hold));
    g_assert_false(g_source_get_ready_time_ns(source, &ready_time));
    release_context(&hold);

    g_source_destroy(source);
    g_source_unref(source);
    g_main_context_unref(context);
}

static void test_multi_reference_unref_fence(void)
{
    GMainContext *context = g_main_context_new();
    GSource *source = g_idle_source_new();
    GCrucibleMainContextHold hold = { 0 };

    g_source_set_callback(source, count_callback, NULL, NULL);
    g_source_attach(source, context);
    g_source_ref(source);
    g_assert_true(g_crucible_main_context_try_hold(context, &hold));

    /* Upstream can decrement multiple references without running disposal.
     * Public lifetime mutations still invalidate the retained cohort first.
     */
    g_source_unref(source);
    g_assert_false(g_crucible_main_context_current(&hold));
    release_context(&hold);

    g_source_destroy(source);
    g_source_unref(source);
    g_main_context_unref(context);
}
#endif

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
    g_test_add_data_func("/crucible/closed-control-cohort", GINT_TO_POINTER(0),
                          test_closed_control_cohort);
    g_test_add_data_func("/crucible/control-invoke-unknown-queued", GINT_TO_POINTER(1),
                          test_closed_control_cohort);
    g_test_add_func("/crucible/control-entry-release-race",
                    test_control_entry_release_race);
    g_test_add_func("/crucible/control-after-fork-membership",
                    test_control_after_fork_membership);
    g_test_add_func("/crucible/foreign-inventory-freshness",
                    test_foreign_inventory_freshness);
#if GLIB_CHECK_VERSION(2, 89, 0)
    g_test_add_func("/crucible/nanosecond-ready-time-fence",
                    test_nanosecond_ready_time_fence);
    g_test_add_func("/crucible/multi-reference-unref-fence",
                    test_multi_reference_unref_fence);
#endif
    return g_test_run();
}
