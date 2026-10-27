/*
 * Actual selected UART bodies under controlled external transport providers.
 * Copyright (c) 2026 Andyl, Inc.
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Includes the original 16550 and PL011 register, FIFO, reset and VMState
 * bodies. Chardev returns, readiness dispatch, input-ready and wake notices,
 * IRQ delivery and the clock are external test providers. This is not a realized
 * machine or TCG run, and controlled coordinates do not authenticate execution.
 */
#include "qemu/osdep.h"
#include "qemu/module.h"
#include "qemu/main-loop.h"
#include "system/cpu-timers.h"
#include "system/runstate.h"
#include "hw/char/serial.h"
#include "hw/char/pl011.h"
#include "hw/core/irq.h"
#include "chardev/char-fe.h"
#include "io/channel-buffer.h"
#include "migration/qemu-file.h"
#include "migration/savevm.h"

static int external_write(CharFrontend *, const uint8_t *, int);
static int external_write_all(CharFrontend *, const uint8_t *, int);
static int external_ioctl(CharFrontend *, int, void *);
static guint external_watch(CharFrontend *, GIOCondition, FEWatchFunc, void *);
static void external_accept_input(CharFrontend *);
static void external_wakeup_request(WakeupReason, Error **);
static PL011State *external_pl011_cast(void *);

/* Only external providers and unused type registration are substituted. The
 * production device bodies are included without extraction or reimplementation.
 */
#define qemu_chr_fe_write external_write
#define qemu_chr_fe_write_all external_write_all
#define qemu_chr_fe_ioctl external_ioctl
#define qemu_chr_fe_add_watch external_watch
#define qemu_chr_fe_accept_input external_accept_input
#define qemu_system_wakeup_request external_wakeup_request
#undef type_init
#define type_init(function) \
    static void *const excluded_##function __attribute__((unused)) = function;
#include "hw/char/serial.c"
#define PL011(object) external_pl011_cast(object)
#include "hw/char/pl011.c"
#undef PL011
#undef qemu_chr_fe_write
#undef qemu_chr_fe_write_all
#undef qemu_chr_fe_ioctl
#undef qemu_chr_fe_add_watch
#undef qemu_chr_fe_accept_input
#undef qemu_system_wakeup_request

#define MAX_EXTERNAL_ATTEMPTS 128

typedef struct ExternalAttempt {
    uint64_t coordinate;
    uint8_t byte;
    bool accepted;
} ExternalAttempt;

typedef struct ExternalTransport {
    bool writable;
    bool watch_available;
    FEWatchFunc watch_callback;
    void *watch_opaque;
    guint watch_id;
    ExternalAttempt attempts[MAX_EXTERNAL_ATTEMPTS];
    size_t attempt_count;
    uint8_t accepted[MAX_EXTERNAL_ATTEMPTS];
    size_t accepted_count;
    unsigned irq_calls;
    unsigned input_ready_notices;
    unsigned wake_notices;
} ExternalTransport;

static ExternalTransport transport;
static uint64_t external_coordinate;
static PL011State *pl011_owner;
static GMutex blocked_lock;
static GCond blocked_condition;
static bool write_all_entered;
static bool write_all_released;

int64_t cpu_get_clock(void)
{
    return external_coordinate;
}

void qemu_set_irq(qemu_irq irq, int level)
{
    /* No CPU or interrupt controller is realized by this provider. */
    (void)irq;
    (void)level;
    transport.irq_calls++;
}

static PL011State *external_pl011_cast(void *object)
{
    /* The reset callback's QOM cast is external; the reset body is original. */
    g_assert_true(object == pl011_owner);
    return pl011_owner;
}

static int external_ioctl(CharFrontend *frontend, int command, void *argument)
{
    (void)frontend;
    (void)command;
    (void)argument;
    return -ENOTSUP;
}

static void external_accept_input(CharFrontend *frontend)
{
    /* Observe the original UART notification, without a real chardev reader. */
    (void)frontend;
    transport.input_ready_notices++;
}

static void external_wakeup_request(WakeupReason reason, Error **error)
{
    /* There is no machine runstate: this provider records only the notice. */
    g_assert_cmpint(reason, ==, QEMU_WAKEUP_REASON_OTHER);
    g_assert_null(error);
    transport.wake_notices++;
}

static gboolean never_ready(gpointer opaque)
{
    (void)opaque;
    return G_SOURCE_CONTINUE;
}

static guint external_watch(CharFrontend *frontend, GIOCondition condition,
                            FEWatchFunc callback, void *opaque)
{
    (void)frontend;
    g_assert_cmpint(condition, ==, G_IO_OUT | G_IO_HUP);
    if (!transport.watch_available) {
        return 0;
    }
    transport.watch_callback = callback;
    transport.watch_opaque = opaque;
    /* Retain a genuine removable GLib source; readiness dispatch itself is
     * explicitly controlled, rather than inferred from elapsed host time.
     */
    transport.watch_id = g_idle_add(never_ready, NULL);
    return transport.watch_id;
}

static int external_write(CharFrontend *frontend, const uint8_t *bytes, int length)
{
    (void)frontend;
    g_assert_cmpint(length, ==, 1);
    g_assert_cmpuint(transport.attempt_count, <, MAX_EXTERNAL_ATTEMPTS);
    transport.attempts[transport.attempt_count++] = (ExternalAttempt) {
        .coordinate = external_coordinate,
        .byte = bytes[0],
        .accepted = transport.writable,
    };
    if (!transport.writable) {
        errno = EAGAIN;
        return -1;
    }
    transport.accepted[transport.accepted_count++] = bytes[0];
    return length;
}

static int external_write_all(CharFrontend *frontend,
                              const uint8_t *bytes, int length)
{
    g_mutex_lock(&blocked_lock);
    write_all_entered = true;
    g_cond_broadcast(&blocked_condition);
    while (!write_all_released) {
        g_cond_wait(&blocked_condition, &blocked_lock);
    }
    g_mutex_unlock(&blocked_lock);

    return external_write(frontend, bytes, length);
}

static void transport_initialize(bool writable)
{
    memset(&transport, 0, sizeof(transport));
    transport.writable = writable;
    transport.watch_available = true;
    external_coordinate = 0;
}

static void dispatch_original_watch(uint64_t coordinate)
{
    guint original_id = transport.watch_id;
    FEWatchFunc callback = transport.watch_callback;
    void *opaque = transport.watch_opaque;

    g_assert_cmpuint(original_id, !=, 0);
    g_assert_nonnull(g_main_context_find_source_by_id(NULL, original_id));
    transport.watch_id = 0;
    external_coordinate = coordinate;
    g_assert_false(callback(NULL, G_IO_OUT, opaque));
    g_assert_true(g_source_remove(original_id));
}

static void timer_noop(void *opaque)
{
    (void)opaque;
}

static void serial_initialize(SerialState *state)
{
    memset(state, 0, sizeof(*state));
    state->baudbase = 115200;
    state->fifo_timeout_timer = timer_new_ns(QEMU_CLOCK_VIRTUAL, timer_noop, NULL);
    state->modem_status_poll = timer_new_ns(QEMU_CLOCK_VIRTUAL, timer_noop, NULL);
    fifo8_create(&state->recv_fifo, UART_FIFO_LENGTH);
    fifo8_create(&state->xmit_fifo, UART_FIFO_LENGTH);
    serial_reset(state);
    serial_ioport_write(state, 2, UART_FCR_FE, 1);
}

static void serial_destroy(SerialState *state)
{
    serial_reset(state);
    timer_free(state->fifo_timeout_timer);
    timer_free(state->modem_status_poll);
    fifo8_destroy(&state->recv_fifo);
    fifo8_destroy(&state->xmit_fifo);
}

static void guest_write(SerialState *state, uint8_t byte, uint64_t coordinate)
{
    external_coordinate = coordinate;
    serial_ioport_write(state, 0, byte, 1);
}

static void test_serial_readiness_changes_register_visibility(void)
{
    SerialState state;
    uint64_t immediate_lsr, deferred_lsr;

    transport_initialize(true);
    serial_initialize(&state);
    guest_write(&state, 'A', 10);
    guest_write(&state, 'B', 20);
    guest_write(&state, 'C', 30);
    immediate_lsr = serial_ioport_read(&state, 5, 1);
    g_assert_cmpmem(transport.accepted, transport.accepted_count, "ABC", 3);
    serial_destroy(&state);

    transport_initialize(false);
    serial_initialize(&state);
    guest_write(&state, 'A', 10);
    guest_write(&state, 'B', 20);
    guest_write(&state, 'C', 30);
    deferred_lsr = serial_ioport_read(&state, 5, 1);
    g_assert_cmpuint(state.tsr_retry, ==, 1);
    g_assert_cmpuint(state.tsr, ==, 'A');
    g_assert_cmpuint(fifo8_num_used(&state.xmit_fifo), ==, 2);
    g_assert_cmpuint(transport.accepted_count, ==, 0);
    g_assert_cmpuint(immediate_lsr, ==, UART_LSR_THRE | UART_LSR_TEMT);
    g_assert_cmpuint(deferred_lsr & (UART_LSR_THRE | UART_LSR_TEMT), ==, 0);

    transport.writable = true;
    dispatch_original_watch(40);
    g_assert_cmpmem(transport.accepted, transport.accepted_count, "ABC", 3);
    g_assert_cmpuint(transport.attempts[0].coordinate, ==, 10);
    g_assert_cmpuint(transport.attempts[1].coordinate, ==, 40);
    g_assert_cmpuint(state.tsr_retry, ==, 0);
    g_assert_cmpuint(serial_ioport_read(&state, 5, 1), ==, immediate_lsr);
    serial_destroy(&state);
}

static void test_serial_delayed_readiness_changes_overrun_output(void)
{
    SerialState state;
    uint8_t writes[UART_FIFO_LENGTH + 4];
    uint8_t expected[UART_FIFO_LENGTH + 1];

    for (unsigned index = 0; index < ARRAY_SIZE(writes); index++) {
        writes[index] = 'A' + index;
    }
    transport_initialize(true);
    serial_initialize(&state);
    for (unsigned index = 0; index < ARRAY_SIZE(writes); index++) {
        guest_write(&state, writes[index], 10 * (index + 1));
    }
    g_assert_cmpmem(transport.accepted, transport.accepted_count,
                    writes, sizeof(writes));
    serial_destroy(&state);

    transport_initialize(false);
    serial_initialize(&state);
    for (unsigned index = 0; index < ARRAY_SIZE(writes); index++) {
        guest_write(&state, writes[index], 10 * (index + 1));
    }
    g_assert_cmpuint(fifo8_num_used(&state.xmit_fifo), ==, UART_FIFO_LENGTH);
    expected[0] = writes[0];
    memcpy(expected + 1, writes + 4, UART_FIFO_LENGTH);

    transport.writable = true;
    dispatch_original_watch(300);
    g_assert_cmpmem(transport.accepted, transport.accepted_count,
                    expected, sizeof(expected));
    g_assert_cmpuint(transport.accepted_count, <, sizeof(writes));
    serial_destroy(&state);
}

static void test_serial_nonfifo_thr_overwrite(void)
{
    SerialState state;

    transport_initialize(false);
    serial_initialize(&state);
    serial_ioport_write(&state, 2, 0, 1);
    guest_write(&state, 'A', 10);
    guest_write(&state, 'B', 20);
    guest_write(&state, 'C', 30);
    g_assert_cmpuint(state.tsr, ==, 'A');
    g_assert_cmpuint(state.thr, ==, 'C');

    transport.writable = true;
    dispatch_original_watch(40);
    g_assert_cmpmem(transport.accepted, transport.accepted_count, "AC", 2);
    serial_destroy(&state);
}

static void test_serial_retry_limit_and_missing_watch_drop(void)
{
    SerialState state;

    transport_initialize(false);
    serial_initialize(&state);
    guest_write(&state, 'A', 10);
    for (unsigned index = 0; index < MAX_XMIT_RETRY; index++) {
        dispatch_original_watch(20 + index);
    }
    g_assert_cmpuint(transport.attempt_count, ==, MAX_XMIT_RETRY + 1);
    g_assert_cmpuint(transport.accepted_count, ==, 0);
    g_assert_cmpuint(state.tsr_retry, ==, 0);
    g_assert_cmpuint(state.lsr & UART_LSR_TEMT, !=, 0);
    serial_destroy(&state);

    transport_initialize(false);
    transport.watch_available = false;
    serial_initialize(&state);
    guest_write(&state, 'A', 10);
    g_assert_cmpuint(transport.attempt_count, ==, 1);
    g_assert_cmpuint(transport.accepted_count, ==, 0);
    g_assert_cmpuint(state.tsr_retry, ==, 0);
    g_assert_cmpuint(state.watch_tag, ==, 0);
    serial_destroy(&state);
}

static void test_serial_loopback_dlab_and_reset(void)
{
    SerialState state;
    const uint8_t inbound = 'D';
    guint pending;

    transport_initialize(true);
    serial_initialize(&state);
    serial_ioport_write(&state, 3, UART_LCR_DLAB, 1);
    guest_write(&state, 'A', 10);
    g_assert_cmpuint(transport.attempt_count, ==, 0);
    g_assert_cmpuint(state.divider & 0xff, ==, 'A');

    serial_ioport_write(&state, 3, 0, 1);
    serial_ioport_write(&state, 4, UART_MCR_LOOP, 1);
    state.wakeup = true;
    guest_write(&state, 'B', 20);
    g_assert_cmpuint(transport.attempt_count, ==, 0);
    g_assert_cmpuint(transport.wake_notices, ==, 1);
    g_assert_cmpuint(serial_ioport_read(&state, 0, 1), ==, 'B');
    g_assert_cmpuint(transport.input_ready_notices, ==, 0);

    serial_ioport_write(&state, 4, UART_MCR_OUT2, 1);
    serial_receive1(&state, &inbound, 1);
    g_assert_cmpuint(serial_ioport_read(&state, 0, 1), ==, inbound);
    g_assert_cmpuint(transport.wake_notices, ==, 2);
    g_assert_cmpuint(transport.input_ready_notices, ==, 1);
    transport.writable = false;
    guest_write(&state, 'C', 30);
    pending = state.watch_tag;
    g_assert_cmpuint(pending, !=, 0);
    serial_reset(&state);
    g_assert_null(g_main_context_find_source_by_id(NULL, pending));
    g_assert_cmpuint(state.watch_tag, ==, 0);
    g_assert_cmpuint(state.tsr_retry, ==, 0);
    g_assert_cmpuint(fifo8_num_used(&state.xmit_fifo), ==, 0);
    g_assert_cmpuint(state.lsr, ==, UART_LSR_THRE | UART_LSR_TEMT);
    serial_destroy(&state);
}

static GByteArray *save_actual_state(const VMStateDescription *description,
                                    void *state)
{
    QIOChannelBuffer *output = qio_channel_buffer_new(4096);
    QEMUFile *file = qemu_file_new_output(QIO_CHANNEL(output));
    GByteArray *bytes = g_byte_array_new();
    Error *error = NULL;

    g_assert_cmpint(vmstate_save_state(file, description, state, NULL, &error), ==, 0);
    g_assert_null(error);
    qemu_put_byte(file, QEMU_VM_EOF);
    g_assert_cmpint(qemu_fflush(file), ==, 0);
    g_byte_array_append(bytes, output->data, output->usage);
    qemu_fclose(file);
    object_unref(OBJECT(output));
    return bytes;
}

static void load_actual_state(const VMStateDescription *description,
                              void *state, GByteArray *bytes)
{
    QIOChannelBuffer *input = qio_channel_buffer_new(bytes->len);
    QEMUFile *file;

    memcpy(input->data, bytes->data, bytes->len);
    input->usage = bytes->len;
    file = qemu_file_new_input(QIO_CHANNEL(input));
    g_assert_cmpint(vmstate_load_state(file, description, state,
                                      description->version_id, NULL), ==, 0);
    qemu_fclose(file);
    object_unref(OBJECT(input));
}

static void test_serial_pending_full_vmstate_roundtrip(void)
{
    SerialState source, restored;
    GByteArray *image;

    transport_initialize(false);
    serial_initialize(&source);
    guest_write(&source, 'A', 10);
    guest_write(&source, 'B', 20);
    guest_write(&source, 'C', 30);
    image = save_actual_state(&vmstate_serial, &source);
    serial_destroy(&source);
    serial_initialize(&restored);
    load_actual_state(&vmstate_serial, &restored, image);
    g_assert_cmpuint(restored.tsr_retry, ==, 1);
    g_assert_cmpuint(restored.tsr, ==, 'A');
    g_assert_cmpuint(fifo8_num_used(&restored.xmit_fifo), ==, 2);

    transport.writable = true;
    dispatch_original_watch(40);
    g_assert_cmpmem(transport.accepted, transport.accepted_count, "ABC", 3);
    serial_destroy(&restored);
    g_byte_array_unref(image);
}

static gpointer pl011_guest_write(gpointer opaque)
{
    pl011_write(opaque, 0, 'A', 4);
    return NULL;
}

static void test_pl011_external_write_all_blocks_tx_update(void)
{
    PL011State state = { 0 }, immediate = { 0 };
    GThread *guest;

    pl011_owner = &immediate;
    pl011_reset((DeviceState *)&immediate);
    transport_initialize(true);
    external_coordinate = 10;
    write_all_released = true;
    pl011_write(&immediate, 0, 'A', 4);
    g_assert_cmpmem(transport.accepted, transport.accepted_count, "A", 1);
    g_assert_cmpuint(immediate.int_level & INT_TX, !=, 0);

    pl011_owner = &state;
    pl011_reset((DeviceState *)&state);
    transport_initialize(true);
    external_coordinate = 10;
    write_all_entered = false;
    write_all_released = false;
    guest = g_thread_new("pl011-native-write", pl011_guest_write, &state);

    g_mutex_lock(&blocked_lock);
    while (!write_all_entered) {
        g_cond_wait(&blocked_condition, &blocked_lock);
    }
    /* The worker is parked inside the external provider. Original TX update
     * follows the write_all return, so this snapshot has a real happens-before.
     */
    g_assert_cmpuint(state.int_level & INT_TX, ==, 0);
    g_assert_cmpuint(transport.attempt_count, ==, 0);
    write_all_released = true;
    g_cond_broadcast(&blocked_condition);
    g_mutex_unlock(&blocked_lock);

    g_thread_join(guest);
    g_assert_cmpuint(state.int_level & INT_TX, !=, 0);
    g_assert_cmpmem(transport.accepted, transport.accepted_count, "A", 1);
    g_assert_cmpuint(transport.attempts[0].coordinate, ==, 10);
    g_assert_cmpuint(state.int_level, ==, immediate.int_level);
    g_assert_cmpuint(state.flags, ==, immediate.flags);
}

static void test_pl011_actual_vmstate_and_reset(void)
{
    PL011State source = { 0 }, restored = { 0 };
    GByteArray *image;

    pl011_owner = &source;
    pl011_reset((DeviceState *)&source);
    source.int_level = INT_TX;
    source.int_enabled = INT_TX;
    source.ibrd = 23;
    image = save_actual_state(&vmstate_pl011, &source);
    load_actual_state(&vmstate_pl011, &restored, image);
    g_assert_cmpuint(restored.int_level, ==, source.int_level);
    g_assert_cmpuint(restored.int_enabled, ==, source.int_enabled);
    g_assert_cmpuint(restored.ibrd, ==, 23);

    pl011_owner = &restored;
    pl011_reset((DeviceState *)&restored);
    g_assert_cmpuint(restored.int_level, ==, 0);
    g_assert_cmpuint(restored.int_enabled, ==, 0);
    g_assert_cmpuint(restored.ibrd, ==, 0);
    g_byte_array_unref(image);
}

int main(int argc, char **argv)
{
    Error *error = NULL;

    g_test_init(&argc, &argv, NULL);
    module_call_init(MODULE_INIT_QOM);
    qemu_init_main_loop(&error);
    g_assert_null(error);
    qemu_clock_enable(QEMU_CLOCK_VIRTUAL, true);
    g_mutex_init(&blocked_lock);
    g_cond_init(&blocked_condition);

    g_test_add_func("/uart-origin/serial/register-readiness",
                    test_serial_readiness_changes_register_visibility);
    g_test_add_func("/uart-origin/serial/fifo-overrun",
                    test_serial_delayed_readiness_changes_overrun_output);
    g_test_add_func("/uart-origin/serial/nonfifo-overwrite",
                    test_serial_nonfifo_thr_overwrite);
    g_test_add_func("/uart-origin/serial/retry-drop",
                    test_serial_retry_limit_and_missing_watch_drop);
    g_test_add_func("/uart-origin/serial/loopback-dlab-reset",
                    test_serial_loopback_dlab_and_reset);
    g_test_add_func("/uart-origin/serial/full-vmstate",
                    test_serial_pending_full_vmstate_roundtrip);
    g_test_add_func("/uart-origin/pl011/blocked-write-all",
                    test_pl011_external_write_all_blocks_tx_update);
    g_test_add_func("/uart-origin/pl011/full-vmstate-reset",
                    test_pl011_actual_vmstate_and_reset);
    return g_test_run();
}
