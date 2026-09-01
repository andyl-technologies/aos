#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "migration/vmstate.h"
#include "block/crucible-shmem.c"

typedef enum TestOutcome {
    TEST_OUTCOME_READ,
    TEST_OUTCOME_ZERO_SUCCESS,
    TEST_OUTCOME_ERROR,
    TEST_OUTCOME_TOO_LARGE,
    TEST_OUTCOME_TYPED_ERROR,
    TEST_OUTCOME_RETRY_PRESERVE_THEN_SUCCESS,
    TEST_OUTCOME_DROP_COMPLETION,
} TestOutcome;

typedef struct TestBackend {
    uint32_t expected_op;
    uint64_t expected_offset;
    size_t expected_len;
    int pending_before_ready;
    TestOutcome outcome;
    uint8_t read_payload[16];
    size_t read_len;
    uint8_t submitted_payload[16];
    size_t submitted_payload_len;
    uint32_t submitted_request_id;
    uint64_t submitted_epoch;
    uint32_t first_submitted_request_id;
    uint64_t first_submitted_epoch;
    uint32_t submitted_op;
    uint64_t submitted_offset;
    size_t submitted_len;
    bool submitted_data_was_null;
    int submit_count;
    int poll_count;
    int typed_errno;
    BDRVCrucibleShmemState *retry_state;
} TestBackend;

static AioContext fixture_aio_context;
static unsigned int fixture_schedule_count;
static unsigned int fixture_yield_count;
static unsigned int fixture_topology_notifications;
static unsigned int fixture_try_malloc_count;
static int64_t fixture_clock_ns;
static BlockDriver *fixture_registered_driver;

void *fixture_try_malloc(size_t size)
{
    fixture_try_malloc_count++;
    return malloc(size == 0 ? 1 : size);
}

uint32_t qemu_get_be32(QEMUFile *file)
{
    uint32_t value;

    if (file->position > file->capacity ||
        file->capacity - file->position < sizeof(value)) {
        file->error = -EIO;
        return 0;
    }
    value = ((uint32_t)file->data[file->position] << 24) |
            ((uint32_t)file->data[file->position + 1] << 16) |
            ((uint32_t)file->data[file->position + 2] << 8) |
            (uint32_t)file->data[file->position + 3];
    file->position += sizeof(value);
    return value;
}

size_t qemu_get_buffer(QEMUFile *file, uint8_t *data, size_t len)
{
    if (file->position > file->capacity ||
        file->capacity - file->position < len) {
        file->error = -EIO;
        return 0;
    }
    memcpy(data, file->data + file->position, len);
    file->position += len;
    return len;
}

void qemu_put_be32(QEMUFile *file, uint32_t value)
{
    if (file->position > file->capacity ||
        file->capacity - file->position < sizeof(value)) {
        file->error = -EIO;
        return;
    }
    file->data[file->position] = (uint8_t)(value >> 24);
    file->data[file->position + 1] = (uint8_t)(value >> 16);
    file->data[file->position + 2] = (uint8_t)(value >> 8);
    file->data[file->position + 3] = (uint8_t)value;
    file->position += sizeof(value);
}

void qemu_put_buffer(QEMUFile *file, const uint8_t *data, size_t len)
{
    if (file->position > file->capacity ||
        file->capacity - file->position < len) {
        file->error = -EIO;
        return;
    }
    memcpy(file->data + file->position, data, len);
    file->position += len;
}

int qemu_file_get_error(QEMUFile *file)
{
    return file->error;
}

void fixture_co_queue_init(CoQueue *queue)
{
    queue->unused = 0;
}

bool fixture_co_queue_empty(const CoQueue *queue)
{
    (void)queue;
    return true;
}

void fixture_co_queue_wait(CoQueue *queue, QemuMutex *mutex)
{
    (void)queue;
    (void)mutex;
    fixture_schedule_count++;
    fixture_yield_count++;
}

void fixture_co_enter_all(CoQueue *queue, void *lockable)
{
    (void)queue;
    (void)lockable;
}

void *qemu_coroutine_self(void)
{
    return &fixture_aio_context;
}

void qemu_coroutine_yield(void)
{
    fixture_yield_count++;
}

AioContext *bdrv_get_aio_context(BlockDriverState *bs)
{
    (void)bs;
    return &fixture_aio_context;
}

int64_t qemu_clock_get_ns(int clock)
{
    (void)clock;
    return fixture_clock_ns;
}

void qemu_co_sleep_ns(int clock, int64_t duration)
{
    (void)clock;
    fixture_clock_ns += duration;
}

void bdrv_notify_topology_change(BlockDriverState *bs)
{
    (void)bs;
    fixture_topology_notifications++;
}

void aio_co_schedule(AioContext *ctx, void *co)
{
    if (ctx == &fixture_aio_context && co == &fixture_aio_context) {
        fixture_schedule_count++;
    }
}

void bdrv_register(BlockDriver *driver)
{
    fixture_registered_driver = driver;
}

void pstrcpy(char *dst, int dst_size, const char *src)
{
    if (dst_size <= 0) {
        return;
    }
    snprintf(dst, (size_t)dst_size, "%s", src);
}

void qemu_iovec_to_buf(const QEMUIOVector *qiov, size_t offset, void *buf,
                       size_t bytes)
{
    memcpy(buf, qiov->base + offset, bytes);
}

void qemu_iovec_from_buf(QEMUIOVector *qiov, size_t offset, const void *buf,
                         size_t bytes)
{
    memcpy(qiov->base + offset, buf, bytes);
}

static int fail(const char *message)
{
    fprintf(stderr, "FAIL: %s\n", message);
    return 1;
}

static int expect_bool(bool condition, const char *message)
{
    return condition ? 0 : fail(message);
}

#ifdef QEMU_PLUGIN_BLK_RETRY_PRESERVE_ID
static int test_submit(uint64_t epoch, uint32_t request_id, uint32_t op,
                       uint64_t offset,
#else
static int test_submit(uint32_t request_id, uint32_t op, uint64_t offset,
#endif
                       const uint8_t *data, size_t len, void *userdata)
{
    TestBackend *backend = userdata;

    backend->submit_count++;
    if (backend->submit_count == 1) {
        backend->first_submitted_request_id = request_id;
#ifdef QEMU_PLUGIN_BLK_RETRY_PRESERVE_ID
        backend->first_submitted_epoch = epoch;
#endif
    }
    backend->submitted_request_id = request_id;
#ifdef QEMU_PLUGIN_BLK_RETRY_PRESERVE_ID
    backend->submitted_epoch = epoch;
#endif
    backend->submitted_op = op;
    backend->submitted_offset = offset;
    backend->submitted_len = len;
    backend->submitted_data_was_null = data == NULL;
    backend->submitted_payload_len = 0;

    if (data != NULL && len <= sizeof(backend->submitted_payload)) {
        memcpy(backend->submitted_payload, data, len);
        backend->submitted_payload_len = len;
    }

    if (op != backend->expected_op || offset != backend->expected_offset ||
        len != backend->expected_len) {
        return -1;
    }
    return 0;
}

#ifdef QEMU_PLUGIN_BLK_RETRY_PRESERVE_ID
static int64_t test_poll(uint64_t epoch, uint32_t request_id, uint8_t *data,
                         size_t capacity,
#else
static int64_t test_poll(uint32_t request_id, uint8_t *data, size_t capacity,
#endif
                         void *userdata)
{
    TestBackend *backend = userdata;

    backend->poll_count++;
    if (request_id != backend->submitted_request_id) {
        return -1;
    }
#ifdef QEMU_PLUGIN_BLK_RETRY_PRESERVE_ID
    if (epoch != backend->submitted_epoch) {
        return -1;
    }
#endif
    if (backend->pending_before_ready > 0) {
        backend->pending_before_ready--;
        return QEMU_PLUGIN_BLK_POLL_PENDING;
    }

    switch (backend->outcome) {
    case TEST_OUTCOME_READ:
        if (capacity < backend->read_len || data == NULL) {
            return -1;
        }
        memcpy(data, backend->read_payload, backend->read_len);
        return (int64_t)backend->read_len;
    case TEST_OUTCOME_ZERO_SUCCESS:
        return 0;
    case TEST_OUTCOME_ERROR:
        return -1;
    case TEST_OUTCOME_TOO_LARGE:
        return (int64_t)capacity + 1;
    case TEST_OUTCOME_TYPED_ERROR:
#ifdef QEMU_PLUGIN_BLK_POLL_ERROR_BASE
        return QEMU_PLUGIN_BLK_POLL_ERROR(backend->typed_errno);
#else
        return -1;
#endif
    case TEST_OUTCOME_RETRY_PRESERVE_THEN_SUCCESS:
#ifdef QEMU_PLUGIN_BLK_RETRY_PRESERVE_ID
        if (backend->poll_count == 1 && backend->retry_state != NULL) {
            backend->retry_state->recovery_deadline_ns = fixture_clock_ns + 50;
            backend->retry_state->recovery_unadmitted = 1;
            return QEMU_PLUGIN_BLK_RETRY_PRESERVE_ID;
        }
        return 0;
#else
        return -1;
#endif
    case TEST_OUTCOME_DROP_COMPLETION:
#ifdef QEMU_PLUGIN_BLK_DROP_COMPLETION
        return QEMU_PLUGIN_BLK_DROP_COMPLETION;
#else
        return -1;
#endif
    }
    return -1;
}

static void reset_backend(TestBackend *backend, uint32_t op, uint64_t offset,
                          size_t len, int pending, TestOutcome outcome)
{
    memset(backend, 0, sizeof(*backend));
    backend->expected_op = op;
    backend->expected_offset = offset;
    backend->expected_len = len;
    backend->pending_before_ready = pending;
    backend->outcome = outcome;
}

#ifdef QEMU_PLUGIN_BLK_RETRY_PRESERVE_ID
typedef struct TestEventBackend {
    uint8_t frame[CRUCIBLE_BLOCK_EVENT_SIZE];
    bool ready;
    int commit_result;
    unsigned int commit_count;
    unsigned int restore_count;
    int restore_result;
    uint64_t state_epoch;
    uint32_t state_next_request_id;
} TestEventBackend;

static void put_u16_le(uint8_t *data, uint16_t value)
{
    data[0] = (uint8_t)value;
    data[1] = (uint8_t)(value >> 8);
}

static void put_u32_le(uint8_t *data, uint32_t value)
{
    data[0] = (uint8_t)value;
    data[1] = (uint8_t)(value >> 8);
    data[2] = (uint8_t)(value >> 16);
    data[3] = (uint8_t)(value >> 24);
}

static void put_u64_le(uint8_t *data, uint64_t value)
{
    put_u32_le(data, (uint32_t)value);
    put_u32_le(data + 4, (uint32_t)(value >> 32));
}

static void reset_event(TestEventBackend *event, uint64_t next_epoch,
                        uint64_t recovery_ns, uint8_t unadmitted)
{
    uint8_t *reset;

    memset(event, 0, sizeof(*event));
    event->frame[0] = CRUCIBLE_BLOCK_STATUS_RESET;
    event->frame[1] = CRUCIBLE_BLOCK_WIRE_VERSION;
    put_u32_le(event->frame + 16, 32);
    reset = event->frame + CRUCIBLE_BLOCK_RESPONSE_HEADER_SIZE;
    put_u64_le(reset, next_epoch);
    put_u64_le(reset + 8, recovery_ns);
    reset[16] = 1;
    reset[17] = 1;
    reset[19] = 5;
    reset[20] = unadmitted;
    event->ready = true;
}

static int64_t test_event_poll(uint8_t *data, size_t capacity, void *userdata)
{
    TestEventBackend *event = userdata;

    if (!event->ready) {
        return 0;
    }
    if (capacity < sizeof(event->frame)) {
        return -1;
    }
    memcpy(data, event->frame, sizeof(event->frame));
    return sizeof(event->frame);
}

static int test_event_commit(void *userdata)
{
    TestEventBackend *event = userdata;

    if (event->commit_result != 0) {
        return event->commit_result;
    }
    event->ready = false;
    event->commit_count++;
    return 0;
}

static int64_t test_transport_save(uint8_t *data, size_t capacity,
                                   void *userdata)
{
    TestEventBackend *event = userdata;

    if (!data && capacity == 0) {
        return CRUCIBLE_BLOCK_TRANSPORT_STATE_HEADER_SIZE;
    }
    if (!data || capacity < CRUCIBLE_BLOCK_TRANSPORT_STATE_HEADER_SIZE) {
        return -1;
    }
    memset(data, 0, CRUCIBLE_BLOCK_TRANSPORT_STATE_HEADER_SIZE);
    memcpy(data, "CBTS", 4);
    put_u16_le(data + 4, 1);
    put_u64_le(data + 8, event->state_epoch);
    put_u32_le(data + 16, event->state_next_request_id);
    return CRUCIBLE_BLOCK_TRANSPORT_STATE_HEADER_SIZE;
}

static int test_transport_restore(const uint8_t *data, size_t len,
                                  uint64_t epoch, uint32_t next_request_id,
                                  void *userdata)
{
    TestEventBackend *event = userdata;

    if (event->restore_result != 0) {
        return event->restore_result;
    }
    if (!data || len != CRUCIBLE_BLOCK_TRANSPORT_STATE_HEADER_SIZE ||
        memcmp(data, "CBTS", 4) != 0 || epoch != event->state_epoch ||
        next_request_id != event->state_next_request_id) {
        return -1;
    }
    event->restore_count++;
    return 0;
}
#endif

static int exercise_driver(void)
{
    BDRVCrucibleShmemState state;
    BlockDriverState bs = {
        .opaque = &state,
    };
    QDict options = {
        .has_size = true,
        .size = 64,
    };
    TestBackend backend;
#ifdef QEMU_PLUGIN_BLK_RETRY_PRESERVE_ID
    TestEventBackend event;
    uint8_t vmstate_wire[4 + CRUCIBLE_BLOCK_TRANSPORT_STATE_HEADER_SIZE];
    QEMUFile vmstate_file;
#endif
    Error *err = NULL;
    uint8_t read_target[4] = {0};
    uint8_t write_source[3] = {9, 8, 7};
    QEMUIOVector read_qiov = {
        .base = read_target,
        .size = sizeof(read_target),
    };
    QEMUIOVector write_qiov = {
        .base = write_source,
        .size = sizeof(write_source),
    };

    if (QEMU_PLUGIN_BLK_POLL_PENDING != -2) {
        return fail("pending sentinel is not distinct from zero-byte success");
    }

    bdrv_crucible_shmem_init();
    if (expect_bool(fixture_registered_driver == &bdrv_crucible_shmem,
                    "block driver was not registered") ||
        expect_bool(strcmp(fixture_registered_driver->format_name,
                           "crucible-shmem") == 0,
                    "format name mismatch") ||
        expect_bool(strcmp(fixture_registered_driver->protocol_name,
                           "crucible-shmem") == 0,
                    "protocol name mismatch")) {
        return 1;
    }

    if (crucible_shmem_open(&bs, &options, 0, &err) != 0 || err != NULL) {
        return fail("open failed");
    }
    if (expect_bool(bs.bl.request_alignment == 1, "request alignment mismatch") ||
        expect_bool(crucible_shmem_co_getlength(&bs) == 64,
                    "reported length mismatch")) {
        return 1;
    }
    crucible_shmem_refresh_filename(&bs);
    if (expect_bool(strcmp(bs.exact_filename, "crucible-shmem://") == 0,
                    "exact filename mismatch")) {
        return 1;
    }

    qemu_plugin_register_blk_cb(test_submit, test_poll, &backend);

#ifdef QEMU_PLUGIN_BLK_RETRY_PRESERVE_ID
    fixture_clock_ns = 1000;
    fixture_topology_notifications = 0;
    reset_event(&event, 1, 100, 0);
    event.state_epoch = 1;
    event.state_next_request_id = 0;
    qemu_plugin_register_blk_event_cb(test_event_poll, test_event_commit,
                                      test_transport_save,
                                      test_transport_restore, &event);
    if (!crucible_shmem_poll_events(&state) ||
        expect_bool(state.request_epoch == 1, "reset epoch mismatch") ||
        expect_bool(state.next_request_id == 0, "reset allocator mismatch") ||
        expect_bool(state.recovery_deadline_ns == 1100,
                    "reset recovery deadline mismatch") ||
        expect_bool(state.recovery_failure == 5,
                    "reset failure result mismatch") ||
        expect_bool(crucible_shmem_failure_errno(1) == ENOMEDIUM,
                    "first typed reset error mapping mismatch") ||
        expect_bool(crucible_shmem_failure_errno(11) == ESTALE,
                    "last typed reset error mapping mismatch") ||
        expect_bool(fixture_topology_notifications == 1,
                    "declared topology was not re-enumerated") ||
        expect_bool(event.commit_count == 1,
                    "accepted reset event was not committed exactly once") ||
        expect_bool(crucible_shmem_admit_after_recovery(&state) == -ETIMEDOUT,
                    "reject recovery policy mismatch")) {
        return 1;
    }
    state.recovery_unadmitted = 1;
    if (expect_bool(crucible_shmem_admit_after_recovery(&state) == 0,
                    "wait recovery policy failed") ||
        expect_bool(fixture_clock_ns == 1100,
                    "wait recovery did not reach exact deadline")) {
        return 1;
    }
    reset_event(&event, 2, 100, 0);
    event.frame[CRUCIBLE_BLOCK_EVENT_SIZE - 1] = 1;
    if (expect_bool(!crucible_shmem_poll_events(&state),
                    "nonzero reset reserved byte was accepted") ||
        expect_bool(state.request_epoch == 1,
                    "malformed reset mutated epoch")) {
        return 1;
    }
    event.frame[CRUCIBLE_BLOCK_EVENT_SIZE - 1] = 0;
    event.commit_result = -1;
    if (expect_bool(!crucible_shmem_poll_events(&state),
                    "rejected event commit was accepted") ||
        expect_bool(state.request_epoch == 1,
                    "rejected event commit mutated epoch") ||
        expect_bool(event.ready,
                    "rejected event commit consumed the event")) {
        return 1;
    }
    event.commit_result = 0;
    event.ready = false;
    event.state_epoch = state.request_epoch;
    event.state_next_request_id = state.next_request_id;

    if (expect_bool(crucible_shmem_pre_save(&state) == 0,
                    "transport continuation save failed") ||
        expect_bool(state.vmstate_plugin_state_len ==
                        CRUCIBLE_BLOCK_TRANSPORT_STATE_HEADER_SIZE,
                    "transport continuation length mismatch")) {
        return 1;
    }
    memset(vmstate_wire, 0, sizeof(vmstate_wire));
    vmstate_file = (QEMUFile) {
        .data = vmstate_wire,
        .capacity = sizeof(vmstate_wire),
    };
    if (expect_bool(crucible_shmem_put_plugin_state(
                        &vmstate_file, &state, 0, NULL, NULL) == 0,
                    "transport VMState encoder failed") ||
        expect_bool(vmstate_file.position == sizeof(vmstate_wire),
                    "transport VMState encoder length mismatch") ||
        expect_bool(crucible_shmem_pre_load(&state) == 0,
                    "transport VMState pre-load cleanup failed")) {
        return 1;
    }
    vmstate_file.position = 0;
    vmstate_file.error = 0;
    if (expect_bool(crucible_shmem_get_plugin_state(
                        &vmstate_file, &state, 0, NULL) == 0,
                    "bounded transport VMState decoder failed") ||
        expect_bool(state.vmstate_plugin_state_len ==
                        CRUCIBLE_BLOCK_TRANSPORT_STATE_HEADER_SIZE,
                    "bounded transport VMState decoder length mismatch")) {
        return 1;
    }
    {
        uint8_t oversized_length[] = { 0x02, 0x00, 0x00, 0x01 };
        unsigned int allocations_before = fixture_try_malloc_count;
        QEMUFile oversized_file = {
            .data = oversized_length,
            .capacity = sizeof(oversized_length),
        };

        if (expect_bool(crucible_shmem_pre_load(&state) == 0,
                        "oversized VMState pre-load cleanup failed") ||
            expect_bool(crucible_shmem_get_plugin_state(
                            &oversized_file, &state, 0, NULL) == -EINVAL,
                        "oversized transport VMState was accepted") ||
            expect_bool(fixture_try_malloc_count == allocations_before,
                        "oversized transport VMState allocated memory") ||
            expect_bool(state.vmstate_plugin_state == NULL &&
                            state.vmstate_plugin_state_len == 0,
                        "oversized transport VMState mutated staging state")) {
            return 1;
        }
    }
    vmstate_file.position = 0;
    vmstate_file.error = 0;
    if (expect_bool(crucible_shmem_get_plugin_state(
                        &vmstate_file, &state, 0, NULL) == 0,
                    "valid transport VMState did not decode after rejection")) {
        return 1;
    }
    state.vmstate_next_request_id = 1;
    if (expect_bool(crucible_shmem_post_load(&state, 1) == -EINVAL,
                    "mismatched transport continuation was restored") ||
        expect_bool(event.restore_count == 0,
                    "mismatched continuation reached plugin restore") ||
        expect_bool(state.next_request_id == 0,
                    "failed restore mutated active allocator")) {
        return 1;
    }
    state.vmstate_next_request_id = 0;
    state.vmstate_recovery_unadmitted = 2;
    if (expect_bool(crucible_shmem_post_load(&state, 1) == -EINVAL,
                    "invalid recovery admission was restored") ||
        expect_bool(state.recovery_unadmitted == 1,
                    "invalid recovery restore mutated active admission")) {
        return 1;
    }
    state.vmstate_recovery_unadmitted = 1;
    event.restore_result = -1;
    if (expect_bool(crucible_shmem_post_load(&state, 1) == -EINVAL,
                    "plugin-rejected continuation was restored") ||
        expect_bool(state.next_request_id == 0 &&
                        state.recovery_unadmitted == 1,
                    "plugin-rejected restore mutated active QEMU state")) {
        return 1;
    }
    event.restore_result = 0;
    if (expect_bool(crucible_shmem_post_load(&state, 1) == 0,
                    "paired transport continuation restore failed") ||
        expect_bool(event.restore_count == 1,
                    "paired continuation did not restore exactly once") ||
        expect_bool(crucible_shmem_pre_load(&state) == 0,
                    "transport continuation pre-load cleanup failed") ||
        expect_bool(state.vmstate_plugin_state == NULL &&
                        state.vmstate_plugin_state_len == 0,
                    "transport continuation pre-load did not clear state")) {
        return 1;
    }
#endif

    reset_backend(&backend, QEMU_PLUGIN_BLK_OP_READ, 8, sizeof(read_target), 2,
                  TEST_OUTCOME_READ);
    backend.read_payload[0] = 1;
    backend.read_payload[1] = 2;
    backend.read_payload[2] = 3;
    backend.read_payload[3] = 4;
    backend.read_len = sizeof(read_target);
    fixture_schedule_count = 0;
    fixture_yield_count = 0;
    if (crucible_shmem_co_preadv(&bs, 8, sizeof(read_target), &read_qiov, 0) !=
        0) {
        return fail("read request failed");
    }
    if (expect_bool(memcmp(read_target, backend.read_payload,
                           sizeof(read_target)) == 0,
                    "read payload mismatch") ||
        expect_bool(backend.poll_count == 3, "read poll count mismatch") ||
        expect_bool(fixture_schedule_count == 2,
                    "pending read was not rescheduled") ||
        expect_bool(fixture_yield_count == 2, "pending read did not yield")) {
        return 1;
    }

    reset_backend(&backend, QEMU_PLUGIN_BLK_OP_WRITE, 12, sizeof(write_source),
                  1, TEST_OUTCOME_ZERO_SUCCESS);
    fixture_schedule_count = 0;
    fixture_yield_count = 0;
    if (crucible_shmem_co_pwritev(&bs, 12, sizeof(write_source), &write_qiov,
                                  0) != 0) {
        return fail("write request failed");
    }
    if (expect_bool(backend.submitted_payload_len == sizeof(write_source),
                    "write payload length mismatch") ||
        expect_bool(memcmp(backend.submitted_payload, write_source,
                           sizeof(write_source)) == 0,
                    "write payload mismatch") ||
        expect_bool(backend.poll_count == 2, "write poll count mismatch") ||
        expect_bool(fixture_schedule_count == 1,
                    "pending write was not rescheduled") ||
        expect_bool(fixture_yield_count == 1, "pending write did not yield")) {
        return 1;
    }

    reset_backend(&backend, QEMU_PLUGIN_BLK_OP_FLUSH, 0, 0, 0,
                  TEST_OUTCOME_ZERO_SUCCESS);
    if (crucible_shmem_co_flush(&bs) != 0) {
        return fail("flush zero-length success failed");
    }
    if (expect_bool(backend.poll_count == 1, "flush poll count mismatch")) {
        return 1;
    }

#ifdef QEMU_PLUGIN_BLK_OP_DISCARD
    reset_backend(&backend, QEMU_PLUGIN_BLK_OP_DISCARD, 20, 4, 0,
                  TEST_OUTCOME_ZERO_SUCCESS);
    if (crucible_shmem_co_pdiscard(&bs, 20, 4) != 0) {
        return fail("discard request failed");
    }
    if (expect_bool(backend.submitted_data_was_null,
                    "discard unexpectedly carried a payload") ||
        expect_bool(backend.submitted_payload_len == 0,
                    "discard captured payload bytes") ||
        expect_bool(backend.poll_count == 1, "discard poll count mismatch")) {
        return 1;
    }
#endif
#ifdef QEMU_PLUGIN_BLK_RETRY_PRESERVE_ID
    reset_backend(&backend, QEMU_PLUGIN_BLK_OP_FLUSH, 0, 0, 0,
                  TEST_OUTCOME_RETRY_PRESERVE_THEN_SUCCESS);
    backend.retry_state = &state;
    fixture_clock_ns = 2000;
    state.recovery_deadline_ns = fixture_clock_ns;
    if (crucible_shmem_co_flush(&bs) != 0 ||
        expect_bool(backend.submit_count == 2,
                    "preserved retry did not submit exactly twice") ||
        expect_bool(backend.submitted_epoch == backend.first_submitted_epoch &&
                        backend.submitted_request_id ==
                            backend.first_submitted_request_id,
                    "preserved retry changed request identity") ||
        expect_bool(fixture_clock_ns == 2050,
                    "preserved retry bypassed recovery admission")) {
        return 1;
    }
    reset_backend(&backend, QEMU_PLUGIN_BLK_OP_FLUSH, 0, 0, 0,
                  TEST_OUTCOME_DROP_COMPLETION);
    if (expect_bool(crucible_shmem_co_flush(&bs) == -ECANCELED,
                    "dropped completion did not reach frontend sentinel") ||
        expect_bool(bdrv_crucible_shmem.bdrv_guest_completion_dropped(
                        &bs, ECANCELED),
                    "drop sentinel was not recognized by block driver") ||
        expect_bool(!bdrv_crucible_shmem.bdrv_guest_completion_dropped(
                        &bs, EIO),
                    "ordinary I/O error was mistaken for dropped completion")) {
        return 1;
    }
    puts("transport_reset_transactional=true");
    puts("transport_reset_recovery_exact=true");
    puts("transport_reset_reserved_rejected=true");
    puts("transport_reset_topology_notified=true");
    puts("transport_reset_error_range_exact=true");
    puts("transport_reset_commit_rejection_transactional=true");
    puts("transport_reset_vmstate_paired=true");
    puts("transport_reset_vmstate_oversize_rejected_preallocation=true");
    puts("transport_reset_preserve_retry_admitted=true");
    puts("transport_reset_drop_sentinel_exact=true");
#endif

    reset_backend(&backend, QEMU_PLUGIN_BLK_OP_READ, 0, sizeof(read_target), 0,
                  TEST_OUTCOME_ERROR);
    if (expect_bool(crucible_shmem_co_preadv(&bs, 0, sizeof(read_target),
                                             &read_qiov, 0) == -EIO,
                    "read error was not propagated")) {
        return 1;
    }

    reset_backend(&backend, QEMU_PLUGIN_BLK_OP_READ, 0, sizeof(read_target), 0,
                  TEST_OUTCOME_TOO_LARGE);
    if (expect_bool(crucible_shmem_co_preadv(&bs, 0, sizeof(read_target),
                                             &read_qiov, 0) == -EOVERFLOW,
                    "oversized read completion was not rejected")) {
        return 1;
    }

#ifdef QEMU_PLUGIN_BLK_POLL_ERROR_BASE
    {
        static const int typed_errnos[] = {
            ENOMEDIUM, EROFS, EINVAL, EBUSY, ETIMEDOUT, EIO,
            EILSEQ, EIO, ENOSPC, ENOENT, ESTALE,
        };
        size_t index;

        for (index = 0; index < sizeof(typed_errnos) / sizeof(typed_errnos[0]);
             index++) {
            reset_backend(&backend, QEMU_PLUGIN_BLK_OP_READ, 0,
                          sizeof(read_target), 0, TEST_OUTCOME_TYPED_ERROR);
            backend.typed_errno = typed_errnos[index];
            if (expect_bool(crucible_shmem_co_preadv(
                                &bs, 0, sizeof(read_target), &read_qiov, 0) ==
                                -typed_errnos[index],
                            "typed read error was not propagated exactly")) {
                return 1;
            }
        }

        reset_backend(&backend, QEMU_PLUGIN_BLK_OP_READ, 0,
                      sizeof(read_target), 0, TEST_OUTCOME_TYPED_ERROR);
        backend.typed_errno = QEMU_PLUGIN_BLK_POLL_ERROR_MAX + 1;
        if (expect_bool(crucible_shmem_co_preadv(
                            &bs, 0, sizeof(read_target), &read_qiov, 0) ==
                            -EOVERFLOW,
                        "out-of-range typed error did not fail closed")) {
            return 1;
        }
    }
#endif

    if (expect_bool(crucible_shmem_co_pwritev(&bs, 63, 2, &write_qiov, 0) ==
                        -ENOSPC,
                    "write beyond end did not fail closed") ||
        expect_bool(crucible_shmem_co_preadv(&bs, 63, 2, &read_qiov, 0) ==
                        -EINVAL,
                    "read beyond end did not fail closed")) {
        return 1;
    }

#ifdef QEMU_PLUGIN_BLK_OP_DISCARD
    if (expect_bool(crucible_shmem_co_pdiscard(&bs, 63, 2) == -ENOSPC,
                    "discard beyond end did not fail closed")) {
        return 1;
    }
#endif

    puts("PASS");
    puts("block_driver_registered=true");
    puts("block_driver_protocol=crucible-shmem");
    puts("plugin_callback_registration_exercised=true");
    puts("read_payload_round_trip=true");
    puts("write_submit_payload_captured=true");
    puts("flush_zero_length_success=true");
    puts("zero_length_success_distinct_from_pending=true");
    puts("pending_sentinel=-2");
    puts("poll_sleep_cadence_scheduled=true");
    puts("poll_sleep_cadence_yielded=true");
    puts("deterministic_completion_offsets=true");
    puts("error_completion_fails_closed=true");
    puts("oversized_completion_fails_closed=true");
    puts("range_checks_fail_closed=true");
    puts("stock_negative_control_block_symbols_absent=true");
#ifdef QEMU_PLUGIN_BLK_POLL_ERROR_BASE
    puts("typed_error_errno_mapping_exact=true");
    puts("typed_error_out_of_range_fails_closed=true");
#endif
#ifdef QEMU_PLUGIN_BLK_OP_DISCARD
    puts("discard_payload_free=true");
    puts("discard_range_checks_fail_closed=true");
#endif
    return 0;
}

int main(void)
{
    return exercise_driver();
}
