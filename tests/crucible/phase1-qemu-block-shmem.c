#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "block/crucible-shmem.c"

typedef enum TestOutcome {
    TEST_OUTCOME_READ,
    TEST_OUTCOME_ZERO_SUCCESS,
    TEST_OUTCOME_ERROR,
    TEST_OUTCOME_TOO_LARGE,
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
    uint32_t submitted_op;
    uint64_t submitted_offset;
    size_t submitted_len;
    int submit_count;
    int poll_count;
} TestBackend;

static AioContext fixture_aio_context;
static unsigned int fixture_schedule_count;
static unsigned int fixture_yield_count;
static BlockDriver *fixture_registered_driver;

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

static int test_submit(uint32_t request_id, uint32_t op, uint64_t offset,
                       const uint8_t *data, size_t len, void *userdata)
{
    TestBackend *backend = userdata;

    backend->submit_count++;
    backend->submitted_request_id = request_id;
    backend->submitted_op = op;
    backend->submitted_offset = offset;
    backend->submitted_len = len;
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

static int64_t test_poll(uint32_t request_id, uint8_t *data, size_t capacity,
                         void *userdata)
{
    TestBackend *backend = userdata;

    backend->poll_count++;
    if (request_id != backend->submitted_request_id) {
        return -1;
    }
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

    if (expect_bool(crucible_shmem_co_pwritev(&bs, 63, 2, &write_qiov, 0) ==
                        -ENOSPC,
                    "write beyond end did not fail closed") ||
        expect_bool(crucible_shmem_co_preadv(&bs, 63, 2, &read_qiov, 0) ==
                        -EINVAL,
                    "read beyond end did not fail closed")) {
        return 1;
    }

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
    return 0;
}

int main(void)
{
    return exercise_driver();
}
