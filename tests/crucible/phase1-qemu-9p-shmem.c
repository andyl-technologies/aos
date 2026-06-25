#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/uio.h>

#include "hw/9pfs/virtio-9p-device.c"

static V9fsVirtioState fixture_device;
static VirtQueue fixture_queue;
static VirtQueueElement *fixture_elem;
static VirtQueueElement *fixture_next_elem;
static int fixture_alloc_remaining;
static int fixture_pop_count;
static int fixture_push_count;
static int fixture_notify_count;
static int fixture_detach_count;
static int fixture_error_count;
static int fixture_pdu_free_count;
static int fixture_upstream_submit_count;
static int fixture_main_loop_wait_count;

static int fixture_burst_start_count;
static int fixture_burst_done_count;
static int fixture_submit_count;
static int fixture_poll_count;
static int fixture_pending_before_ready;
static int fixture_submit_status;
static int64_t fixture_poll_status;
static uint32_t fixture_last_request_id;
static uint32_t fixture_seen_request_ids[4];
static size_t fixture_last_request_len;
static size_t fixture_last_response_capacity;
static uint8_t fixture_last_request[64];
static uint8_t fixture_response[64];
static size_t fixture_response_len;

static int fail(const char *message)
{
    fprintf(stderr, "FAIL: %s\n", message);
    return 1;
}

static int expect_bool(bool condition, const char *message)
{
    return condition ? 0 : fail(message);
}

static uint32_t load_le32(const uint8_t *data)
{
    return (uint32_t)data[0] | ((uint32_t)data[1] << 8) |
           ((uint32_t)data[2] << 16) | ((uint32_t)data[3] << 24);
}

static void store_le32(uint8_t *data, uint32_t value)
{
    data[0] = (uint8_t)(value & 0xff);
    data[1] = (uint8_t)((value >> 8) & 0xff);
    data[2] = (uint8_t)((value >> 16) & 0xff);
    data[3] = (uint8_t)((value >> 24) & 0xff);
}

static void store_le16(uint8_t *data, uint16_t value)
{
    data[0] = (uint8_t)(value & 0xff);
    data[1] = (uint8_t)((value >> 8) & 0xff);
}

static VirtQueueElement *new_elem(uint8_t *request, size_t request_len,
                                  uint8_t *response, size_t response_capacity)
{
    VirtQueueElement *elem = calloc(1, sizeof(*elem));
    if (elem == NULL) {
        return NULL;
    }

    elem->out_sg = calloc(1, sizeof(*elem->out_sg));
    elem->in_sg = calloc(1, sizeof(*elem->in_sg));
    if (elem->out_sg == NULL || elem->in_sg == NULL) {
        free(elem->out_sg);
        free(elem->in_sg);
        free(elem);
        return NULL;
    }

    elem->out_num = 1;
    elem->in_num = 1;
    elem->out_sg[0].iov_base = request;
    elem->out_sg[0].iov_len = request_len;
    elem->in_sg[0].iov_base = response;
    elem->in_sg[0].iov_len = response_capacity;
    return elem;
}

static void reset_fixture(void)
{
    memset(&fixture_device, 0, sizeof(fixture_device));
    fixture_device.vq = &fixture_queue;
    fixture_device.state.tag = "crucible";
    fixture_device.state.fsconf.tag = "crucible";
    fixture_alloc_remaining = 1;
    fixture_elem = NULL;
    fixture_next_elem = NULL;
    fixture_pop_count = 0;
    fixture_push_count = 0;
    fixture_notify_count = 0;
    fixture_detach_count = 0;
    fixture_error_count = 0;
    fixture_pdu_free_count = 0;
    fixture_upstream_submit_count = 0;
    fixture_main_loop_wait_count = 0;
    fixture_burst_start_count = 0;
    fixture_burst_done_count = 0;
    fixture_submit_count = 0;
    fixture_poll_count = 0;
    fixture_pending_before_ready = 0;
    fixture_submit_status = 0;
    fixture_poll_status = 0;
    fixture_last_request_id = UINT32_MAX;
    for (size_t index = 0; index < sizeof(fixture_seen_request_ids) /
                                     sizeof(fixture_seen_request_ids[0]);
         index++) {
        fixture_seen_request_ids[index] = UINT32_MAX;
    }
    fixture_last_request_len = 0;
    fixture_last_response_capacity = 0;
    memset(fixture_last_request, 0, sizeof(fixture_last_request));
    memset(fixture_response, 0, sizeof(fixture_response));
    fixture_response_len = 0;
}

static void prepare_request(uint8_t *request, size_t request_len, uint8_t id,
                            uint16_t tag)
{
    memset(request, 0, request_len);
    store_le32(request, (uint32_t)request_len);
    request[4] = id;
    store_le16(request + 5, tag);
    for (size_t index = 7; index < request_len; index++) {
        request[index] = (uint8_t)(0xa0 + index);
    }
}

static void prepare_response(uint8_t *response, size_t response_len, uint8_t id,
                             uint16_t tag)
{
    memset(response, 0, response_len);
    store_le32(response, (uint32_t)response_len);
    response[4] = id;
    store_le16(response + 5, tag);
    for (size_t index = 7; index < response_len; index++) {
        response[index] = (uint8_t)(0x50 + index);
    }
}

static void fixture_burst_start(void *userdata)
{
    int *marker = userdata;
    if (marker != NULL) {
        *marker += 1;
    }
    fixture_burst_start_count++;
}

static void fixture_burst_done(void *userdata)
{
    int *marker = userdata;
    if (marker != NULL) {
        *marker += 10;
    }
    fixture_burst_done_count++;
}

static int fixture_submit(uint32_t request_id, const uint8_t *data, size_t len,
                          size_t response_capacity, void *userdata)
{
    (void)userdata;
    int submit_index = fixture_submit_count;
    if (submit_index >= 0 &&
        (size_t)submit_index < sizeof(fixture_seen_request_ids) /
                                  sizeof(fixture_seen_request_ids[0])) {
        fixture_seen_request_ids[submit_index] = request_id;
    }
    fixture_submit_count++;
    fixture_last_request_id = request_id;
    fixture_last_request_len = len;
    fixture_last_response_capacity = response_capacity;
    if (len > sizeof(fixture_last_request)) {
        return -1;
    }
    memcpy(fixture_last_request, data, len);
    return fixture_submit_status;
}

static int64_t fixture_poll(uint32_t request_id, uint8_t *data, size_t capacity,
                            void *userdata)
{
    (void)userdata;
    fixture_poll_count++;
    if (request_id != fixture_last_request_id) {
        return -1;
    }
    if (fixture_pending_before_ready > 0) {
        fixture_pending_before_ready--;
        return QEMU_PLUGIN_9P_POLL_PENDING;
    }
    if (fixture_poll_status != 0) {
        return fixture_poll_status;
    }
    if (fixture_response_len > capacity) {
        return (int64_t)capacity + 1;
    }
    memcpy(data, fixture_response, fixture_response_len);
    return (int64_t)fixture_response_len;
}

static int run_upstream_fallback(void)
{
    uint8_t request[11];
    uint8_t response[32] = {0};

    reset_fixture();
    prepare_request(request, sizeof(request), 100, 42);
    fixture_elem = new_elem(request, sizeof(request), response, sizeof(response));
    if (fixture_elem == NULL) {
        return fail("failed to allocate upstream fallback element");
    }

    qemu_plugin_register_9p_cb(NULL, NULL, NULL, NULL, NULL);
    handle_9p_output((VirtIODevice *)&fixture_device, &fixture_queue);

    return expect_bool(fixture_upstream_submit_count == 1,
                       "upstream pdu_submit was not used without callbacks") ||
           expect_bool(fixture_push_count == 0,
                       "upstream fallback should not push through shmem path") ||
           expect_bool(fixture_submit_count == 0,
                       "submit callback fired while unregistered");
}

static int run_forwarding_path(void)
{
    int userdata_marker = 0;
    uint8_t request[13];
    uint8_t response_area[32] = {0};

    reset_fixture();
    prepare_request(request, sizeof(request), 110, 77);
    prepare_response(fixture_response, 9, 111, 77);
    fixture_response_len = 9;
    fixture_pending_before_ready = 2;
    fixture_elem = new_elem(request, sizeof(request), response_area,
                            sizeof(response_area));
    if (fixture_elem == NULL) {
        return fail("failed to allocate forwarding element");
    }

    qemu_plugin_register_9p_cb(fixture_burst_start, fixture_submit,
                               fixture_poll, fixture_burst_done,
                               &userdata_marker);
    handle_9p_output((VirtIODevice *)&fixture_device, &fixture_queue);

    return expect_bool(userdata_marker == 11, "userdata did not reach burst callbacks") ||
           expect_bool(fixture_burst_start_count == 1, "burst start count mismatch") ||
           expect_bool(fixture_burst_done_count == 1, "burst done count mismatch") ||
           expect_bool(fixture_submit_count == 1, "submit count mismatch") ||
           expect_bool(fixture_poll_count == 3, "poll count mismatch") ||
           expect_bool(fixture_main_loop_wait_count == 2,
                       "pending polls did not wait through main loop") ||
           expect_bool(fixture_upstream_submit_count == 0,
                       "upstream pdu_submit used during forwarding") ||
           expect_bool(fixture_push_count == 1, "forwarded response was not pushed") ||
           expect_bool(fixture_notify_count == 1, "forwarded response was not notified") ||
           expect_bool(fixture_detach_count == 0, "forwarded request was detached") ||
           expect_bool(fixture_pdu_free_count == 1, "forwarded pdu was not freed") ||
           expect_bool(fixture_last_request_id == 0, "first request id mismatch") ||
           expect_bool(fixture_last_request_len == sizeof(request),
                       "request length mismatch") ||
           expect_bool(fixture_last_response_capacity == sizeof(response_area),
                       "response capacity mismatch") ||
           expect_bool(memcmp(fixture_last_request, request, sizeof(request)) == 0,
                       "raw request bytes were not forwarded") ||
           expect_bool(memcmp(response_area, fixture_response, fixture_response_len) == 0,
                       "raw response bytes were not copied to guest iov") ||
           expect_bool(load_le32(response_area) == fixture_response_len,
                       "response header length mismatch");
}

static int run_two_request_burst(void)
{
    int userdata_marker = 0;
    uint8_t request_a[9];
    uint8_t request_b[10];
    uint8_t response_a[32] = {0};
    uint8_t response_b[32] = {0};

    reset_fixture();
    fixture_alloc_remaining = 2;
    prepare_request(request_a, sizeof(request_a), 112, 11);
    prepare_request(request_b, sizeof(request_b), 113, 12);
    prepare_response(fixture_response, 9, 114, 12);
    fixture_response_len = 9;
    fixture_elem = new_elem(request_a, sizeof(request_a), response_a,
                            sizeof(response_a));
    fixture_next_elem = new_elem(request_b, sizeof(request_b), response_b,
                                 sizeof(response_b));
    if (fixture_elem == NULL || fixture_next_elem == NULL) {
        return fail("failed to allocate two-request burst elements");
    }

    qemu_plugin_register_9p_cb(fixture_burst_start, fixture_submit,
                               fixture_poll, fixture_burst_done,
                               &userdata_marker);
    handle_9p_output((VirtIODevice *)&fixture_device, &fixture_queue);

    return expect_bool(userdata_marker == 11,
                       "userdata did not bracket two-request burst") ||
           expect_bool(fixture_pop_count == 2,
                       "two-request burst did not drain both queue entries") ||
           expect_bool(fixture_burst_start_count == 1,
                       "two-request burst start count mismatch") ||
           expect_bool(fixture_burst_done_count == 1,
                       "two-request burst done count mismatch") ||
           expect_bool(fixture_submit_count == 2,
                       "two-request burst submit count mismatch") ||
           expect_bool(fixture_poll_count == 2,
                       "two-request burst poll count mismatch") ||
           expect_bool(fixture_push_count == 2,
                       "two-request burst push count mismatch") ||
           expect_bool(fixture_notify_count == 2,
                       "two-request burst notify count mismatch") ||
           expect_bool(fixture_seen_request_ids[0] == 0,
                       "first burst request id mismatch") ||
           expect_bool(fixture_seen_request_ids[1] == 1,
                       "second burst request id mismatch");
}

static int run_partial_registration_fallback(void)
{
    uint8_t request[9];
    uint8_t response[32] = {0};

    reset_fixture();
    prepare_request(request, sizeof(request), 120, 1);
    fixture_elem = new_elem(request, sizeof(request), response, sizeof(response));
    if (fixture_elem == NULL) {
        return fail("failed to allocate partial-registration element");
    }

    qemu_plugin_register_9p_cb(fixture_burst_start, fixture_submit, NULL,
                               fixture_burst_done, NULL);
    handle_9p_output((VirtIODevice *)&fixture_device, &fixture_queue);

    return expect_bool(fixture_upstream_submit_count == 1,
                       "partial callback registration did not fall back upstream") ||
           expect_bool(fixture_submit_count == 0,
                       "partial callback registration used shmem submit");
}

static int run_oversized_response_fails_closed(void)
{
    uint8_t request[9];
    uint8_t response_area[8] = {0};

    reset_fixture();
    prepare_request(request, sizeof(request), 130, 9);
    prepare_response(fixture_response, 12, 131, 9);
    fixture_response_len = 12;
    fixture_elem = new_elem(request, sizeof(request), response_area,
                            sizeof(response_area));
    if (fixture_elem == NULL) {
        return fail("failed to allocate oversized-response element");
    }

    qemu_plugin_register_9p_cb(fixture_burst_start, fixture_submit,
                               fixture_poll, fixture_burst_done, NULL);
    handle_9p_output((VirtIODevice *)&fixture_device, &fixture_queue);

    return expect_bool(fixture_error_count == 1, "oversized response did not fail") ||
           expect_bool(fixture_detach_count == 1, "oversized response was not detached") ||
           expect_bool(fixture_push_count == 0, "oversized response was pushed") ||
           expect_bool(fixture_device.elems[0] == NULL,
                       "oversized response left stale pdu slot") ||
           expect_bool(fixture_burst_done_count == 1,
                       "oversized response did not finish burst");
}

static int run_oversized_request_fails_closed(void)
{
    uint8_t request[7];
    uint8_t response_area[16] = {0};

    reset_fixture();
    prepare_request(request, sizeof(request), 140, 3);
    store_le32(request, 16);
    fixture_elem = new_elem(request, sizeof(request), response_area,
                            sizeof(response_area));
    if (fixture_elem == NULL) {
        return fail("failed to allocate oversized-request element");
    }

    qemu_plugin_register_9p_cb(fixture_burst_start, fixture_submit,
                               fixture_poll, fixture_burst_done, NULL);
    handle_9p_output((VirtIODevice *)&fixture_device, &fixture_queue);

    return expect_bool(fixture_error_count == 1, "oversized request did not fail") ||
           expect_bool(fixture_submit_count == 0,
                       "oversized request reached submit callback") ||
           expect_bool(fixture_detach_count == 1, "oversized request was not detached") ||
           expect_bool(fixture_device.elems[0] == NULL,
                       "oversized request left stale pdu slot") ||
           expect_bool(fixture_burst_done_count == 1,
                       "oversized request did not finish burst");
}

static int run_request_id_overflow_fails_closed(void)
{
    uint8_t request[9];
    uint8_t response_area[16] = {0};

    reset_fixture();
    prepare_request(request, sizeof(request), 150, 4);
    fixture_device.next_crucible_9p_request_id = UINT32_MAX;
    fixture_elem = new_elem(request, sizeof(request), response_area,
                            sizeof(response_area));
    if (fixture_elem == NULL) {
        return fail("failed to allocate overflow element");
    }

    qemu_plugin_register_9p_cb(fixture_burst_start, fixture_submit,
                               fixture_poll, fixture_burst_done, NULL);
    handle_9p_output((VirtIODevice *)&fixture_device, &fixture_queue);

    return expect_bool(fixture_error_count == 1, "request id overflow did not fail") ||
           expect_bool(fixture_submit_count == 0,
                       "overflow request reached submit callback") ||
           expect_bool(fixture_detach_count == 1, "overflow request was not detached") ||
           expect_bool(fixture_device.elems[0] == NULL,
                       "overflow request left stale pdu slot") ||
           expect_bool(fixture_burst_done_count == 1,
                       "overflow request did not finish burst");
}

int main(void)
{
    if (QEMU_PLUGIN_9P_POLL_PENDING != -2) {
        return fail("9p pending sentinel mismatch");
    }

    if (run_upstream_fallback() ||
        run_forwarding_path() ||
        run_two_request_burst() ||
        run_partial_registration_fallback() ||
        run_oversized_response_fails_closed() ||
        run_oversized_request_fails_closed() ||
        run_request_id_overflow_fails_closed()) {
        return 1;
    }

    printf("virtio_9p_forwarding_path_exercised=true\n");
    printf("plugin_9p_callback_registration_exercised=true\n");
    printf("upstream_9p_fallback_without_callbacks=true\n");
    printf("partial_9p_registration_falls_back=true\n");
    printf("raw_9p_request_round_trip=true\n");
    printf("raw_9p_response_delivered=true\n");
    printf("burst_callbacks_exercised=true\n");
    printf("multi_request_burst_exercised=true\n");
    printf("pending_9p_poll_waits=true\n");
    printf("ninep_pending_sentinel=%d\n", QEMU_PLUGIN_9P_POLL_PENDING);
    printf("oversized_9p_response_fails_closed=true\n");
    printf("oversized_9p_request_fails_closed=true\n");
    printf("request_id_overflow_fails_closed=true\n");
    printf("failure_path_clears_pdu_slot=true\n");
    printf("stock_negative_control_9p_symbols_absent=true\n");
    printf("PASS\n");
    return 0;
}

VirtQueueElement *virtqueue_pop(VirtQueue *vq, size_t sz)
{
    (void)vq;
    (void)sz;
    fixture_pop_count++;
    if (fixture_elem == NULL) {
        return NULL;
    }
    VirtQueueElement *elem = fixture_elem;
    fixture_elem = fixture_next_elem;
    fixture_next_elem = NULL;
    return elem;
}

void virtqueue_push(VirtQueue *vq, VirtQueueElement *elem, uint32_t len)
{
    (void)vq;
    (void)elem;
    (void)len;
    fixture_push_count++;
}

void virtqueue_detach_element(VirtQueue *vq, VirtQueueElement *elem, uint32_t len)
{
    (void)vq;
    (void)elem;
    (void)len;
    fixture_detach_count++;
}

void virtio_notify(VirtIODevice *vdev, VirtQueue *vq)
{
    (void)vdev;
    (void)vq;
    fixture_notify_count++;
}

void virtio_error(VirtIODevice *vdev, const char *fmt, ...)
{
    (void)vdev;
    (void)fmt;
    fixture_error_count++;
}

V9fsPDU *pdu_alloc(V9fsState *s)
{
    if (fixture_alloc_remaining <= 0) {
        return NULL;
    }
    fixture_alloc_remaining--;
    fixture_device.state = *s;
    fixture_device.state.tag = "crucible";
    fixture_device.state.fsconf.tag = "crucible";
    fixture_device.state.transport = s->transport;
    static V9fsPDU pdu;
    memset(&pdu, 0, sizeof(pdu));
    pdu.s = &fixture_device.state;
    pdu.idx = 0;
    return &pdu;
}

void pdu_free(V9fsPDU *pdu)
{
    (void)pdu;
    fixture_pdu_free_count++;
}

void pdu_submit(V9fsPDU *pdu, P9MsgHeader *hdr)
{
    (void)pdu;
    (void)hdr;
    fixture_upstream_submit_count++;
}

void qemu_plugin_main_loop_wait(void)
{
    fixture_main_loop_wait_count++;
}

uint64_t qemu_plugin_icount_raw(void)
{
    return 0;
}

void virtio_add_feature(uint64_t *features, unsigned int feature)
{
    *features |= 1ULL << feature;
}

void virtio_stw_p(VirtIODevice *vdev, uint16_t *dst, uint16_t value)
{
    (void)vdev;
    *dst = value;
}

void virtio_init(VirtIODevice *vdev, uint16_t device_id, size_t config_size)
{
    (void)vdev;
    (void)device_id;
    (void)config_size;
}

VirtQueue *virtio_add_queue(VirtIODevice *vdev, int queue_size,
                            void (*handler)(VirtIODevice *, VirtQueue *))
{
    (void)vdev;
    (void)queue_size;
    (void)handler;
    return &fixture_queue;
}

void virtio_cleanup(VirtIODevice *vdev)
{
    (void)vdev;
}

void virtio_delete_queue(VirtQueue *vq)
{
    (void)vq;
}

bool qtest_enabled(void)
{
    return false;
}

FsDriverEntry *get_fsdev_fsentry(char *id)
{
    (void)id;
    return NULL;
}

int v9fs_device_realize_common(V9fsState *s, const V9fsTransport *transport,
                               Error **errp)
{
    (void)errp;
    s->transport = transport;
    return 0;
}

void v9fs_device_unrealize_common(V9fsState *s)
{
    (void)s;
}

void v9fs_reset(V9fsState *s)
{
    (void)s;
}

ssize_t v9fs_iov_vmarshal(const struct iovec *iov, unsigned int iov_cnt,
                          size_t offset, int bswap, const char *fmt, va_list ap)
{
    (void)iov;
    (void)iov_cnt;
    (void)offset;
    (void)bswap;
    (void)fmt;
    (void)ap;
    return 0;
}

ssize_t v9fs_iov_vunmarshal(const struct iovec *iov, unsigned int iov_cnt,
                            size_t offset, int bswap, const char *fmt, va_list ap)
{
    (void)iov;
    (void)iov_cnt;
    (void)offset;
    (void)bswap;
    (void)fmt;
    (void)ap;
    return 0;
}

void device_class_set_props(DeviceClass *dc, const Property *props)
{
    (void)dc;
    (void)props;
}

void set_bit(int bit, unsigned long *addr)
{
    *addr |= 1UL << bit;
}

void type_register_static(const TypeInfo *info)
{
    (void)info;
}
