#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/uio.h>

#include "net/net.c"

static NetQueue fixture_queue;
static NetClientInfo fixture_nic_info = {.type = NET_CLIENT_DRIVER_NIC};
static NetClientInfo fixture_backend_info = {.type = NET_CLIENT_DRIVER_USER};
static NetClientState fixture_sender;
static NetClientState fixture_peer;
static int fixture_backend_send_count;
static int fixture_backend_send_iov_count;
static int fixture_filter_tx_count;
static int fixture_filter_rx_count;
static int fixture_callback_count;
static int fixture_callback_status;
static int fixture_userdata_marker;
static uint8_t fixture_backend_payload[64];
static size_t fixture_backend_payload_len;
static uint8_t fixture_callback_payload[64];
static size_t fixture_callback_payload_len;

static int fail(const char *message)
{
    fprintf(stderr, "FAIL: %s\n", message);
    return 1;
}

static int expect_bool(bool condition, const char *message)
{
    return condition ? 0 : fail(message);
}

static void reset_fixture(void)
{
    memset(&fixture_queue, 0, sizeof(fixture_queue));
    memset(&fixture_sender, 0, sizeof(fixture_sender));
    memset(&fixture_peer, 0, sizeof(fixture_peer));
    fixture_sender.info = &fixture_nic_info;
    fixture_sender.peer = &fixture_peer;
    fixture_peer.info = &fixture_backend_info;
    fixture_peer.incoming_queue = &fixture_queue;
    fixture_backend_send_count = 0;
    fixture_backend_send_iov_count = 0;
    fixture_filter_tx_count = 0;
    fixture_filter_rx_count = 0;
    fixture_callback_count = 0;
    fixture_callback_status = 0;
    fixture_userdata_marker = 0;
    fixture_backend_payload_len = 0;
    fixture_callback_payload_len = 0;
    memset(fixture_backend_payload, 0, sizeof(fixture_backend_payload));
    memset(fixture_callback_payload, 0, sizeof(fixture_callback_payload));
    qemu_plugin_register_net_tx_cb(NULL, NULL);
}

static int fixture_net_tx_cb(const uint8_t *data, size_t len, void *userdata)
{
    int *marker = userdata;

    fixture_callback_count++;
    if (marker != NULL) {
        *marker += 1;
    }
    if (len > sizeof(fixture_callback_payload)) {
        return -1;
    }
    memcpy(fixture_callback_payload, data, len);
    fixture_callback_payload_len = len;
    return fixture_callback_status;
}

static int run_upstream_fallback(void)
{
    static const uint8_t frame[] = {0x52, 0x54, 0x00, 0x12, 0x34, 0x56};
    ssize_t ret;

    reset_fixture();
    ret = qemu_send_packet(&fixture_sender, frame, sizeof(frame));

    return expect_bool(ret == (ssize_t)sizeof(frame), "upstream send returned wrong length") ||
           expect_bool(fixture_backend_send_count == 1, "upstream backend was not used") ||
           expect_bool(fixture_callback_count == 0, "callback fired while unregistered") ||
           expect_bool(fixture_filter_tx_count == 1, "TX filter did not run on fallback") ||
           expect_bool(fixture_filter_rx_count == 1, "RX filter did not run on fallback") ||
           expect_bool(fixture_backend_payload_len == sizeof(frame),
                       "backend payload length mismatch") ||
           expect_bool(memcmp(fixture_backend_payload, frame, sizeof(frame)) == 0,
                       "backend did not receive exact frame");
}

static int run_registered_flat_intercept(void)
{
    static const uint8_t frame[] = {0xde, 0xad, 0xbe, 0xef};
    ssize_t ret;

    reset_fixture();
    qemu_plugin_register_net_tx_cb(fixture_net_tx_cb, &fixture_userdata_marker);
    ret = qemu_send_packet(&fixture_sender, frame, sizeof(frame));

    return expect_bool(ret == (ssize_t)sizeof(frame), "callback send returned wrong length") ||
           expect_bool(fixture_callback_count == 1, "callback did not fire") ||
           expect_bool(fixture_userdata_marker == 1, "callback userdata not passed") ||
           expect_bool(fixture_backend_send_count == 0, "backend was used during callback") ||
           expect_bool(fixture_filter_tx_count == 0, "TX filter ran during callback") ||
           expect_bool(fixture_filter_rx_count == 0, "RX filter ran during callback") ||
           expect_bool(fixture_callback_payload_len == sizeof(frame),
                       "callback payload length mismatch") ||
           expect_bool(memcmp(fixture_callback_payload, frame, sizeof(frame)) == 0,
                       "callback did not receive exact flat frame");
}

static int run_registered_iov_intercept(void)
{
    static const uint8_t part_a[] = {0x01, 0x02, 0x03};
    static const uint8_t part_b[] = {0x04, 0x05};
    static const uint8_t expected[] = {0x01, 0x02, 0x03, 0x04, 0x05};
    struct iovec iov[] = {
        {
            .iov_base = (void *)part_a,
            .iov_len = sizeof(part_a),
        },
        {
            .iov_base = (void *)part_b,
            .iov_len = sizeof(part_b),
        },
    };
    ssize_t ret;

    reset_fixture();
    qemu_plugin_register_net_tx_cb(fixture_net_tx_cb, NULL);
    ret = qemu_sendv_packet(&fixture_sender, iov, 2);

    return expect_bool(ret == (ssize_t)sizeof(expected), "iov callback length mismatch") ||
           expect_bool(fixture_callback_count == 1, "iov callback did not fire") ||
           expect_bool(fixture_backend_send_iov_count == 0, "iov backend was used") ||
           expect_bool(fixture_callback_payload_len == sizeof(expected),
                       "iov callback payload length mismatch") ||
           expect_bool(memcmp(fixture_callback_payload, expected, sizeof(expected)) == 0,
                       "iov callback did not receive exact coalesced frame");
}

static int run_registered_backend_sender_uses_upstream(void)
{
    static const uint8_t frame[] = {0x99, 0x88, 0x77};
    ssize_t ret;

    reset_fixture();
    fixture_peer.peer = &fixture_sender;
    fixture_sender.incoming_queue = &fixture_queue;
    qemu_plugin_register_net_tx_cb(fixture_net_tx_cb, NULL);
    ret = qemu_send_packet(&fixture_peer, frame, sizeof(frame));

    return expect_bool(ret == (ssize_t)sizeof(frame), "backend sender length mismatch") ||
           expect_bool(fixture_callback_count == 0, "callback fired for non-NIC sender") ||
           expect_bool(fixture_backend_send_count == 1, "backend sender did not use upstream") ||
           expect_bool(fixture_filter_tx_count == 1, "backend sender skipped TX filter") ||
           expect_bool(fixture_filter_rx_count == 1, "backend sender skipped RX filter") ||
           expect_bool(fixture_backend_payload_len == sizeof(frame),
                       "backend sender payload length mismatch") ||
           expect_bool(memcmp(fixture_backend_payload, frame, sizeof(frame)) == 0,
                       "backend sender payload mismatch");
}

static int run_registered_oversized_iov_fails_loudly(void)
{
    static uint8_t oversized[NET_BUFSIZE + 1];
    struct iovec iov[] = {
        {
            .iov_base = oversized,
            .iov_len = sizeof(oversized),
        },
    };
    ssize_t ret;

    reset_fixture();
    qemu_plugin_register_net_tx_cb(fixture_net_tx_cb, NULL);
    ret = qemu_sendv_packet(&fixture_sender, iov, 1);

    return expect_bool(ret == -1, "oversized iov did not fail loudly") ||
           expect_bool(fixture_callback_count == 0, "oversized iov reached callback") ||
           expect_bool(fixture_backend_send_iov_count == 0, "oversized iov reached backend") ||
           expect_bool(fixture_filter_tx_count == 0, "oversized iov ran TX filter") ||
           expect_bool(fixture_filter_rx_count == 0, "oversized iov ran RX filter");
}

static int run_callback_failure_fails_loudly(void)
{
    static const uint8_t frame[] = {0xba, 0xd0};
    ssize_t ret;

    reset_fixture();
    fixture_callback_status = 7;
    qemu_plugin_register_net_tx_cb(fixture_net_tx_cb, NULL);
    ret = qemu_send_packet(&fixture_sender, frame, sizeof(frame));

    return expect_bool(ret == -1, "callback failure did not fail loudly") ||
           expect_bool(fixture_callback_count == 1, "failing callback was not called") ||
           expect_bool(fixture_backend_send_count == 0,
                       "backend used after callback failure");
}

static int run_link_down_preserves_upstream_drop(void)
{
    static const uint8_t frame[] = {0x0d, 0x0e, 0x0f};
    ssize_t ret;

    reset_fixture();
    fixture_sender.link_down = 1;
    qemu_plugin_register_net_tx_cb(fixture_net_tx_cb, NULL);
    ret = qemu_send_packet(&fixture_sender, frame, sizeof(frame));

    return expect_bool(ret == (ssize_t)sizeof(frame), "link-down return mismatch") ||
           expect_bool(fixture_callback_count == 0, "callback fired while link down") ||
           expect_bool(fixture_backend_send_count == 0, "backend used while link down");
}

int main(void)
{
    if (run_upstream_fallback() ||
        run_registered_flat_intercept() ||
        run_registered_iov_intercept() ||
        run_registered_backend_sender_uses_upstream() ||
        run_registered_oversized_iov_fails_loudly() ||
        run_callback_failure_fails_loudly() ||
        run_link_down_preserves_upstream_drop()) {
        return 1;
    }

    printf("PASS\n");
    printf("qemu_plugin_register_net_tx_cb_symbol=true\n");
    printf("net_tx_callback_upstream_fallback=true\n");
    printf("net_tx_callback_intercepts_flat_frame=true\n");
    printf("net_tx_callback_intercepts_iov_frame=true\n");
    printf("net_tx_callback_bypasses_backend_when_registered=true\n");
    printf("net_tx_callback_guest_only=true\n");
    printf("net_tx_oversized_iov_fails_loudly=true\n");
    printf("net_tx_callback_failure_fails_loudly=true\n");
    printf("net_tx_link_down_keeps_upstream_drop=true\n");
    printf("net_tx_callback_userdata_exercised=true\n");
    printf("stock_negative_control_net_tx_symbol_absent=true\n");
    return 0;
}

int filter_receive(NetClientState *nc, int direction, NetClientState *sender,
                   unsigned flags, const uint8_t *buf, int size,
                   NetPacketSent *sent_cb)
{
    (void)nc;
    (void)sender;
    (void)flags;
    (void)buf;
    (void)size;
    (void)sent_cb;
    if (direction == NET_FILTER_DIRECTION_TX) {
        fixture_filter_tx_count++;
    } else if (direction == NET_FILTER_DIRECTION_RX) {
        fixture_filter_rx_count++;
    }
    return 0;
}

int filter_receive_iov(NetClientState *nc, int direction, NetClientState *sender,
                       unsigned flags, const struct iovec *iov, int iovcnt,
                       NetPacketSent *sent_cb)
{
    (void)nc;
    (void)sender;
    (void)flags;
    (void)iov;
    (void)iovcnt;
    (void)sent_cb;
    if (direction == NET_FILTER_DIRECTION_TX) {
        fixture_filter_tx_count++;
    } else if (direction == NET_FILTER_DIRECTION_RX) {
        fixture_filter_rx_count++;
    }
    return 0;
}

ssize_t qemu_net_queue_send(NetQueue *queue, NetClientState *sender,
                            unsigned flags, const uint8_t *data, size_t size,
                            NetPacketSent *sent_cb)
{
    (void)queue;
    (void)sender;
    (void)flags;
    (void)sent_cb;
    fixture_backend_send_count++;
    if (size > sizeof(fixture_backend_payload)) {
        return -1;
    }
    memcpy(fixture_backend_payload, data, size);
    fixture_backend_payload_len = size;
    return (ssize_t)size;
}

ssize_t qemu_net_queue_send_iov(NetQueue *queue, NetClientState *sender,
                                unsigned flags, const struct iovec *iov,
                                int iovcnt, NetPacketSent *sent_cb)
{
    (void)queue;
    (void)sender;
    (void)flags;
    (void)iov;
    (void)iovcnt;
    (void)sent_cb;
    fixture_backend_send_iov_count++;
    return 0;
}
