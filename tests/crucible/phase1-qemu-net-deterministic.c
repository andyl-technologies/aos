#include <stdbool.h>
#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>

typedef struct CPUState CPUState;

typedef struct run_on_cpu_data {
  long host_ulong;
} run_on_cpu_data;

struct CPUState {
  int unused;
};

static CPUState fake_cpu;
static CPUState *current_cpu = &fake_cpu;

#define RUN_ON_CPU_HOST_ULONG(value) ((run_on_cpu_data){.host_ulong = (value)})

static void
qemu_clock_advance_virtual_time(int64_t new_time)
{
  (void)new_time;
}

static int64_t
qemu_clock_deadline_ns_all(int clock, int attrs)
{
  (void)clock;
  (void)attrs;
  return -1;
}

static int64_t
qemu_clock_get_ns(int clock)
{
  (void)clock;
  return 0;
}

#define QEMU_CLOCK_VIRTUAL 0
#define QEMU_TIMER_ATTR_ALL 0

static void
async_run_on_cpu(CPUState *cpu, void (*fn)(CPUState *, run_on_cpu_data),
                 run_on_cpu_data data)
{
  fn(cpu, data);
}

typedef enum NetClientDriver {
  NET_CLIENT_DRIVER_USER = 0,
  NET_CLIENT_DRIVER_NIC = 1,
} NetClientDriver;

typedef struct NetClientState NetClientState;
typedef struct NetQueue NetQueue;
typedef void(NetPacketSent)(NetClientState *sender, ssize_t ret);

struct NetQueue {
  int unused;
};

typedef struct NetClientInfo {
  NetClientDriver type;
} NetClientInfo;

struct NetClientState {
  NetClientInfo *info;
  int link_down;
  NetQueue *incoming_queue;
  unsigned receive_disabled : 1;
  unsigned int queue_index;
  bool can_receive;
  struct NetClientState *peer;
  struct NetClientState *next;
};

typedef struct NetClientStateList {
  NetClientState *first;
} NetClientStateList;

#define QTAILQ_FOREACH(var, head, field)                                      \
  for ((var) = (head)->first; (var) != NULL; (var) = (var)->field)

static NetClientInfo control_info = {.type = NET_CLIENT_DRIVER_USER};
static NetClientInfo backend_info = {.type = NET_CLIENT_DRIVER_USER};
static NetClientInfo nic_info = {.type = NET_CLIENT_DRIVER_NIC};
static NetClientState control_client;
static NetClientState backend_client;
static NetClientState nic_queue;
static NetClientState secondary_nic_queue;
static NetQueue nic_incoming_queue;
NetClientStateList net_clients;

#define QEMU_NET_PACKET_FLAG_NONE 0

enum { MAX_QUEUED_FRAMES = 4, MAX_FRAME_LEN = 64 };

struct QueuedFrame {
  uint8_t data[MAX_FRAME_LEN];
  size_t len;
  NetClientState *sender;
  NetPacketSent *sent_cb;
};

struct Observation {
  uint64_t producer_host_tick;
  uint64_t delivery_icount;
  uint64_t guest_observed_icount;
  uint8_t payload[MAX_FRAME_LEN];
  size_t payload_len;
};

static struct QueuedFrame queued_frames[MAX_QUEUED_FRAMES];
static size_t queued_frame_count;
static unsigned int direct_receive_calls;
static unsigned int queued_append_calls;
static unsigned int flush_calls;
static unsigned int queue_sent_callback_calls;
static unsigned int notify_event_calls;
static unsigned int delivered_frame_count;
static uint64_t current_icount;
static uint64_t last_guest_observed_icount;
static uint8_t last_payload[MAX_FRAME_LEN];
static size_t last_payload_len;

static void
reset_fixture(void)
{
  control_client.info = &control_info;
  control_client.link_down = 0;
  control_client.incoming_queue = NULL;
  control_client.receive_disabled = 0;
  control_client.queue_index = 0;
  control_client.can_receive = true;
  control_client.peer = NULL;
  control_client.next = &nic_queue;

  nic_queue.info = &nic_info;
  nic_queue.link_down = 0;
  nic_queue.incoming_queue = &nic_incoming_queue;
  nic_queue.receive_disabled = 0;
  nic_queue.queue_index = 0;
  nic_queue.can_receive = true;
  nic_queue.peer = &backend_client;
  nic_queue.next = &backend_client;

  backend_client.info = &backend_info;
  backend_client.link_down = 0;
  backend_client.incoming_queue = NULL;
  backend_client.receive_disabled = 0;
  backend_client.queue_index = 0;
  backend_client.can_receive = true;
  backend_client.peer = &nic_queue;
  backend_client.next = &secondary_nic_queue;

  secondary_nic_queue.info = &nic_info;
  secondary_nic_queue.link_down = 0;
  secondary_nic_queue.incoming_queue = NULL;
  secondary_nic_queue.receive_disabled = 0;
  secondary_nic_queue.queue_index = 1;
  secondary_nic_queue.can_receive = true;
  secondary_nic_queue.peer = NULL;
  secondary_nic_queue.next = NULL;

  net_clients.first = &control_client;

  queued_frame_count = 0;
  direct_receive_calls = 0;
  queued_append_calls = 0;
  flush_calls = 0;
  queue_sent_callback_calls = 0;
  notify_event_calls = 0;
  delivered_frame_count = 0;
  current_icount = 0;
  last_guest_observed_icount = 0;
  last_payload_len = 0;
  memset(last_payload, 0, sizeof(last_payload));
}

int
qemu_can_receive_packet(NetClientState *nc)
{
  return nc != NULL && !nc->receive_disabled && nc->can_receive;
}

static ssize_t
deliver_to_guest(const uint8_t *buf, int size)
{
  delivered_frame_count++;
  last_guest_observed_icount = current_icount;
  last_payload_len = (size_t)size;
  memcpy(last_payload, buf, (size_t)size);
  return size;
}

ssize_t
qemu_receive_packet(NetClientState *nc, const uint8_t *buf, int size)
{
  direct_receive_calls++;
  if (!qemu_can_receive_packet(nc)) {
    return 0;
  }
  return deliver_to_guest(buf, size);
}

bool
qemu_net_queue_append_lossless(NetQueue *queue, NetClientState *sender,
                               unsigned flags, const uint8_t *buf,
                               size_t size, NetPacketSent *sent_cb)
{
  queued_append_calls++;
  if (queue != &nic_incoming_queue || sender != &backend_client ||
      flags != QEMU_NET_PACKET_FLAG_NONE || sent_cb == NULL) {
    return false;
  }

  if (queued_frame_count >= MAX_QUEUED_FRAMES || size > MAX_FRAME_LEN) {
    return false;
  }
  memcpy(queued_frames[queued_frame_count].data, buf, (size_t)size);
  queued_frames[queued_frame_count].len = (size_t)size;
  queued_frames[queued_frame_count].sender = sender;
  queued_frames[queued_frame_count].sent_cb = sent_cb;
  queued_frame_count++;
  return true;
}

bool
qemu_net_queue_flush(NetQueue *queue)
{
  flush_calls++;
  if (queue != &nic_incoming_queue || !qemu_can_receive_packet(&nic_queue)) {
    return false;
  }
  for (size_t index = 0; index < queued_frame_count; index++) {
    ssize_t delivered =
      deliver_to_guest(queued_frames[index].data, (int)queued_frames[index].len);
    if (queued_frames[index].sent_cb != NULL) {
      queue_sent_callback_calls++;
      queued_frames[index].sent_cb(queued_frames[index].sender, delivered);
    }
  }
  queued_frame_count = 0;
  return true;
}

void
qemu_notify_event(void)
{
  notify_event_calls++;
}

#include "plugins/api-system.c"

static int
run_skewed_producer(uint64_t producer_host_tick, struct Observation *observation)
{
  static const uint8_t frame[] = {0x52, 0x54, 0x00, 0x10, 0x00, 0x08};
  const uint64_t delivery_icount = 4096;

  reset_fixture();
  current_icount = 100;
  if (qemu_plugin_net_send(frame, sizeof(frame)) != 0 ||
      delivered_frame_count != 0 || queued_frame_count != 1 ||
      queued_append_calls != 1 || flush_calls != 0) {
    fprintf(stderr,
            "lossless queue before delivery mismatch: delivered=%u queued=%zu appends=%u flushes=%u\n",
            delivered_frame_count, queued_frame_count, queued_append_calls,
            flush_calls);
    return 1;
  }

  (void)producer_host_tick;
  current_icount = delivery_icount;
  if (qemu_plugin_net_flush() != 0 || queued_frame_count != 0 ||
      delivered_frame_count != 1 || last_guest_observed_icount != delivery_icount ||
      flush_calls != 1 || queue_sent_callback_calls != 1 ||
      notify_event_calls != 1) {
    fprintf(stderr,
            "flush delivery mismatch: queued=%zu delivered=%u observed=%llu flushes=%u callbacks=%u notify=%u\n",
            queued_frame_count, delivered_frame_count,
            (unsigned long long)last_guest_observed_icount, flush_calls,
            queue_sent_callback_calls, notify_event_calls);
    return 1;
  }

  observation->producer_host_tick = producer_host_tick;
  observation->delivery_icount = delivery_icount;
  observation->guest_observed_icount = last_guest_observed_icount;
  observation->payload_len = last_payload_len;
  memcpy(observation->payload, last_payload, last_payload_len);
  return 0;
}

static int
stock_naive_drop_without_queue(void)
{
  static const uint8_t frame[] = {0xaa, 0xbb, 0xcc, 0xdd};

  reset_fixture();
  nic_queue.can_receive = false;
  current_icount = 123;
  if (qemu_receive_packet(&nic_queue, frame, sizeof(frame)) != 0 ||
      direct_receive_calls != 1 || delivered_frame_count != 0 ||
      queued_frame_count != 0) {
    fputs("stock direct receive did not drop while NIC was not ready\n", stderr);
    return 1;
  }

  nic_queue.can_receive = true;
  current_icount = 4096;
  if (!qemu_net_queue_flush(&nic_incoming_queue) ||
      delivered_frame_count != 0 || queued_frame_count != 0) {
    fputs("stock direct receive unexpectedly preserved a dropped frame\n", stderr);
    return 1;
  }

  return 0;
}

int
main(void)
{
  static const uint8_t frame[] = {0xde, 0xad, 0xbe, 0xef};
  struct Observation early;
  struct Observation late;

  reset_fixture();
  current_icount = 77;
  if (qemu_plugin_net_can_receive() != 1 ||
      qemu_plugin_net_inject(frame, sizeof(frame)) != 0 ||
      delivered_frame_count != 1 || direct_receive_calls != 1 ||
      last_guest_observed_icount != 77 ||
      memcmp(last_payload, frame, sizeof(frame)) != 0) {
    fprintf(stderr,
            "direct injection mismatch: can_receive=%d delivered=%u direct=%u observed=%llu\n",
            qemu_plugin_net_can_receive(), delivered_frame_count,
            direct_receive_calls,
            (unsigned long long)last_guest_observed_icount);
    return 1;
  }

  reset_fixture();
  current_icount = 200;
  if (qemu_plugin_net_can_receive() != 1 ||
      qemu_plugin_net_send(frame, sizeof(frame)) != 0 ||
      queued_frame_count != 1 || delivered_frame_count != 0 ||
      queued_append_calls != 1 || queue_sent_callback_calls != 0 ||
      direct_receive_calls != 0) {
    fprintf(stderr,
            "ready NIC send should queue without delivery: can_receive=%d queued=%zu delivered=%u appends=%u callbacks=%u direct=%u\n",
            qemu_plugin_net_can_receive(), queued_frame_count,
            delivered_frame_count, queued_append_calls,
            queue_sent_callback_calls, direct_receive_calls);
    return 1;
  }
  current_icount = 201;
  if (qemu_plugin_net_flush() != 0 || queued_frame_count != 0 ||
      delivered_frame_count != 1 || last_guest_observed_icount != 201 ||
      queue_sent_callback_calls != 1 || notify_event_calls != 1) {
    fprintf(stderr,
            "ready NIC queued frame did not flush at chosen icount: queued=%zu delivered=%u observed=%llu callbacks=%u notify=%u\n",
            queued_frame_count, delivered_frame_count,
            (unsigned long long)last_guest_observed_icount,
            queue_sent_callback_calls, notify_event_calls);
    return 1;
  }

  reset_fixture();
  nic_queue.can_receive = false;
  current_icount = 88;
  if (qemu_plugin_net_can_receive() != 0 ||
      qemu_plugin_net_inject(frame, sizeof(frame)) == 0 ||
      delivered_frame_count != 0 || queued_frame_count != 0 ||
      direct_receive_calls != 1) {
    fprintf(stderr,
            "direct injection should fail closed when not ready: delivered=%u queued=%zu direct=%u\n",
            delivered_frame_count, queued_frame_count, direct_receive_calls);
    return 1;
  }

  reset_fixture();
  nic_queue.can_receive = false;
  current_icount = 300;
  if (qemu_plugin_net_send(frame, sizeof(frame)) != 0 ||
      queued_frame_count != 1 || qemu_plugin_net_flush() == 0 ||
      queued_frame_count != 1 || delivered_frame_count != 0 ||
      queue_sent_callback_calls != 0) {
    fprintf(stderr,
            "not-ready flush should fail loudly and keep queued frame: queued=%zu delivered=%u callbacks=%u\n",
            queued_frame_count, delivered_frame_count,
            queue_sent_callback_calls);
    return 1;
  }
  nic_queue.can_receive = true;
  current_icount = 301;
  if (qemu_plugin_net_flush() != 0 || queued_frame_count != 0 ||
      delivered_frame_count != 1 || last_guest_observed_icount != 301 ||
      queue_sent_callback_calls != 1) {
    fprintf(stderr,
            "not-ready queued frame did not flush after receiver recovered: queued=%zu delivered=%u observed=%llu callbacks=%u\n",
            queued_frame_count, delivered_frame_count,
            (unsigned long long)last_guest_observed_icount,
            queue_sent_callback_calls);
    return 1;
  }

  reset_fixture();
  net_clients.first = &control_client;
  control_client.next = NULL;
  if (qemu_plugin_net_inject(frame, sizeof(frame)) == 0 ||
      qemu_plugin_net_send(frame, sizeof(frame)) == 0 ||
      qemu_plugin_net_flush() == 0 ||
      qemu_plugin_net_can_receive() != -1) {
    fputs("missing NIC did not fail loudly\n", stderr);
    return 1;
  }

  if (stock_naive_drop_without_queue() != 0) {
    return 1;
  }

  if (run_skewed_producer(10, &early) != 0 ||
      run_skewed_producer(9000, &late) != 0) {
    return 1;
  }
  if (early.delivery_icount != late.delivery_icount ||
      early.guest_observed_icount != late.guest_observed_icount ||
      early.payload_len != late.payload_len ||
      memcmp(early.payload, late.payload, early.payload_len) != 0) {
    fputs("skewed producer timing changed guest-visible delivery\n", stderr);
    return 1;
  }

  reset_fixture();
  nic_queue.link_down = 1;
  if (qemu_plugin_net_can_receive() != 0 ||
      qemu_plugin_net_inject(frame, sizeof(frame)) == 0 ||
      qemu_plugin_net_send(frame, sizeof(frame)) == 0 ||
      qemu_plugin_net_flush() == 0 ||
      delivered_frame_count != 0 || queued_frame_count != 0) {
    fputs("link-down NIC did not fail loudly\n", stderr);
    return 1;
  }

  reset_fixture();
  if (qemu_plugin_net_send(frame, sizeof(frame)) != 0 || queued_frame_count != 1) {
    fputs("pre-link-down queue setup failed\n", stderr);
    return 1;
  }
  nic_queue.link_down = 1;
  if (qemu_plugin_net_flush() == 0 || delivered_frame_count != 0 ||
      queued_frame_count != 1) {
    fputs("link-down NIC flush did not fail loudly with queued frame preserved\n", stderr);
    return 1;
  }

  reset_fixture();
  backend_client.link_down = 1;
  if (qemu_plugin_net_send(frame, sizeof(frame)) == 0 ||
      qemu_plugin_net_flush() == 0 ||
      delivered_frame_count != 0 || queued_frame_count != 0) {
    fputs("link-down backend did not fail loudly\n", stderr);
    return 1;
  }

  puts("PASS");
  puts("patched_qemu_plugin_net_fixture=true");
  puts("net_inject_symbol=qemu_plugin_net_inject");
  puts("net_send_symbol=qemu_plugin_net_send");
  puts("net_flush_symbol=qemu_plugin_net_flush");
  puts("net_can_receive_symbol=qemu_plugin_net_can_receive");
  puts("direct_inject_delivers_when_ready=true");
  puts("direct_inject_fails_closed_when_not_ready=true");
  puts("lossless_send_queues_until_flush=true");
  puts("send_deferred_when_nic_ready=true");
  puts("flush_makes_frame_visible_at_delivery_icount=true");
  puts("flush_fails_loudly_when_not_ready=true");
  puts("queue_sent_callback_required=true");
  puts("skewed_producer_observed_icount_identical=true");
  puts("guest_observed_icount=4096");
  puts("delivery_icount=4096");
  puts("arrival_order_visible=false");
  puts("missing_nic_fails_loudly=true");
  puts("link_down_fails_loudly=true");
  puts("stock_negative_control_exercised=true");
  puts("stock_negative_control_drop_without_queue=true");
  return 0;
}
