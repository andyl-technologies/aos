// SPDX-License-Identifier: GPL-2.0-only
/*
 * Live guest fixture for Crucible clock and accelerator fault gates.
 *
 * This is ordinary guest software. It talks to the production QEMU device over
 * the standardized modern virtio-pci transport and never includes QEMU headers
 * or shares process-private objects with the host.
 */

#define _GNU_SOURCE

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <linux/rtc.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define VIRTIO_VENDOR_ID 0x1af4
#define VIRTIO_CRUCIBLE_PCI_DEVICE_ID 0x103f
#define VIRTIO_PCI_CAP_ID 0x09
#define VIRTIO_PCI_CAP_COMMON_CFG 1
#define VIRTIO_PCI_CAP_NOTIFY_CFG 2
#define VIRTIO_PCI_CAP_DEVICE_CFG 4
#define VIRTIO_F_VERSION_1 32
#define VIRTQ_DESC_F_NEXT 1
#define VIRTQ_DESC_F_WRITE 2
#define VIRTIO_STATUS_ACKNOWLEDGE 1
#define VIRTIO_STATUS_DRIVER 2
#define VIRTIO_STATUS_DRIVER_OK 4
#define VIRTIO_STATUS_FEATURES_OK 8
#define QUEUE_SIZE 64
#define PAGE_BYTES 4096

struct virtq_desc {
    uint64_t address;
    uint32_t length;
    uint16_t flags;
    uint16_t next;
} __attribute__((packed));

struct virtq_used_element {
    uint32_t id;
    uint32_t length;
} __attribute__((packed));

struct accelerator_config {
    uint16_t protocol_version;
    uint16_t class_mask;
    uint32_t queue_depth;
    uint32_t data_max;
    uint32_t flags;
    uint8_t device_id[32];
} __attribute__((packed));

struct accelerator_job {
    uint16_t protocol_version;
    uint16_t class_id;
    uint16_t job_kind;
    uint16_t queue_id;
    uint64_t sequence;
    uint64_t service_units;
    uint32_t input_len;
    uint32_t output_capacity;
    uint32_t status;
    uint32_t output_len;
} __attribute__((packed));

struct pci_capability {
    uint8_t next;
    uint8_t bar;
    uint32_t offset;
    uint32_t length;
    uint32_t notify_multiplier;
};

struct mapped_capability {
    volatile uint8_t *mapping;
    size_t mapping_length;
    volatile uint8_t *address;
    struct pci_capability capability;
};

struct accelerator_device {
    int config_fd;
    char device_path[512];
    struct mapped_capability common;
    struct mapped_capability notify;
    struct mapped_capability device;
    struct virtq_desc *descriptors;
    volatile uint16_t *available;
    volatile uint16_t *used;
    uint8_t *request;
    struct accelerator_job *response;
    uint8_t *output;
    uint16_t available_index;
    uint16_t used_index;
    uint16_t notify_offset;
};

static uint16_t load_u16(const void *pointer)
{
    uint16_t value;
    memcpy(&value, pointer, sizeof(value));
    return value;
}

static uint32_t load_u32(const void *pointer)
{
    uint32_t value;
    memcpy(&value, pointer, sizeof(value));
    return value;
}

static void store_u16(void *pointer, uint16_t value)
{
    memcpy(pointer, &value, sizeof(value));
}

static void store_u32(void *pointer, uint32_t value)
{
    memcpy(pointer, &value, sizeof(value));
}

static void store_u64(void *pointer, uint64_t value)
{
    memcpy(pointer, &value, sizeof(value));
}

static int read_exact_at(int fd, void *bytes, size_t length, off_t offset)
{
    ssize_t count = pread(fd, bytes, length, offset);
    return count == (ssize_t)length ? 0 : -1;
}

static int write_exact_at(int fd, const void *bytes, size_t length, off_t offset)
{
    ssize_t count = pwrite(fd, bytes, length, offset);
    return count == (ssize_t)length ? 0 : -1;
}

static uint64_t guest_physical_address(void *pointer)
{
    uint64_t entry = 0;
    uint64_t virtual_address = (uint64_t)(uintptr_t)pointer;
    int pagemap = open("/proc/self/pagemap", O_RDONLY | O_CLOEXEC);
    if (pagemap < 0 || read_exact_at(pagemap, &entry, sizeof(entry),
                                     (off_t)((virtual_address / PAGE_BYTES) * 8)) != 0) {
        if (pagemap >= 0) {
            close(pagemap);
        }
        return 0;
    }
    close(pagemap);
    if ((entry & (UINT64_C(1) << 63)) == 0) {
        return 0;
    }
    return ((entry & ((UINT64_C(1) << 55) - 1)) * PAGE_BYTES)
           + (virtual_address % PAGE_BYTES);
}

static void *allocate_dma_page(void)
{
    void *page = mmap(NULL, PAGE_BYTES, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS | MAP_LOCKED, -1, 0);
    if (page == MAP_FAILED) {
        return NULL;
    }
    memset(page, 0, PAGE_BYTES);
    if (guest_physical_address(page) == 0) {
        munmap(page, PAGE_BYTES);
        return NULL;
    }
    return page;
}

static int pci_identity_matches(int fd)
{
    uint16_t vendor = 0;
    uint16_t device = 0;
    return read_exact_at(fd, &vendor, sizeof(vendor), 0) == 0
           && read_exact_at(fd, &device, sizeof(device), 2) == 0
           && vendor == VIRTIO_VENDOR_ID
           && device == VIRTIO_CRUCIBLE_PCI_DEVICE_ID;
}

static int find_accelerator(struct accelerator_device *device)
{
    DIR *directory = opendir("/sys/bus/pci/devices");
    if (directory == NULL) {
        return -1;
    }
    struct dirent *entry;
    while ((entry = readdir(directory)) != NULL) {
        if (entry->d_name[0] == '.') {
            continue;
        }
        char path[512];
        int length = snprintf(path, sizeof(path), "/sys/bus/pci/devices/%s", entry->d_name);
        if (length <= 0 || (size_t)length >= sizeof(path)) {
            continue;
        }
        char config_path[560];
        length = snprintf(config_path, sizeof(config_path), "%s/config", path);
        if (length <= 0 || (size_t)length >= sizeof(config_path)) {
            continue;
        }
        int fd = open(config_path, O_RDWR | O_CLOEXEC);
        if (fd < 0) {
            continue;
        }
        uint16_t vendor = 0;
        uint16_t device_id = 0;
        uint16_t subsystem = 0;
        if (read_exact_at(fd, &vendor, sizeof(vendor), 0) == 0
            && read_exact_at(fd, &device_id, sizeof(device_id), 2) == 0
            && read_exact_at(fd, &subsystem, sizeof(subsystem), 0x2e) == 0) {
            printf("CRUCIBLE_PCI_CANDIDATE path=%s vendor=%04x device=%04x subsystem=%04x\n",
                   path, (unsigned)vendor, (unsigned)device_id,
                   (unsigned)subsystem);
        }
        if (pci_identity_matches(fd)) {
            device->config_fd = fd;
            memcpy(device->device_path, path, (size_t)strlen(path) + 1);
            closedir(directory);
            return 0;
        }
        close(fd);
    }
    closedir(directory);
    return -1;
}

static int read_capability(int fd, uint8_t pointer, struct pci_capability *capability,
                           uint8_t *kind)
{
    uint8_t header[20] = {0};
    if (read_exact_at(fd, header, sizeof(header), pointer) != 0
        || header[0] != VIRTIO_PCI_CAP_ID || header[2] < 16) {
        return -1;
    }
    capability->next = header[1];
    *kind = header[3];
    capability->bar = header[4];
    capability->offset = load_u32(header + 8);
    capability->length = load_u32(header + 12);
    capability->notify_multiplier = header[2] >= 20 ? load_u32(header + 16) : 0;
    return 0;
}

static int map_capability(struct accelerator_device *device,
                          const struct pci_capability *capability,
                          struct mapped_capability *mapped)
{
    char path[560];
    int length = snprintf(path, sizeof(path), "%s/resource%u",
                          device->device_path, capability->bar);
    if (length <= 0 || (size_t)length >= sizeof(path)) {
        return -1;
    }
    int fd = open(path, O_RDWR | O_SYNC | O_CLOEXEC);
    if (fd < 0) {
        return -1;
    }
    struct stat status;
    if (fstat(fd, &status) != 0 || status.st_size <= 0
        || capability->offset > (uint64_t)status.st_size
        || capability->length > (uint64_t)status.st_size - capability->offset) {
        close(fd);
        return -1;
    }
    void *mapping = mmap(NULL, (size_t)status.st_size, PROT_READ | PROT_WRITE,
                         MAP_SHARED, fd, 0);
    close(fd);
    if (mapping == MAP_FAILED) {
        return -1;
    }
    mapped->mapping = mapping;
    mapped->mapping_length = (size_t)status.st_size;
    mapped->address = (volatile uint8_t *)mapping + capability->offset;
    mapped->capability = *capability;
    return 0;
}

static int discover_capabilities(struct accelerator_device *device)
{
    uint8_t pointer = 0;
    if (read_exact_at(device->config_fd, &pointer, sizeof(pointer), 0x34) != 0) {
        return -1;
    }
    unsigned visited = 0;
    while (pointer != 0 && visited++ < 64) {
        uint8_t id = 0;
        uint8_t next = 0;
        if (read_exact_at(device->config_fd, &id, sizeof(id), pointer) != 0
            || read_exact_at(device->config_fd, &next, sizeof(next), pointer + 1) != 0) {
            return -1;
        }
        if (id == VIRTIO_PCI_CAP_ID) {
            struct pci_capability capability;
            uint8_t kind = 0;
            if (read_capability(device->config_fd, pointer, &capability, &kind) != 0) {
                return -1;
            }
            struct mapped_capability *destination = NULL;
            if (kind == VIRTIO_PCI_CAP_COMMON_CFG) {
                destination = &device->common;
            } else if (kind == VIRTIO_PCI_CAP_NOTIFY_CFG) {
                destination = &device->notify;
            } else if (kind == VIRTIO_PCI_CAP_DEVICE_CFG) {
                destination = &device->device;
            }
            if (destination != NULL && destination->mapping == NULL
                && map_capability(device, &capability, destination) != 0) {
                return -1;
            }
        }
        pointer = next;
    }
    return device->common.mapping != NULL && device->notify.mapping != NULL
                   && device->device.mapping != NULL
               ? 0
               : -1;
}

static int unbind_pci_driver(const struct accelerator_device *device)
{
    char driver_path[560];
    int length = snprintf(driver_path, sizeof(driver_path), "%s/driver",
                          device->device_path);
    if (length <= 0 || (size_t)length >= sizeof(driver_path)) {
        return -1;
    }
    struct stat status;
    if (lstat(driver_path, &status) != 0) {
        return errno == ENOENT ? 0 : -1;
    }

    char unbind_path[600];
    length = snprintf(unbind_path, sizeof(unbind_path), "%s/unbind", driver_path);
    if (length <= 0 || (size_t)length >= sizeof(unbind_path)) {
        return -1;
    }
    int unbind = open(unbind_path, O_WRONLY | O_CLOEXEC);
    if (unbind < 0) {
        return -1;
    }
    const char *address = strrchr(device->device_path, '/');
    if (address == NULL || address[1] == '\0') {
        close(unbind);
        return -1;
    }
    address++;
    ssize_t written = write(unbind, address, strlen(address));
    close(unbind);
    return written == (ssize_t)strlen(address) ? 0 : -1;
}

static int enable_pci_device(struct accelerator_device *device)
{
    char enable_path[560];
    int length = snprintf(enable_path, sizeof(enable_path), "%s/enable", device->device_path);
    if (length <= 0 || (size_t)length >= sizeof(enable_path)) {
        return -1;
    }
    int enable = open(enable_path, O_WRONLY | O_CLOEXEC);
    if (enable >= 0) {
        ssize_t enabled = write(enable, "1\n", 2);
        close(enable);
        if (enabled != 2) {
            return -1;
        }
    }
    uint16_t command = 0;
    if (read_exact_at(device->config_fd, &command, sizeof(command), 4) != 0) {
        return -1;
    }
    command |= 0x6;
    return write_exact_at(device->config_fd, &command, sizeof(command), 4);
}

static int setup_virtqueue(struct accelerator_device *device)
{
    volatile uint8_t *common = device->common.address;
    common[20] = 0;
    common[20] = VIRTIO_STATUS_ACKNOWLEDGE | VIRTIO_STATUS_DRIVER;

    store_u32((void *)(common + 0), 1);
    uint32_t device_features = load_u32((const void *)(common + 4));
    if ((device_features & (UINT32_C(1) << (VIRTIO_F_VERSION_1 - 32))) == 0) {
        return -1;
    }
    store_u32((void *)(common + 8), 1);
    store_u32((void *)(common + 12), UINT32_C(1) << (VIRTIO_F_VERSION_1 - 32));
    common[20] |= VIRTIO_STATUS_FEATURES_OK;
    if ((common[20] & VIRTIO_STATUS_FEATURES_OK) == 0) {
        return -1;
    }

    store_u16((void *)(common + 22), 0);
    uint16_t maximum = load_u16((const void *)(common + 24));
    if (maximum < QUEUE_SIZE) {
        return -1;
    }
    store_u16((void *)(common + 24), QUEUE_SIZE);
    device->notify_offset = load_u16((const void *)(common + 30));

    device->descriptors = allocate_dma_page();
    device->available = allocate_dma_page();
    device->used = allocate_dma_page();
    device->request = allocate_dma_page();
    device->response = allocate_dma_page();
    device->output = allocate_dma_page();
    if (device->descriptors == NULL || device->available == NULL || device->used == NULL
        || device->request == NULL || device->response == NULL || device->output == NULL) {
        return -1;
    }
    store_u64((void *)(common + 32), guest_physical_address(device->descriptors));
    store_u64((void *)(common + 40), guest_physical_address((void *)device->available));
    store_u64((void *)(common + 48), guest_physical_address((void *)device->used));
    store_u16((void *)(common + 28), 1);
    common[20] |= VIRTIO_STATUS_DRIVER_OK;
    return 0;
}

static int accelerator_open(struct accelerator_device *device)
{
    memset(device, 0, sizeof(*device));
    device->config_fd = -1;
    if (find_accelerator(device) != 0) {
        printf("CRUCIBLE_ACCELERATOR_OPEN_STAGE=discover-pci result=FAIL\n");
        return -1;
    }
    printf("CRUCIBLE_ACCELERATOR_PCI path=%s\n", device->device_path);
    if (unbind_pci_driver(device) != 0) {
        printf("CRUCIBLE_ACCELERATOR_OPEN_STAGE=unbind-pci-driver result=FAIL errno=%d\n",
               errno);
        return -1;
    }
    if (enable_pci_device(device) != 0) {
        printf("CRUCIBLE_ACCELERATOR_OPEN_STAGE=enable-pci result=FAIL errno=%d\n",
               errno);
        return -1;
    }
    if (discover_capabilities(device) != 0) {
        printf("CRUCIBLE_ACCELERATOR_OPEN_STAGE=map-capabilities result=FAIL errno=%d\n",
               errno);
        return -1;
    }
    if (setup_virtqueue(device) != 0) {
        printf("CRUCIBLE_ACCELERATOR_OPEN_STAGE=setup-virtqueue result=FAIL errno=%d\n",
               errno);
        return -1;
    }
    const struct accelerator_config *config =
        (const struct accelerator_config *)(const void *)device->device.address;
    if (config->protocol_version != 1 || config->class_mask != 7
        || config->queue_depth != QUEUE_SIZE || config->data_max != 4608
        || (config->flags & 1) == 0) {
        printf("CRUCIBLE_ACCELERATOR_OPEN_STAGE=validate-config result=FAIL "
               "protocol=%u class_mask=%u queue_depth=%u data_max=%u flags=%u\n",
               config->protocol_version, config->class_mask, config->queue_depth,
               config->data_max, config->flags);
        return -1;
    }
    printf("CRUCIBLE_ACCELERATOR_OPEN_STAGE=ready result=PASS\n");
    return 0;
}

static int accelerator_submit(struct accelerator_device *device, uint16_t class_id,
                              uint64_t sequence, uint64_t service_units,
                              const uint8_t *input, uint32_t input_length,
                              uint32_t output_capacity)
{
    memset(device->request, 0, PAGE_BYTES);
    memset(device->response, 0, PAGE_BYTES);
    memset(device->output, 0, PAGE_BYTES);
    struct accelerator_job *request = (struct accelerator_job *)(void *)device->request;
    request->protocol_version = 1;
    request->class_id = class_id;
    request->job_kind = 1;
    request->sequence = sequence;
    request->service_units = service_units;
    request->input_len = input_length;
    request->output_capacity = output_capacity;
    memcpy(device->request + sizeof(*request), input, input_length);

    device->descriptors[0].address = guest_physical_address(device->request);
    device->descriptors[0].length = (uint32_t)sizeof(*request) + input_length;
    device->descriptors[0].flags = VIRTQ_DESC_F_NEXT;
    device->descriptors[0].next = 1;
    device->descriptors[1].address = guest_physical_address(device->response);
    device->descriptors[1].length = sizeof(*device->response);
    device->descriptors[1].flags = VIRTQ_DESC_F_WRITE | VIRTQ_DESC_F_NEXT;
    device->descriptors[1].next = 2;
    device->descriptors[2].address = guest_physical_address(device->output);
    device->descriptors[2].length = output_capacity;
    device->descriptors[2].flags = VIRTQ_DESC_F_WRITE;
    device->descriptors[2].next = 0;

    volatile uint16_t *available_ring = device->available + 2;
    available_ring[device->available_index % QUEUE_SIZE] = 0;
    __sync_synchronize();
    device->available_index++;
    device->available[1] = device->available_index;
    __sync_synchronize();
    uintptr_t notify_byte_offset =
        (uintptr_t)device->notify_offset * device->notify.capability.notify_multiplier;
    if (notify_byte_offset + sizeof(uint16_t) > device->notify.capability.length) {
        return -1;
    }
    store_u16((void *)(device->notify.address + notify_byte_offset), 0);

    for (uint64_t attempt = 0; attempt < UINT64_C(500000000); attempt++) {
        __sync_synchronize();
        if (device->used[1] != device->used_index) {
            volatile struct virtq_used_element *ring =
                (volatile struct virtq_used_element *)(void *)(device->used + 2);
            struct virtq_used_element element = ring[device->used_index % QUEUE_SIZE];
            if (element.id != 0 || element.length < sizeof(*device->response)) {
                return -1;
            }
            device->used_index++;
            return 0;
        }
        __asm__ __volatile__("pause" ::: "memory");
    }
    return -1;
}

static int run_accelerator_jobs(void)
{
    struct accelerator_device device;
    if (accelerator_open(&device) != 0) {
        printf("CRUCIBLE_ACCELERATOR_OPEN=FAIL errno=%d\n", errno);
        return -1;
    }

    uint8_t gpu[20];
    store_u32(gpu, 2);
    int32_t gpu_values[] = {1, 2, 3, 4};
    memcpy(gpu + 4, gpu_values, sizeof(gpu_values));
    if (accelerator_submit(&device, 1, 1, 1000, gpu, sizeof(gpu), 8) != 0) {
        return -1;
    }
    int32_t gpu_left = 0;
    int32_t gpu_right = 0;
    memcpy(&gpu_left, device.output, sizeof(gpu_left));
    memcpy(&gpu_right, device.output + 4, sizeof(gpu_right));
    printf("CRUCIBLE_ACCELERATOR_GPU status=%u length=%u values=%d,%d\n",
           device.response->status, device.response->output_len, gpu_left, gpu_right);

    const uint8_t tpu[] = {1, 0, 2, 0, 1, 0, 2, 3, 4, 5};
    if (accelerator_submit(&device, 2, 2, 1000, tpu, sizeof(tpu), 4) != 0) {
        return -1;
    }
    int32_t tpu_result = 0;
    memcpy(&tpu_result, device.output, sizeof(tpu_result));
    printf("CRUCIBLE_ACCELERATOR_TPU status=%u length=%u value=%d\n",
           device.response->status, device.response->output_len, tpu_result);

    uint8_t fpga[259];
    for (unsigned index = 0; index < 256; index++) {
        fpga[index] = (uint8_t)(255 - index);
    }
    fpga[256] = 0;
    fpga[257] = 1;
    fpga[258] = 255;
    if (accelerator_submit(&device, 3, 3, 1000, fpga, sizeof(fpga), 3) != 0) {
        return -1;
    }
    printf("CRUCIBLE_ACCELERATOR_FPGA status=%u length=%u values=%u,%u,%u\n",
           device.response->status, device.response->output_len,
           device.output[0], device.output[1], device.output[2]);
    return 0;
}

static uint64_t read_arch_counter(void)
{
#if defined(__x86_64__)
    uint32_t low;
    uint32_t high;
    __asm__ __volatile__("rdtsc" : "=a"(low), "=d"(high));
    return ((uint64_t)high << 32) | low;
#elif defined(__aarch64__)
    uint64_t value;
    __asm__ __volatile__("mrs %0, cntvct_el0" : "=r"(value));
    return value;
#else
#error unsupported Crucible fault-hardware guest architecture
#endif
}

static void print_clock_sample(const char *label)
{
    struct timespec monotonic;
    struct timespec realtime;
    if (clock_gettime(CLOCK_MONOTONIC, &monotonic) != 0
        || clock_gettime(CLOCK_REALTIME, &realtime) != 0) {
        printf("CRUCIBLE_CLOCK_%s=FAIL errno=%d\n", label, errno);
        return;
    }
    printf("CRUCIBLE_CLOCK_%s counter=%" PRIu64 " monotonic=%" PRId64 ".%09ld realtime=%" PRId64 ".%09ld\n",
           label, read_arch_counter(), (int64_t)monotonic.tv_sec, monotonic.tv_nsec,
           (int64_t)realtime.tv_sec, realtime.tv_nsec);
}

int main(void)
{
    (void)mount("proc", "/proc", "proc", 0, NULL);
    (void)mount("sysfs", "/sys", "sysfs", 0, NULL);
    setvbuf(stdout, NULL, _IONBF, 0);

    printf("CRUCIBLE_FAULT_HARDWARE_GUEST=READY\n");
    print_clock_sample("BEFORE");
    int accelerator = run_accelerator_jobs();
    print_clock_sample("AFTER");
    printf("CRUCIBLE_FAULT_HARDWARE_GUEST=%s\n", accelerator == 0 ? "PASS" : "FAIL");

    const struct timespec interval = {0, 20000000};
    for (;;) {
        nanosleep(&interval, NULL);
    }
}
