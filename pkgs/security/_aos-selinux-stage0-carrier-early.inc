// SPDX-License-Identifier: Apache-2.0
// Static pre-policy loop and dm-verity activation for the signed Mount carrier.

static int open_retained_carrier_launcher(char *observed_context, size_t context_capacity) {
    struct stat root_status;
    int root_fd = open(AOS_MOUNT_CARRIER_ROOT, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    int descriptor;

    if (root_fd < 0 || fstat(root_fd, &root_status) < 0) {
        fail_closed("open retained Mount carrier root for systemd execution");
    }
    descriptor = open_verified_mount_carrier_file(
        root_fd, "launcher", EXPECTED_INIT_EXEC_CONTEXT, root_status.st_dev,
        observed_context, context_capacity);
    close(root_fd);
    return descriptor;
}

static void ensure_carrier_device_node(const char *path, mode_t type, dev_t device) {
    struct stat metadata;

    if (mknod(path, type | 0600, device) < 0 && errno != EEXIST) {
        fail_closed("create Mount carrier device %s: %s", path, strerror(errno));
    }
    if (lstat(path, &metadata) < 0 || (metadata.st_mode & S_IFMT) != type ||
        metadata.st_rdev != device || metadata.st_uid != 0 || metadata.st_gid != 0) {
        fail_closed("Mount carrier device %s has the wrong physical identity", path);
    }
}

static int open_signed_carrier_artifact(
    const char *name,
    off_t minimum_size,
    off_t maximum_size) {
    struct open_how directory_how = {
        .flags = O_PATH | O_DIRECTORY | O_CLOEXEC,
        .resolve = RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS |
                   RESOLVE_NO_SYMLINKS | RESOLVE_NO_XDEV,
    };
    struct open_how artifact_how = {
        .flags = O_RDONLY | O_CLOEXEC | O_NOCTTY,
        .resolve = RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS |
                   RESOLVE_NO_SYMLINKS | RESOLVE_NO_XDEV,
    };
    struct stat image_root;
    struct stat metadata;
    int image_fd;
    int carrier_fd;
    int descriptor;

    require_filesystem(AOS_MOUNT_CARRIER_SOURCE, EROFS_SUPER_MAGIC_V1, ST_RDONLY | ST_NODEV, 0);
    image_fd = open("/newroot", O_PATH | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (image_fd < 0 || fstat(image_fd, &image_root) < 0) {
        fail_closed("open signed stage1 root for Mount carrier artifact: %s", strerror(errno));
    }
    carrier_fd = (int)syscall(
        SYS_openat2,
        image_fd,
        "lib/aos/mount-executable-carrier",
        &directory_how,
        sizeof(directory_how));
    close(image_fd);
    if (carrier_fd < 0) {
        fail_closed("resolve exact signed-stage1 Mount carrier directory: %s", strerror(errno));
    }
    descriptor = (int)syscall(SYS_openat2, carrier_fd, name, &artifact_how, sizeof(artifact_how));
    close(carrier_fd);
    if (descriptor < 0 ||
        fstat(descriptor, &metadata) < 0 || !S_ISREG(metadata.st_mode) ||
        metadata.st_uid != 0 || metadata.st_gid != 0 ||
        (metadata.st_mode & 0777) != 0444 || metadata.st_dev != image_root.st_dev ||
        metadata.st_size < minimum_size || metadata.st_size > maximum_size) {
        fail_closed("Mount carrier %s is not a bounded signed-stage1 artifact", name);
    }
    return descriptor;
}

static void require_signed_carrier_hash(void) {
    char hash[66];
    const unsigned char *expected = _binary_carrier_root_hash_bin_start;
    int descriptor = open_signed_carrier_artifact("carrier.root-hash", 65, 65);
    ssize_t count = read(descriptor, hash, sizeof(hash));

    close(descriptor);
    if (count != 65 || memcmp(hash, expected, 65) != 0) {
        fail_closed("signed stage1 carrier hash differs from stage0 executable authority");
    }
}

static int configure_carrier_loop(int source_fd, off_t expected_size, char *path, size_t capacity) {
    struct loop_config configuration = {0};
    struct loop_info64 observed = {0};
    struct stat source_metadata;
    unsigned long long capacity_bytes = 0;
    int read_only = 0;
    int control;
    int index;
    int loop_fd;

    ensure_carrier_device_node("/dev/loop-control", S_IFCHR, makedev(10, 237));
    control = open("/dev/loop-control", O_RDWR | O_CLOEXEC | O_NOFOLLOW);
    if (control < 0 || (index = ioctl(control, LOOP_CTL_GET_FREE)) < 0) {
        fail_closed("reserve Mount carrier loop device: %s", strerror(errno));
    }
    close(control);
    if (snprintf(path, capacity, "/dev/loop%d", index) >= (int)capacity) {
        fail_closed("Mount carrier loop path exceeds its bound");
    }
    ensure_carrier_device_node(path, S_IFBLK, makedev(7, (unsigned int)index));
    loop_fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (loop_fd < 0 || fstat(source_fd, &source_metadata) < 0) {
        fail_closed("open retained Mount carrier loop device: %s", strerror(errno));
    }

    configuration.fd = (unsigned int)source_fd;
    configuration.info.lo_flags = LO_FLAGS_AUTOCLEAR;
    if (ioctl(loop_fd, LOOP_CONFIGURE, &configuration) < 0 ||
        ioctl(loop_fd, LOOP_GET_STATUS64, &observed) < 0 ||
        ioctl(loop_fd, BLKROGET, &read_only) < 0 ||
        ioctl(loop_fd, BLKGETSIZE64, &capacity_bytes) < 0 ||
        observed.lo_inode != (unsigned long long)source_metadata.st_ino ||
        (observed.lo_flags & (LO_FLAGS_AUTOCLEAR | LO_FLAGS_READ_ONLY)) !=
            (LO_FLAGS_AUTOCLEAR | LO_FLAGS_READ_ONLY) ||
        read_only != 1 ||
        (expected_size > 0 && capacity_bytes != (unsigned long long)expected_size)) {
        fail_closed("Mount carrier loop is not the exact read-only signed image");
    }
    return loop_fd;
}

static void initialize_carrier_dm_request(struct dm_ioctl *control, size_t size) {
    memset(control, 0, sizeof(*control));
    control->version[0] = DM_VERSION_MAJOR;
    control->version[1] = DM_VERSION_MINOR;
    control->version[2] = DM_VERSION_PATCHLEVEL;
    control->data_size = size;
    control->data_start = sizeof(*control);
    memcpy(control->name, "aos-mount-carrier", sizeof("aos-mount-carrier"));
}

static dev_t activate_carrier_mapper(const char *data_loop, const char *hash_loop) {
    union {
        struct dm_ioctl control;
        unsigned char bytes[4096];
    } request = {0};
    struct dm_ioctl *control = &request.control;
    struct dm_target_spec *target;
    const unsigned char *root_hash = _binary_carrier_root_hash_bin_start;
    char *parameters;
    size_t parameter_capacity;
    int parameter_size;
    int descriptor;
    dev_t device;

    ensure_directory("/dev/mapper", 0755);
    ensure_carrier_device_node("/dev/mapper/control", S_IFCHR, makedev(10, 236));
    descriptor = open("/dev/mapper/control", O_RDWR | O_CLOEXEC | O_NOFOLLOW);
    if (descriptor < 0) {
        fail_closed("open Mount carrier mapper control: %s", strerror(errno));
    }
    initialize_carrier_dm_request(control, sizeof(*control));
    control->flags = DM_READONLY_FLAG;
    if (ioctl(descriptor, DM_DEV_CREATE, control) < 0) {
        fail_closed("create read-only Mount carrier mapper: %s", strerror(errno));
    }

    initialize_carrier_dm_request(control, sizeof(request));
    control->flags = DM_READONLY_FLAG;
    control->target_count = 1;
    target = (struct dm_target_spec *)(request.bytes + control->data_start);
    target->sector_start = 0;
    target->length = 32768U * 8U;
    memcpy(target->target_type, "verity", sizeof("verity"));
    parameters = (char *)(target + 1);
    parameter_capacity = sizeof(request) - control->data_start - sizeof(*target);
    parameter_size = snprintf(
        parameters,
        parameter_capacity,
        "1 %s %s 4096 4096 32768 1 sha256 %.*s %s",
        data_loop,
        hash_loop,
        64,
        root_hash,
        AOS_MOUNT_CARRIER_SALT);
    if (parameter_size < 0 || (size_t)parameter_size >= parameter_capacity) {
        fail_closed("Mount carrier dm-verity table exceeds its bound");
    }
    target->next = (sizeof(*target) + (size_t)parameter_size + 1U + 7U) & ~7U;
    control->data_size = control->data_start + target->next;
    if (control->data_size > sizeof(request) ||
        ioctl(descriptor, DM_TABLE_LOAD, control) < 0) {
        fail_closed("load signed Mount carrier dm-verity table: %s", strerror(errno));
    }

    initialize_carrier_dm_request(control, sizeof(*control));
    if (ioctl(descriptor, DM_DEV_SUSPEND, control) < 0) {
        fail_closed("activate Mount carrier dm-verity table: %s", strerror(errno));
    }
    initialize_carrier_dm_request(control, sizeof(*control));
    if (ioctl(descriptor, DM_DEV_STATUS, control) < 0 ||
        (control->flags & (DM_ACTIVE_PRESENT_FLAG | DM_READONLY_FLAG)) !=
            (DM_ACTIVE_PRESENT_FLAG | DM_READONLY_FLAG) ||
        control->target_count != 1) {
        fail_closed("Mount carrier mapper did not become active and read-only");
    }
    device = control->dev;
    close(descriptor);
    ensure_carrier_device_node(AOS_MOUNT_CARRIER_MAPPER, S_IFBLK, device);
    require_mount_carrier_table(device);
    return device;
}

static void mount_signed_carrier_before_policy(void) {
    char data_loop_path[64];
    char hash_loop_path[64];
    int data_source;
    int hash_source;
    int data_loop;
    int hash_loop;
    dev_t device;

    require_signed_carrier_hash();
    data_source = open_signed_carrier_artifact("carrier.ext4", 128U * 1024U * 1024U, 128U * 1024U * 1024U);
    hash_source = open_signed_carrier_artifact("carrier.hash", 1, 8U * 1024U * 1024U);
    data_loop = configure_carrier_loop(
        data_source, 128U * 1024U * 1024U, data_loop_path, sizeof(data_loop_path));
    hash_loop = configure_carrier_loop(
        hash_source, 0, hash_loop_path, sizeof(hash_loop_path));
    close(data_source);
    close(hash_source);

    device = activate_carrier_mapper(data_loop_path, hash_loop_path);
    ensure_directory("/run/aos", 0755);
    ensure_directory(AOS_MOUNT_CARRIER_ROOT, 0755);
    mount_filesystem(
        AOS_MOUNT_CARRIER_MAPPER,
        AOS_MOUNT_CARRIER_ROOT,
        "ext4",
        MS_RDONLY | MS_NOSUID | MS_NODEV,
        NULL,
        EXT4_SUPER_MAGIC,
        ST_RDONLY | ST_NOSUID | ST_NODEV,
        ST_NOEXEC);
    close(data_loop);
    close(hash_loop);
    log_status("signed Mount carrier mounted before policy: st_dev=%ju", (uintmax_t)device);
}
