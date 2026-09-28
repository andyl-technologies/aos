/* SPDX-License-Identifier: MIT */
/* Pure tests of the actual statmount admission reducer; no mount or TPM I/O. */
#define AOS_VIEW_ZFS_SOURCE "testpool/var/lib"
#define main runtime_roots_production_main
#include "aos-selinux-runtime-roots.c"
#undef main

static uint32_t append_string(struct view_mount_response *response, const char *value) {
        const size_t start = offsetof(struct statmount, str);
        const size_t offset = response->status.size - start;
        const size_t length = strlen(value) + 1;

        if (offset + length > sizeof(response->strings))
                abort();
        memcpy((char *)response + start + offset, value, length);
        response->status.size += (uint32_t)length;
        return (uint32_t)offset;
}

static struct view_mount_response fixture(bool zfs) {
        struct view_mount_response response = {0};

        response.status.size = offsetof(struct statmount, str);
        response.status.mask = STATMOUNT_SB_BASIC | STATMOUNT_MNT_BASIC |
                STATMOUNT_FS_TYPE | STATMOUNT_MNT_ROOT | STATMOUNT_MNT_POINT |
                (zfs ? STATMOUNT_SB_SOURCE : 0);
        response.status.mnt_id = 123;
        response.status.sb_dev_major = 0;
        response.status.sb_dev_minor = 42;
        response.status.sb_magic = zfs ? AOS_ZFS_SUPER_MAGIC : EXT4_SUPER_MAGIC;
        response.status.mnt_attr = MOUNT_ATTR_NOSUID | MOUNT_ATTR_NODEV;
        response.status.fs_type = append_string(&response, zfs ? "zfs" : "ext4");
        response.status.mnt_root = append_string(&response, "/");
        response.status.mnt_point = append_string(&response, zfs ? "/var/lib" : "/var");
        response.status.sb_source = append_string(&response, AOS_VIEW_ZFS_SOURCE);
        return response;
}

static void require_result(const char *name, const struct view_mount_response *response,
                            bool zfs, bool accepted) {
        const bool actual = validate_view_mount_response(response, 123, makedev(0, 42), zfs) == 0;

        if (actual != accepted) {
                fprintf(stderr, "view-roots-test: %s returned %s\n", name, actual ? "accepted" : "refused");
                exit(1);
        }
}

int main(void) {
        struct view_mount_response response;

        response = fixture(false);
        require_result("exact ext4", &response, false, true);
        response = fixture(true);
        require_result("exact declared ZFS dataset", &response, true, true);
        response.status.mnt_attr |= MOUNT_ATTR_NOATIME;
        require_result("declared ZFS noatime", &response, true, true);
        response = fixture(true);
        response.status.mnt_id++;
        require_result("changed mount ID", &response, true, false);
        response = fixture(true);
        response.status.sb_dev_minor++;
        require_result("changed filesystem device", &response, true, false);
        response = fixture(true);
        response.status.sb_source = append_string(&response, "otherpool/var/lib");
        require_result("substituted pool", &response, true, false);
        response = fixture(true);
        response.status.mnt_point = append_string(&response, "/var");
        require_result("wrong declared mountpoint", &response, true, false);
        response = fixture(true);
        response.status.mnt_root = append_string(&response, "/subtree");
        require_result("bind subtree", &response, true, false);
        response = fixture(true);
        response.status.mnt_attr |= MOUNT_ATTR_IDMAP;
        require_result("idmapped source", &response, true, false);
        response = fixture(true);
        response.status.mnt_attr |= MOUNT_ATTR_RDONLY;
        require_result("read-only writer source", &response, true, false);
        response = fixture(true);
        response.status.mask &= ~STATMOUNT_SB_SOURCE;
        require_result("missing source observation", &response, true, false);
        response = fixture(true);
        response.status.fs_type = response.status.size;
        require_result("out-of-bounds string", &response, true, false);
        response = fixture(true);
        response.status.size = sizeof(response) + 1;
        require_result("oversized kernel frame", &response, true, false);
        response = fixture(true);
        response.status.sb_magic = EXT4_SUPER_MAGIC;
        require_result("wrong filesystem magic", &response, true, false);
        puts("view-roots-test: 14 pure statmount cases passed");
        return 0;
}
