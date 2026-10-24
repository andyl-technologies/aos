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

static void test_storage_custody_metadata(void) {
        const dev_t device = makedev(8, 2);
        const struct stat valid = {
                .st_mode = S_IFREG | 0400,
                .st_uid = 0,
                .st_gid = 0,
                .st_nlink = 1,
                .st_size = 0,
                .st_dev = device,
        };
        struct stat rejected[] = {valid, valid, valid, valid, valid, valid, valid, valid};

        rejected[0].st_mode = S_IFLNK | 0400;
        rejected[1].st_mode = S_IFREG | 0600;
        rejected[2].st_mode = S_IFREG | 0440;
        rejected[3].st_uid = 811;
        rejected[4].st_gid = 811;
        rejected[5].st_nlink = 2;
        rejected[6].st_size = 32;
        rejected[7].st_dev = makedev(8, 3);

        if (!empty_custody_target_metadata(&valid, device)) {
                fputs("view-roots-test: exact empty custody target refused\n", stderr);
                exit(1);
        }
        for (size_t index = 0; index < sizeof(rejected) / sizeof(rejected[0]); ++index) {
                if (empty_custody_target_metadata(&rejected[index], device)) {
                        fprintf(stderr, "view-roots-test: unsafe custody metadata case %zu accepted\n", index);
                        exit(1);
                }
        }
}

int main(void) {
        struct view_mount_response response;

        test_storage_custody_metadata();

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
