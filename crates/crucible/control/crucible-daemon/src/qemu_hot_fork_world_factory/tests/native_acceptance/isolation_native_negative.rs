//! Genuine accepted native rejection of missing or aliased child VMState files.

use super::*;

#[test]
#[ignore = "requires the packaged patched QEMU, cgroup v2, and project quotas"]
fn production_factory_rejects_missing_child_file_with_live_qemu_source() {
    run_atomic_world_case(crate::packaged_qemu_executor::NativeAtomicWorldCase::Missing);
}

#[test]
#[ignore = "requires the packaged patched QEMU, cgroup v2, and project quotas"]
fn production_factory_rejects_aliased_child_files_with_live_qemu_source() {
    run_atomic_world_case(crate::packaged_qemu_executor::NativeAtomicWorldCase::Aliased);
}
