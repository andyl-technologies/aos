//! Package-owned boot finalizer for A/B image rollout transitions.

fn main() -> anyhow::Result<()> {
    aos_package::sysroot::run_image_rollout_boot_commit()
}
