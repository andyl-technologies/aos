//! Package-owned qualification-observer entry point for A/B image rollout effects.

fn main() -> anyhow::Result<()> {
    aos_package_manager::sysroot::run_image_rollout_observer()
}
