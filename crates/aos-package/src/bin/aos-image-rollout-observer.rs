//! Package-owned qualification-observer entry point for A/B image rollout effects.

fn main() -> anyhow::Result<()> {
    aos_package::sysroot::run_image_rollout_observer()
}
