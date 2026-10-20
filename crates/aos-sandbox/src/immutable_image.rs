//! Forwards the shared immutable DATA engine for existing Domain purposes.
//!
//! Role-specific Git selections remain here. All measurements, partial native
//! destinations and retained currentness use the single lower Broker engine;
//! none of these DATA APIs issue a selected role or protected execution grant.

pub use aos_sandbox_broker::immutable_image::{
    ImmutableFileRevalidationOriginalV1, ImmutableImageErrorV1, RetainedImmutableFileV1,
    decode_immutable_sha256_pin_v1, read_immutable_image_pin_v1,
    require_readonly_launch_flags, retain_original_backend_pid1_v1,
};
pub(crate) use aos_sandbox_broker::immutable_image::PendingImmutableFileV1;

#[cfg(all(target_os = "linux", feature = "git-helper-mechanics"))]
pub(crate) mod git_helper;
