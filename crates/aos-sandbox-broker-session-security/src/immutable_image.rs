//! Reuses nonauthorizing immutable measurement for the existing local owners.

pub(crate) use aos_sandbox::immutable_image::{
    ImmutableImageErrorV1, RetainedImmutableFileV1, require_readonly_launch_flags,
};
