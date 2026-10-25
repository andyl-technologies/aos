//! Consumes the target build script's generated environment.

/// Preserves the build-script metadata received by target compilation.
pub const PROFILE: [&str; 5] = [
    env!("AOS_PROFILE_OPT_LEVEL"),
    env!("AOS_PROFILE_DEBUG"),
    env!("AOS_PROFILE_PROFILE"),
    env!("AOS_PROFILE_HOST"),
    env!("AOS_PROFILE_TARGET"),
];
