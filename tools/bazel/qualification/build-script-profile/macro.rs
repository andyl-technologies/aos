//! Consumes the execution configuration's build-script metadata.

extern crate proc_macro;

const PROFILE: [&str; 5] = [
    env!("AOS_PROFILE_OPT_LEVEL"),
    env!("AOS_PROFILE_DEBUG"),
    env!("AOS_PROFILE_PROFILE"),
    env!("AOS_PROFILE_HOST"),
    env!("AOS_PROFILE_TARGET"),
];

/// Retains a dependency on the execution-side generated environment.
#[proc_macro]
pub fn profile(tokens: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let _ = PROFILE;
    tokens
}
