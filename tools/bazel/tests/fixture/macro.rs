//! Exercises a source-built procedural macro on the execution platform.

use proc_macro::TokenStream;

#[cfg(not(target_os = "linux"))]
compile_error!("the fixture procedural macro must compile for the Linux execution platform");

/// Preserves the expression supplied by the consumer.
#[proc_macro]
pub fn identity(input: TokenStream) -> TokenStream {
    input
}
