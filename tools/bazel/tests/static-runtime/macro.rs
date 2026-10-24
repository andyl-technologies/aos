//! Verifies that guest target flags never reach execution-platform macros.

use proc_macro::TokenStream;

#[cfg(target_feature = "crt-static")]
compile_error!("execution-platform procedural macros must remain dynamically linked");

/// Preserves the supplied expression on the execution platform.
#[proc_macro]
pub fn identity(input: TokenStream) -> TokenStream {
    input
}
