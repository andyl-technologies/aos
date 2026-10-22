//! Exercises a source-built procedural macro on the execution platform.

use proc_macro::TokenStream;

/// Preserves the expression supplied by the consumer.
#[proc_macro]
pub fn identity(input: TokenStream) -> TokenStream {
    input
}
