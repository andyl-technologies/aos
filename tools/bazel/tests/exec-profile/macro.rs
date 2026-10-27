//! Exposes the procedural macro's execution compiler setting as a boolean.

use proc_macro::TokenStream;

/// Expands to whether debug assertions were enabled when compiling this macro.
#[proc_macro]
pub fn execution_debug_assertions(_: TokenStream) -> TokenStream {
    let value = proc_macro::Ident::new(
        if cfg!(debug_assertions) {
            "true"
        } else {
            "false"
        },
        proc_macro::Span::call_site(),
    );
    TokenStream::from(proc_macro::TokenTree::Ident(value))
}
