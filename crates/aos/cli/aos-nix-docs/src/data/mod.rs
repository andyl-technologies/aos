//! Compiled-in reference documentation.
//!
//! Unlike the rest of the index, which is extracted from the source tree at
//! runtime, the content here is static `&'static` data baked into the
//! binary: [`builtins`] documents the Nix builtin functions and [`language`]
//! holds the Nix language reference chapters shown on the TUI's Language
//! tab. Both are folded into the [`crate::model::DocIndex`] by
//! [`crate::extract::build_index`].

pub mod builtins;
pub mod language;
