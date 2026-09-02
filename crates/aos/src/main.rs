//! `aos` is the command-line tool for AOS repository and system-development
//! workflows.
//!
//! # Subcommand families
//!
//! The clap definitions live in `cli` and the implementations in
//! `commands`, one module per subcommand:
//!
//! - **Nix workflows** (need a `NixRunner`): `build`, `system`, `show`,
//!   `graph`, `lint`, `test`, `repl`, `gc`, `why-depends`, `describe`,
//!   `prefetch`, `fmt`, and `doc` (implemented in the `aos-doc` crate).
//! - **Server-side**: `serve` (the HTTP binary cache server, implemented
//!   in `aos-server`) and `token` (provisioning-token management over the
//!   server's bootstrap socket).
//! - **Client-side**: `cache` (binary cache push/pull/prefetch/list,
//!   implemented in `aos-cache`) and the `--remote` modes of `build` and
//!   `gc` (via `aos-remote`).
//! - **Misc**: `completions` (shell completion scripts).
//!
//! # Exit codes
//!
//! `0` success; `1` build/test failure (and unknown errors); `2` user
//! error; `3` Nix not found — see `handle_error` and
//! `aos_core::error::AosError::exit_code`.

/// Runs the `aos` CLI.
#[tokio::main]
async fn main() {
    aos::entry::aos_main().await;
}
