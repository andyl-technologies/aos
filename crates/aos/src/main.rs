//! `aos` — the command-line tool for working with the AOS repository.
//!
//! This binary is a *multicall* executable: behaviour depends on the name
//! it is invoked as (`argv[0]`, normalised by `aos_core::invocation`):
//!
//! - `aos` — the full CLI, dispatching on the first argument.
//! - `apm` — alias for `aos package ...` (the package manager).
//! - `apr` — alias for `aos package registry ...` (registry operations).
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
//! - **Package management**: `package` / `apm` / `apr` (implemented in
//!   `aos-package`).
//! - **Misc**: `completions` (shell completion scripts).
//!
//! # Exit codes
//!
//! `0` success; `1` build/test failure (and unknown errors); `2` user
//! error; `3` Nix not found — see `handle_error` and
//! `aos_core::error::AosError::exit_code`.

mod cli;
mod commands;
mod entry;
mod logging;

/// Process entry point: installs the panic hook, applies the multicall
/// `argv[0]` rewrite (`apm`/`apr`), parses the CLI, runs the selected
/// command, and exits with the mapped exit code.
#[tokio::main]
async fn main() {
    entry::main().await;
}
