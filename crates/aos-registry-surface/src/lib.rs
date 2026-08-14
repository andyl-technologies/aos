//! Pure-Rust, no-IO reader for the AOS registry wire surface (RFC-0004).
//!
//! Everything `apm` reads over dumb-HTTP, readable in-process and without
//! the git CLI — which is what lets the *same code* run on a native
//! server, a Cloudflare Worker, and a visitor's browser. This crate is the
//! extracted, dependency-light core of that reader: it does no I/O, pulls
//! in no async runtime, and compiles cleanly to `wasm32-unknown-unknown`,
//! so the registry web-surface SPA (`aos-registry-spa`) reuses the exact
//! verifier the hub indexer and `apm` run. One parser — server, Worker,
//! browser — which also kills the parser-divergence bug class.
//!
//! # Module map
//!
//! - [`object`] — SHA-256 loose objects: inflate, hash-verify, and parse
//!   commits, trees, and tags.
//! - [`keymap`] — machine paths, mutability, and HTTP response metadata shared
//!   by producers and serving runtimes.
//! - [`sshsig`] — OpenSSH SSHSIG signature parsing and Ed25519
//!   verification (the format `git -c gpg.format=ssh` produces).
//! - [`tagobject`] — the pure header parser for git tag objects plus the
//!   name-binding check, shared with `apm` so the two readers cannot drift
//!   on the format.
//! - [`tag`] — signed tag payloads: channel partitions and release tags,
//!   with name binding, built on [`tagobject`] and [`sshsig`].
//! - [`refs`] — `info/refs` and `HEAD` parsing.
//! - [`stack`] — the committed `[caches]` cache-stack node model
//!   ([`StackNode`](stack::StackNode)): the nestable try/mirror expression
//!   flattened into the priority list consumers resolve.
//!
//! The crate deliberately excludes the surface *transport* (the trait that
//! fetches loose objects over `file://`/HTTP, or `fetch()` in a browser)
//! and tree-walking that depends on `aos-package`'s committed-file parsers;
//! those live in the consumer (`aos-hub`'s `surface::load`, or the
//! SPA's own fetch glue) so this core stays pure.

pub mod keymap;
pub mod manifest;
pub mod object;
pub mod refs;
pub mod sshsig;
pub mod stack;
pub mod tag;
pub mod tagobject;
