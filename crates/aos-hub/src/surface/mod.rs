//! Pure-Rust reader for the AOS registry wire surface.
//!
//! Everything `apm` reads over dumb-HTTP, readable in-process and without
//! the git CLI — which is what lets the same code run on a native server,
//! a Cloudflare Worker, and (now) a visitor's browser. The dependency-light,
//! no-IO core lives in the standalone [`aos_registry_surface`] crate so it
//! compiles to `wasm32-unknown-unknown` and the registry web-surface SPA
//! (`aos-registry-spa`) can reuse the *exact* verifier the hub indexer runs:
//!
//! - [`object`] — SHA-256 loose objects: inflate, hash-verify, and parse
//!   commits, trees, and tags.
//! - [`sshsig`] — OpenSSH SSHSIG signature parsing and Ed25519
//!   verification (the format `git -c gpg.format=ssh` produces).
//! - [`tag`] — signed tag payloads: channel partitions and release tags,
//!   with name binding.
//! - [`refs`] — `info/refs` and `HEAD` parsing.
//!
//! Those four modules are re-exported from [`aos_registry_surface`]; only
//! [`load`] stays here, because tree-walking depends on the hub's
//! [`crate::fetch::SurfaceFetch`] transport and `aos-package`'s
//! committed-file parsers, neither of which belongs in the pure core.
//!
//! Format parsers are shared with `aos-package` wherever they exist there
//! (tag headers, package TOML, `keys.toml`, `registry.toml`), so this
//! reader and `apm` cannot silently diverge on committed formats. The
//! parts implemented in the surface crate — loose objects, SSHSIG, refs —
//! are the parts `apm` delegates to the git CLI.

pub mod load;

pub use aos_registry_surface::{object, refs, sshsig, tag};
