//! Pure-Rust reader for the AOS registry wire surface.
//!
//! Everything `apm` reads over dumb-HTTP, readable in-process and without
//! the git CLI — which is what lets the same code run on a native server,
//! a Cloudflare Worker, and (eventually) in a visitor's browser:
//!
//! - [`object`] — SHA-256 loose objects: inflate, hash-verify, and parse
//!   commits, trees, and tags.
//! - [`sshsig`] — OpenSSH SSHSIG signature parsing and Ed25519
//!   verification (the format `git -c gpg.format=ssh` produces).
//! - [`tag`] — signed tag payloads: channel partitions and release tags,
//!   with name binding.
//! - [`refs`] — `info/refs` and `HEAD` parsing.
//! - [`load`] — walking a verified commit's tree into the committed
//!   registry files (`registry.toml`, `keys.toml`, packages, closures).
//!
//! Format parsers are shared with `aos-package` wherever they exist there
//! (tag headers, package TOML, `keys.toml`, `registry.toml`), so this
//! reader and `apm` cannot silently diverge on committed formats. The
//! parts implemented here — loose objects, SSHSIG, refs — are the parts
//! `apm` delegates to the git CLI.

pub mod load;
pub mod object;
pub mod refs;
pub mod sshsig;
pub mod tag;
