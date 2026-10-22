//! Pure-Rust, no-IO reader for the AOS registry wire surface (RFC-0004).
//!
//! Portable registry records and everything `apm` reads over dumb-HTTP, readable in-process and without
//! the git CLI — which is what lets the *same code* run on a native
//! server, a Cloudflare Worker, and a visitor's browser. This crate is the
//! extracted, dependency-light core of that reader: it does no I/O, pulls
//! in no async runtime, and compiles cleanly to `wasm32-unknown-unknown`,
//! so the registry web-surface SPA (`aos-registry-web`) reuses the exact
//! verifier the hub indexer and `apm` run. One parser — server, Worker,
//! browser — which also kills the parser-divergence bug class.
//!
//! # Module map
//!
//! - [`consumer`] - package records and registry source configuration.
//! - [`release`] - planned release coordinates shared by publication projects.
//! - [`tuf`] - signed catalog metadata envelopes and role policies.
//! - [`provenance`] - DSSE envelopes and shared pre-authentication framing.
//! - [`measurement`] - stable package attestation identity framing.
//! - [`platform`] - target platform normalization.
//! - [`channel`] - pure rollout selection, floors, frontiers, and partition tags.
//! - [`object`] — SHA-256 loose objects: inflate, hash-verify, and parse
//!   commits, trees, and tags.
//! - [`object_bundle`] — bounded OID-sharded loose-object transport bundles.
//! - [`pack_index`] — bounded SHA-256 pack-index structural and checksum
//!   validation.
//! - [`package_version`] — exact upstream package-version validation.
//! - [`publication`] - shared ordering for prepared publication pointers.
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
//! - [`store`] — signed realization-graph records carrying exact NAR identity
//!   and dependency edges for modern package metadata.
//!
//! The crate deliberately excludes the surface *transport* (the trait that
//! fetches loose objects over `file://`/HTTP, or `fetch()` in a browser)
//! and native tree-walking. Those live in `aos-registry-client`,
//! serving runtimes, or the
//! SPA's own fetch glue so the shared contracts stay portable.

pub mod channel;
pub mod keymap;
pub mod manifest;
pub mod native_dependencies;
pub mod object;
pub mod object_bundle;
pub mod pack_index;
pub mod package_version;
pub mod publication;
pub mod refs;
pub mod sshsig;
pub mod stack;
pub mod staging;
pub mod store;
pub mod support;
pub mod tag;
pub mod tagobject;

/// Portable registry consumer records and source configuration.
pub mod consumer;

/// Planned registry release coordinates.
pub mod release;

/// Signed registry catalog metadata schemas.
pub mod tuf;

/// Target platform names used in package manifests.
pub mod platform;

/// Stable package attestation measurement identities.
pub mod measurement;

/// DSSE provenance envelopes and shared pre-authentication framing.
pub mod provenance;
