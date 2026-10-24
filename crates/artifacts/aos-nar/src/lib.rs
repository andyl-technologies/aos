//! NAR (Nix ARchive) formats and binary-cache metadata.
//!
//! A NAR is Nix's canonical, reproducible serialisation of a store path.
//! This crate provides reusable operations for moving NARs between
//! stores and caches:
//!
//! - [`info`] -- parse and render `.narinfo` metadata files and extract
//!   hash/basename components from store paths.
//! - [`cache`] -- static binary-cache layout: NAR URLs, narinfo
//!   rendering, Ed25519 narinfo signing, and `nix-cache-info` bodies.
//! - [`export`] -- the `nix-store --export` / `--import` stream format
//!   (NAR bytes followed by a path/references/deriver trailer).
//! - [`pack`] -- the AOS upload-pack container (`AOSP`) that bundles
//!   multiple NAR exports into a single integrity-checked blob.
//!
//! The optional `compression` feature adds the `verify` module for streaming
//! SHA-256 checks, bounded raw/zstd decoding, and authenticated regular-file
//! extraction. It does not add registry policy or Nix subprocess dependencies.

pub mod cache;
pub mod export;
pub mod info;
pub mod pack;

/// Verifies content and extracts authenticated regular-file archives.
#[cfg(feature = "compression")]
pub mod verify;
