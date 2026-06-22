//! Image and closure profiler for AOS production artifacts.
//!
//! AOS builds its bootable images — the UKI (kernel + initrd), the
//! rootfs, and the system toplevel — from Nix runtime closures. Nix's
//! reference scanner is deliberately conservative: *any* 32-character
//! store hash that appears as a string anywhere in an output's files
//! becomes a runtime reference, whether it is a real `DT_NEEDED` shared
//! library, an RPATH pointing at a build-only tool, a path baked into a
//! `pkg-config` file, or a comment left behind in a wrapper script. The
//! result is closure bloat: build- and dev-time artifacts that ride
//! into the production image as runtime dependencies but are never
//! loaded at runtime.
//!
//! This crate finds that bloat and, crucially, explains *why* each
//! suspect path is present so a fix (a `nuke-references` entry, a strip,
//! an output split) can be made with confidence.
//!
//! # Module map
//!
//! - [`target`] — resolve a profiling target (store path or Nix
//!   attribute) to a realised store path.
//! - [`closure`] — enumerate a runtime closure, build its reference
//!   graph, compute each path's *exclusive* (dominator-tree) size, and
//!   flag known build-tool suspects.
//! - [`scan`] — walk a store path's files and locate every embedded
//!   reference to another path, classifying *where* the reference lives
//!   (an ELF `.interp`, an RPATH, a `.comment` section, a shebang, a
//!   `.pc` file, …). Owns the hand-rolled ELF reader.
//! - [`verdict`] — fold a set of reference sites into a [`Verdict`]:
//!   load-bearing at runtime, a dev-output leak, or spurious.
//! - [`report`] — render closure and reference reports as human tables
//!   or JSON.
//!
//! # The two views
//!
//! A closure (what Nix *thinks* is a runtime dependency) and an image
//! (the bytes actually shipped) are not the same set — the initrd in
//! particular is built from a curated package list, not the full
//! toplevel closure. This crate currently implements the **closure
//! view**, which works against any installable: `pkgs.<name>`,
//! `system.config.system.build.toplevel`, an initrd derivation, or a
//! bare store path. The physical image view (PE section sizing,
//! `cpio.gz` decomposition) is layered on top of the same scanner.

pub mod closure;
pub mod report;
pub mod scan;
pub mod target;
pub mod verdict;

pub use closure::{ClosureGraph, Suspect};
pub use scan::{RefLocus, RefSite};
pub use target::{Target, resolve};
pub use verdict::Verdict;
