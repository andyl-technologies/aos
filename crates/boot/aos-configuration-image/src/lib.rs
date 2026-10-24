//! Owns native OS configuration lower images and their verified boot mounting.
//!
//! [`model`] describes the typed file inputs and immutable result. [`render`]
//! assembles files without following destination symlinks. [`lower`] publishes
//! deterministic EROFS images with durable receipts and checks them on reuse.
//! Immutable SELinux images supply their selected file contexts; generated
//! lowers retain that exact labeling input and use it in their content identity.
//! [`boot`] reads one explicitly bound, committed package-generation result and
//! mounts its verified image. Package journals remain the authority for commit.

#![forbid(unsafe_code)]

pub mod boot;
pub mod lower;
pub mod model;
pub mod mount;
mod render;
mod selinux;

pub use render::certificate_bundle;
