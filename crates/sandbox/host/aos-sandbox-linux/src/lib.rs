//! Audited Linux descriptor boundary for the AOS sandbox runtime.
//!
//! The crate wraps pidfds, namespace descriptors, race-resistant `openat2`
//! resolution, the descriptor-based mount API, bounded fixed-process execution,
//! and mount-topology queries.
//! All retained kernel resources are represented by owned descriptor types.
//! Raw syscall invocation and vendored Linux 6.18 UAPI live in the private
//! `uapi` module, except for the narrowly scoped duplication boundary in
//! [`inherited_fd`]. Safe callers may duplicate an open inherited number into
//! new ownership, but cannot assume ownership of the original table entry.
//!
//! The modules divide responsibility as follows:
//!
//! - [`pidfd`] owns process-role observations and typed namespace descriptors;
//! - [`self_execution`] retains and revalidates the calling process's kernel identity;
//! - [`inherited_fd`] safely duplicates unowned process-start descriptors;
//! - [`fixed_spawn`] executes one absolute program with an exact inherited descriptor table;
//! - [`path`] resolves descendants beneath a pre-opened directory;
//! - [`cgroup`] checks exact and hinted descendant membership against retained cgroup-v2 anchors;
//! - [`credential`] retains bounded optional file-read DATA without role authority;
//! - [`process`] executes fixed absolute programs with bounded output and time;
//! - [`mount`] constructs, attributes, idmaps, and attaches detached mounts;
//! - [`inventory`] lists mounts and reads stable mount metadata;
//! - [`immutable_file`] pins descriptors and maps seal-proven immutable files;
//! - [`netlink`] resolves descriptor-backed peer Network namespace IDs; and
//! - [`seqpacket`] exchanges bounded records with kernel-pinned peer identity;
//! - [`selinux_policy`] compares the enforcing kernel policy with an exact immutable package;
//! - [`startup_fd_table`] exclusively claims and double-observes the initial descriptor table; and
//! - [`unix_stream`] owns strict stream subject and EOF receives.
//!
//! Generic process pins, endpoint correlation, kernel boot identity and sealed
//! credentials are owned directly by `aos-linux-descriptors`; callers use that
//! canonical crate without an old-path compatibility export.

#![cfg(target_os = "linux")]

pub mod cgroup;
pub mod credential;
pub mod guest_startup_report;
pub mod fixed_spawn;
pub mod fuse_mount;
pub mod fuse_worker_image;
pub mod fuse_worker_objects;
pub mod fuse_worker_startup;
pub mod guest_cgroup;
pub mod guest_confinement;
pub mod immutable_file;
pub mod inherited_fd;
pub mod inventory;
pub mod kernel_clone;
pub mod mount;
pub mod netlink;
pub mod no_setid;
pub mod path;
pub mod pidfd;
pub mod process;
pub mod protected_file;
pub mod selinux_policy;
pub mod self_execution;
pub mod seqpacket;
pub mod signer_mount;
pub mod startup_fd_table;
mod uapi;
pub mod unix_stream;

use aos_linux_descriptors::{Error, Result};
