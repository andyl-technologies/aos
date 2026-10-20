//! Owns the installed Publisher execution transport and native session custody.
//!
//! [`publisher_sessions`] retains the exact accepted socket, pidfd, cgroup,
//! record-subject observations and fixed process-local reservations. Controller
//! administration keeps its actual protected journal, policy and commit gates.
//! The `aos-view-publisher` executable holds its registered networkless channel;
//! it sends no publication request and creates no publication effect authority.

#[cfg(target_os = "linux")]
pub mod publisher_sessions;
