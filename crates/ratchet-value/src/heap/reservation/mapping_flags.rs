//! Platform-specific flags for the Candidate-C anonymous mapping.

#[cfg(any(target_os = "android", target_os = "linux"))]
pub(super) const MAP_ANONYMOUS_FLAG: libc::c_int = libc::MAP_ANONYMOUS;

// Candidate C reserves an offset domain, not 4 GiB of committed memory. Linux
// otherwise charges the entire writable mapping against strict overcommit and
// cgroup commit limits even though only the two bump lanes are faulted in.
#[cfg(any(target_os = "android", target_os = "linux"))]
pub(super) const MAP_NORESERVE_FLAG: libc::c_int = libc::MAP_NORESERVE;

#[cfg(not(any(target_os = "android", target_os = "linux")))]
pub(super) const MAP_ANONYMOUS_FLAG: libc::c_int = libc::MAP_ANON;

#[cfg(not(any(target_os = "android", target_os = "linux")))]
pub(super) const MAP_NORESERVE_FLAG: libc::c_int = 0;
