//! Fixed owner/helper SID observation for required-mode physical TPM custody.
//!
//! These checks do not authenticate a compiled policy or freeze PID 1 policy.
//! They refuse an init-domain alias, permissive kernel, or substituted procfs
//! observation before credentials cross the private carrier. Installed policy,
//! original launch identity and service crash quiescence remain separate gates.

use std::fs::File;
use std::io::Read as _;

use rustix::fs::{Mode, OFlags, fstatfs, open};

use super::super::FloorErrorV1;
use super::super::format::FloorEndpointV1;

const SELINUXFS_MAGIC: u64 = 0xf97c_ff8c;
const PROCFS_MAGIC: u64 = 0x9fa0;

pub(in crate::recovery::journal::tpm_floor) const fn owner_context(
    endpoint: FloorEndpointV1,
) -> &'static str {
    match endpoint {
        FloorEndpointV1::ControllerStorageClient => "system_u:system_r:aos_sandbox_controller_t",
        FloorEndpointV1::StorageBroker => "system_u:system_r:aos_sandbox_storage_t",
    }
}

pub(super) const fn helper_context(endpoint: FloorEndpointV1) -> &'static str {
    match endpoint {
        FloorEndpointV1::ControllerStorageClient => {
            "system_u:system_r:aos_method46_controller_helper_t"
        }
        FloorEndpointV1::StorageBroker => "system_u:system_r:aos_method46_storage_helper_t",
    }
}

pub(crate) fn require_owner(
    endpoint: FloorEndpointV1,
) -> Result<(), FloorErrorV1> {
    let enforcement = read_bounded("/sys/fs/selinux/enforce", SELINUXFS_MAGIC, 2)?;
    if enforcement != b"1" && enforcement != b"1\n" {
        return Err(FloorErrorV1::Provisioning);
    }
    require_context("/proc/self/attr/current", owner_context(endpoint))
}

pub(crate) fn require_helper(endpoint: FloorEndpointV1, pid: u32) -> Result<(), FloorErrorV1> {
    require_helper_preamble(endpoint, pid)?;
    require_context(
        &format!("/proc/{pid}/attr/current"),
        helper_context(endpoint),
    )
}

pub(super) fn require_helper_preamble(endpoint: FloorEndpointV1, pid: u32) -> Result<(), FloorErrorV1> {
    require_owner(endpoint)?;
    if pid == 0 || pid == std::process::id() {
        return Err(FloorErrorV1::Provisioning);
    }
    Ok(())
}

pub(super) fn require_observed_helper_context(
    endpoint: FloorEndpointV1,
    bytes: &[u8],
) -> Result<(), FloorErrorV1> {
    if bytes.len() > 256 || !context_matches(bytes, helper_context(endpoint).as_bytes()) {
        return Err(FloorErrorV1::Provisioning);
    }
    Ok(())
}

fn require_context(path: &str, expected: &str) -> Result<(), FloorErrorV1> {
    let observed = read_bounded(path, PROCFS_MAGIC, 256)?;
    if !context_matches(&observed, expected.as_bytes()) {
        return Err(FloorErrorV1::Provisioning);
    }
    Ok(())
}

fn context_matches(observed: &[u8], expected: &[u8]) -> bool {
    let observed = observed
        .strip_suffix(b"\n")
        .or_else(|| observed.strip_suffix(b"\0"))
        .unwrap_or(observed);
    !expected.is_empty() && observed == expected
}

fn read_bounded(path: &str, magic: u64, maximum: u64) -> Result<Vec<u8>, FloorErrorV1> {
    let descriptor = open(
        path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|_| FloorErrorV1::Unavailable)?;
    if fstatfs(&descriptor)
        .map_err(|_| FloorErrorV1::Unavailable)?
        .f_type as u64
        != magic
    {
        return Err(FloorErrorV1::Provisioning);
    }
    let mut bytes = Vec::new();
    File::from(descriptor)
        .take(maximum + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| FloorErrorV1::Unavailable)?;
    if bytes.len() as u64 > maximum {
        return Err(FloorErrorV1::Provisioning);
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tpm_floor_confinement_context_is_exact_and_role_separated() {
        for endpoint in [
            FloorEndpointV1::ControllerStorageClient,
            FloorEndpointV1::StorageBroker,
        ] {
            let expected = owner_context(endpoint).as_bytes();
            assert!(context_matches(expected, expected));
            assert!(context_matches(&[expected, b"\n"].concat(), expected));
            for invalid in [
                b"system_u:system_r:init_t".as_slice(),
                helper_context(endpoint).as_bytes(),
                b"",
                b"\0",
                b"system_u:system_r:aos_sandbox_controller_t:s0",
            ] {
                assert!(!context_matches(invalid, expected));
            }
            assert!(!context_matches(&[expected, b"\0\n"].concat(), expected));
        }
        assert_ne!(
            owner_context(FloorEndpointV1::ControllerStorageClient),
            owner_context(FloorEndpointV1::StorageBroker)
        );
    }

    #[test]
    fn retained_helper_context_uses_the_same_exact_matcher_and_bound() {
        for endpoint in [FloorEndpointV1::ControllerStorageClient, FloorEndpointV1::StorageBroker] {
            let expected = helper_context(endpoint).as_bytes();
            for observed in [expected.to_vec(), [expected, b"\n"].concat(), [expected, b"\0"].concat()] {
                assert!(require_observed_helper_context(endpoint, &observed).is_ok());
            }
            for observed in [Vec::new(), vec![b'x'; 257], [expected, b"\0\n"].concat()] {
                assert_eq!(
                    require_observed_helper_context(endpoint, &observed),
                    Err(FloorErrorV1::Provisioning),
                );
            }
            assert!(require_observed_helper_context(endpoint, owner_context(endpoint).as_bytes()).is_err());
        }
    }
}
