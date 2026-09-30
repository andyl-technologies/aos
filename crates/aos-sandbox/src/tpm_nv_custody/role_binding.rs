//! Canonical service-owner binding DATA for the new failed-Create role pins.
//!
//! ```text
//! SHA256(domain || version:u16be=1 || role:u8 || node16 || epoch16 ||
//!        purpose-length:u16be || fixed-purpose || unit-length:u16be || fixed-unit)
//! ```
//!
//! This binding identifies the separately provisioned service role, not a target
//! RuntimeScope assignment. It contains no pin bytes, genesis or future head.
//! Computing it neither proves PID1 delivery nor constructs signing authority.

use sha2::{Digest as _, Sha256};

use super::NvCustodyErrorV1;

const DOMAIN: &[u8] = b"aos.sandbox.create-failure.service-owner-binding.v1\0";
const PURPOSE: &[u8] = b"root-policy-failed-create-floor-v1";

/// Selects only one fixed failed-Create service-owner DATA role.
#[doc(hidden)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CreateFailureServiceRoleV1 {
    /// Identifies the existing Controller service.
    Controller,
    /// Identifies the existing Host service.
    Host,
    /// Identifies the existing Root policy-authority service.
    Root,
}

impl CreateFailureServiceRoleV1 {
    fn code(self) -> u8 {
        match self {
            Self::Controller => 1,
            Self::Host => 2,
            Self::Root => 3,
        }
    }

    fn unit(self) -> &'static [u8] {
        match self {
            Self::Controller => b"aos-sandboxd.service",
            Self::Host => b"aos-sandbox-hostd.service",
            Self::Root => b"aos-sandbox-policy-authorityd.service",
        }
    }
}

/// Computes the fixed service-role binding without accepting an assignment.
///
/// # Errors
///
/// Rejects zero node or deployment epoch, or an unencodable fixed string length.
/// The result remains DATA and does not prove the current service or target.
#[doc(hidden)]
pub fn canonical_create_failure_service_binding_v1(
    role: CreateFailureServiceRoleV1,
    node: [u8; 16],
    deployment_epoch: [u8; 16],
) -> Result<[u8; 32], NvCustodyErrorV1> {
    if node == [0; 16] || deployment_epoch == [0; 16] {
        return Err(NvCustodyErrorV1::Encoding);
    }
    let unit = role.unit();
    let purpose_length = u16::try_from(PURPOSE.len()).map_err(|_| NvCustodyErrorV1::Encoding)?;
    let unit_length = u16::try_from(unit.len()).map_err(|_| NvCustodyErrorV1::Encoding)?;

    Ok(Sha256::new()
        .chain_update(DOMAIN)
        .chain_update(1_u16.to_be_bytes())
        .chain_update([role.code()])
        .chain_update(node)
        .chain_update(deployment_epoch)
        .chain_update(purpose_length.to_be_bytes())
        .chain_update(PURPOSE)
        .chain_update(unit_length.to_be_bytes())
        .chain_update(unit)
        .finalize()
        .into())
}

#[cfg(test)]
mod tests;
