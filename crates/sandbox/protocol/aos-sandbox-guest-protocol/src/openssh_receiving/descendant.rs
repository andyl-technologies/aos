//! Shares the request-bound DATA codec for the funded SSH descendant recipe.
//!
//! ```text
//! AOSSSH01 | runtime[32] | AgentSession[32] | execution[16] | request[32]
//!          | memory:u64 | processes:u32 | perProcessNoFile:u32
//!          | sourceCopiedFiles:u32 | sourceHighestFd:u32
//! ```
//!
//! All integers are big endian. The actual Host financial owner must debit the
//! full source before issuing this DATA through its authenticated request. The
//! Guest's existing authorized Process owner separately owns and limits the
//! native subtree; decoding this record cannot adopt a process or pay a debt.

use aos_sandbox_model::{ResourceDimension as D, ResourceVector};
use sha2::{Digest as _, Sha256};

use crate::{AgentExecutionOperationV1, AgentOperationRequestV1, AgentRuntimeBindingV1};

/// Gives the complete fixed version-one descendant-plan width.
pub const OPENSSH_DESCENDANT_PLAN_BYTES_V1: usize = 144;

/// Bounds the complete native SSH subtree, including its listener daemon.
///
/// The kernel pids limit applies to every fork/exec/helper, including failed
/// authentication and relay paths. Four is the explicit financed recipe,
/// not a claim that an untested nofile/memory allowance supports every flow.
pub const OPENSSH_DESCENDANT_PROCESS_CEILING_V1: u32 = 4;

const MAGIC: &[u8; 8] = b"AOSSSH01";

/// Rejects noncanonical, foreign or unrepresentable descendant-plan DATA.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum OpenSshDescendantPlanDataErrorV1 {
    /// The exact version, width, nonzero coordinates or fixed recipe differ.
    #[error("SSH descendant plan DATA is not canonical")]
    Invalid,
    /// The original runtime/session/execution/specification do not match.
    #[error("SSH descendant plan DATA belongs to another original request")]
    Binding,
    /// The finite quote cannot represent the complete native source envelope.
    #[error("SSH descendant plan DATA exceeds its finite quote")]
    Quote,
}

/// Binds finite mechanical native limits to one actual Authorize request.
///
/// This is passive, copyable DATA. It carries no financial, execution, signal,
/// cgroup or listener permission. A pure quote is only a solver input; the
/// actual same financial owner must reserve the complete source independently.
/// The existing complete request commitment covers its operation/sequence,
/// backend binding, canonical specification, admission, principal and audit;
/// equal execution/specification alone cannot retarget this plan.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OpenSshDescendantPlanDataV1 {
    runtime: [u8; 32],
    session: [u8; 32],
    execution: [u8; 16],
    request_commitment: [u8; 32],
    memory: u64,
    per_process_nofile: u32,
    source_copied_files: u32,
    source_highest_fd: u32,
}

impl OpenSshDescendantPlanDataV1 {
    /// Derives a finite DATA plan from the actual request and remaining quote.
    ///
    /// Native-control/header/resident costs must already be excluded from
    /// these quote inputs. Nofile is the largest whole per-process amount
    /// within the quote for the fixed four-process subtree. It is not copied
    /// from an inherited hard limit and establishes no successful-flow claim.
    ///
    /// # Errors
    /// Rejects non-Authorize input, zero memory, an unrepresentable per-process
    /// width, or fewer than the three actual standard descriptor entries.
    pub fn derive_quote_data_v1(
        runtime: &AgentRuntimeBindingV1,
        request: &AgentOperationRequestV1,
        memory_quote: u64,
        descriptor_quote: u64,
        source_copied_files: u32,
        source_highest_fd: u32,
    ) -> Result<Self, OpenSshDescendantPlanDataErrorV1> {
        let (execution, request_commitment) = request_coordinates(request)?;
        let per_process_nofile =
            u32::try_from(descriptor_quote / u64::from(OPENSSH_DESCENDANT_PROCESS_CEILING_V1))
                .map_err(|_| OpenSshDescendantPlanDataErrorV1::Quote)?;
        if memory_quote == 0 || per_process_nofile < 3
            || source_copied_files == 0 || source_highest_fd < 2
        {
            return Err(OpenSshDescendantPlanDataErrorV1::Quote);
        }
        Ok(Self {
            runtime: guest_runtime_identity_data_v1(runtime),
            session: *request.session().digest().as_bytes(),
            execution,
            request_commitment,
            memory: memory_quote,
            per_process_nofile,
            source_copied_files,
            source_highest_fd,
        })
    }

    /// Encodes the sole fixed portable DATA representation without allocation.
    #[must_use]
    pub fn encode_data_v1(&self) -> [u8; OPENSSH_DESCENDANT_PLAN_BYTES_V1] {
        let mut bytes = [0; OPENSSH_DESCENDANT_PLAN_BYTES_V1];
        bytes[..8].copy_from_slice(MAGIC);
        bytes[8..40].copy_from_slice(&self.runtime);
        bytes[40..72].copy_from_slice(&self.session);
        bytes[72..88].copy_from_slice(&self.execution);
        bytes[88..120].copy_from_slice(&self.request_commitment);
        bytes[120..128].copy_from_slice(&self.memory.to_be_bytes());
        bytes[128..132].copy_from_slice(&OPENSSH_DESCENDANT_PROCESS_CEILING_V1.to_be_bytes());
        bytes[132..136].copy_from_slice(&self.per_process_nofile.to_be_bytes());
        bytes[136..140].copy_from_slice(&self.source_copied_files.to_be_bytes());
        bytes[140..144].copy_from_slice(&self.source_highest_fd.to_be_bytes());
        bytes
    }

    /// Decodes exact DATA while granting no resource or native permission.
    ///
    /// # Errors
    /// Rejects unknown versions, extra/missing bytes, sentinel coordinates or
    /// caps, a different process recipe or fewer than three descriptor entries.
    pub fn decode_data_v1(bytes: &[u8]) -> Result<Self, OpenSshDescendantPlanDataErrorV1> {
        use OpenSshDescendantPlanDataErrorV1::Invalid;
        if bytes.len() != OPENSSH_DESCENDANT_PLAN_BYTES_V1 || &bytes[..8] != MAGIC {
            return Err(Invalid);
        }
        let plan = Self {
            runtime: bytes[8..40].try_into().map_err(|_| Invalid)?,
            session: bytes[40..72].try_into().map_err(|_| Invalid)?,
            execution: bytes[72..88].try_into().map_err(|_| Invalid)?,
            request_commitment: bytes[88..120].try_into().map_err(|_| Invalid)?,
            memory: u64::from_be_bytes(bytes[120..128].try_into().map_err(|_| Invalid)?),
            per_process_nofile: u32::from_be_bytes(
                bytes[132..136].try_into().map_err(|_| Invalid)?,
            ),
            source_copied_files: u32::from_be_bytes(bytes[136..140].try_into().map_err(|_| Invalid)?),
            source_highest_fd: u32::from_be_bytes(bytes[140..144].try_into().map_err(|_| Invalid)?),
        };
        if bytes[128..132] != OPENSSH_DESCENDANT_PROCESS_CEILING_V1.to_be_bytes()
            || plan.runtime == [0; 32]
            || plan.session == [0; 32]
            || plan.execution == [0; 16]
            || plan.request_commitment == [0; 32]
            || plan.memory == 0
            || plan.per_process_nofile < 3
            || plan.source_copied_files == 0
            || plan.source_highest_fd < 2
        {
            return Err(Invalid);
        }
        Ok(plan)
    }

    /// Compares DATA against the actual runtime and fully reconstructed request.
    ///
    /// # Errors
    /// Rejects non-Authorize input or different runtime/session/execution/spec.
    pub fn require_request_data_v1(
        &self,
        runtime: &AgentRuntimeBindingV1,
        request: &AgentOperationRequestV1,
    ) -> Result<(), OpenSshDescendantPlanDataErrorV1> {
        let (execution, request_commitment) = request_coordinates(request)?;
        if self.runtime != guest_runtime_identity_data_v1(runtime)
            || self.session != *request.session().digest().as_bytes()
            || self.execution != execution
            || self.request_commitment != request_commitment
        {
            return Err(OpenSshDescendantPlanDataErrorV1::Binding);
        }
        Ok(())
    }

    /// Returns the finite SSH-subtree memory ceiling as cost/limit DATA.
    #[must_use]
    pub const fn memory_bytes_data_v1(&self) -> u64 {
        self.memory
    }

    /// Returns the fixed whole-subtree process ceiling as cost/limit DATA.
    #[must_use]
    pub const fn processes_data_v1(&self) -> u32 {
        OPENSSH_DESCENDANT_PROCESS_CEILING_V1
    }

    /// Returns the financed per-process native nofile ceiling as DATA.
    #[must_use]
    pub const fn per_process_nofile_data_v1(&self) -> u32 {
        self.per_process_nofile
    }

    /// Returns the prepaid maximum copied positions, including the loader alias.
    ///
    /// The real Agent's all-open observation and finite concurrent growth must
    /// fit this bound before libc. The field cannot itself reserve a source.
    #[must_use]
    pub const fn source_copied_files_data_v1(&self) -> u32 { self.source_copied_files }

    /// Returns the prepaid maximum inclusive parent FD number before birth.
    ///
    /// This includes CLOEXEC/high-numbered entries and concurrent growth. It is
    /// independent of the child's enforced nofile value and grants no FD access.
    #[must_use]
    pub const fn source_highest_fd_data_v1(&self) -> u32 { self.source_highest_fd }

    /// Returns the complete native budget, excluding enclosing/control costs.
    ///
    /// This amount includes the daemon itself. Its single already-counted PID
    /// must join once when the genuine caller assembles the whole source. It
    /// conveys no reservation, capacity, currentness or native permission.
    #[must_use]
    pub fn native_budget_demand_data_v1(&self) -> ResourceVector {
        ResourceVector::ZERO
            .with(D::MemoryBytes, self.memory)
            .with(D::Pids, u64::from(OPENSSH_DESCENDANT_PROCESS_CEILING_V1))
            .with(
                D::OpenFiles,
                u64::from(OPENSSH_DESCENDANT_PROCESS_CEILING_V1)
                    * u64::from(self.per_process_nofile),
            )
    }
}

fn request_coordinates(
    request: &AgentOperationRequestV1,
) -> Result<([u8; 16], [u8; 32]), OpenSshDescendantPlanDataErrorV1> {
    match request.operation() {
        AgentExecutionOperationV1::Authorize { execution, .. } => Ok((
            *execution.as_bytes(),
            *request.request_commitment().as_bytes(),
        )),
        _ => Err(OpenSshDescendantPlanDataErrorV1::Binding),
    }
}

/// Computes the existing Guest ledger runtime identity through its sole codec.
///
/// This comparison-only digest grants no execution or financial authority.
#[must_use]
pub fn guest_runtime_identity_data_v1(runtime: &AgentRuntimeBindingV1) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"aos-sandbox-guest-effect-runtime-v1\0");
    digest.update(runtime.sandbox().as_bytes());
    digest.update(runtime.incarnation().as_bytes());
    digest.update(runtime.assignment_epoch().get().to_be_bytes());
    digest.update(runtime.assignment_digest().as_bytes());
    digest.update(runtime.desired_generation().get().to_be_bytes());
    digest.update(runtime.namespace_generation().get().to_be_bytes());
    digest.update(runtime.payload_boot_id());
    digest.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plan() -> OpenSshDescendantPlanDataV1 {
        OpenSshDescendantPlanDataV1 {
            runtime: [1; 32],
            session: [2; 32],
            execution: [3; 16],
            request_commitment: [4; 32],
            memory: 5_000_000,
            per_process_nofile: 23,
            source_copied_files: 96,
            source_highest_fd: 160,
        }
    }

    #[test]
    fn exact_wire_and_complete_native_budget_use_the_same_caps() {
        let original = plan();
        let bytes = original.encode_data_v1();

        let decoded = OpenSshDescendantPlanDataV1::decode_data_v1(&bytes).unwrap();

        assert_eq!(bytes.len(), 144);
        assert_eq!(&bytes[..8], b"AOSSSH01");
        assert_eq!(decoded, original);
        assert_eq!(
            decoded.native_budget_demand_data_v1(),
            ResourceVector::ZERO
                .with(D::MemoryBytes, 5_000_000)
                .with(D::Pids, 4)
                .with(D::OpenFiles, 92)
        );
    }

    #[test]
    fn unknown_versions_widths_coordinates_and_native_recipes_stay_closed() {
        let bytes = plan().encode_data_v1();
        for offset in [8..40, 40..72, 72..88, 88..120, 120..128, 128..132, 132..136,
            136..140, 140..144] {
            let mut malformed = bytes;
            malformed[offset].fill(0);
            assert_eq!(
                OpenSshDescendantPlanDataV1::decode_data_v1(&malformed),
                Err(OpenSshDescendantPlanDataErrorV1::Invalid)
            );
        }
        let mut version = bytes;
        version[7] = b'2';
        assert!(OpenSshDescendantPlanDataV1::decode_data_v1(&version).is_err());
        assert!(OpenSshDescendantPlanDataV1::decode_data_v1(&bytes[..136]).is_err());
        let mut extended = bytes.to_vec();
        extended.push(0);
        assert!(OpenSshDescendantPlanDataV1::decode_data_v1(&extended).is_err());
    }
}
