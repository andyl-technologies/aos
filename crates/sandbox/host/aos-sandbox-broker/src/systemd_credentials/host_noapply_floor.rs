//! Retains Host's fixed Root no-Apply public pin and eight native readbacks.
//!
//! This closed leaf uses the existing credential ancestry, read and held/named
//! comparison engines. It creates no Source, signer, floor or effect authority.

use super::*;
use aos_sandbox_model::{ResourceDimension as D, ResourceVector};
use aos_sandbox_protocol::host_execution_no_apply::root_attestation::ROOT_NO_APPLY_PUBLIC_PIN_BYTES_V2;

const NAMES: [&str; 1] = ["root-noapply-floor-public"];
const MAXIMUM_BYTES: [u64; 1] = [ROOT_NO_APPLY_PUBLIC_PIN_BYTES_V2 as u64];
const POSTS: usize = 8;

/// Reports a closed pin while the original native cause remains resident.
#[derive(Clone, Copy, Debug, thiserror::Error)]
#[error("Host Root no-Apply public credential remains closed")]
pub struct HostNoApplyRootPublicCredentialClosedV2;

#[derive(Clone, Copy)]
enum First {
    Capture,
    InitialPost,
    Post(usize),
    Order,
}

/// Holds the fixed Host public pin through the four settlement turns.
///
/// The actual initial19 owner prepays its complete recipe before constructing
/// or entering this original. Whole positive duplicate readback scratch retires
/// after comparison; the original five descriptors and all failed prefixes stay
/// held. No retirement refunds the original financial debit.
#[must_use]
pub struct HostNoApplyRootPublicCredentialOriginalV2 {
    originals: [OriginalControllerCredential; 1],
    ancestors: CredentialAncestors,
    initial_readback: CredentialReadback<1>,
    readbacks: [CredentialReadback<1>; POSTS],
    capture: Option<CredentialResult<()>>,
    initial_post: Option<CredentialResult<()>>,
    results: [Option<CredentialResult<()>>; POSTS],
    entered: bool,
    next: usize,
    owed: Option<usize>,
    first: Option<First>,
}

impl HostNoApplyRootPublicCredentialOriginalV2 {
    /// Creates inert fixed destinations without allocation or native IO.
    #[must_use]
    pub fn new() -> Self {
        Self {
            originals: [OriginalControllerCredential {
                public: None,
                read: CredentialReadSlot::new(),
            }],
            ancestors: CredentialAncestors::new(),
            initial_readback: CredentialReadback::new(),
            readbacks: std::array::from_fn(|_| CredentialReadback::new()),
            capture: None,
            initial_post: None,
            results: std::array::from_fn(|_| None),
            entered: false,
            next: 0,
            owed: None,
            first: None,
        }
    }

    /// Prices capture and the actual eight finite held/named readbacks.
    ///
    /// Each prefix retains four fixed directories and one file. Positive
    /// duplicates retire before another primary; a failed before still owes
    /// its separate after. Thus at most three five-descriptor prefixes coexist.
    /// All19 complete bounded file reads remain charged, including retired
    /// positive scratch. Arithmetic failure supplies no admission.
    #[must_use]
    pub fn receiving_demand_v2() -> Option<ResourceVector> {
        let namespace = 5_u64;
        let files = namespace.checked_mul(3)?;
        let read_bound = MAXIMUM_BYTES[0].checked_add(1)?;
        let buffers = read_bound.checked_mul(4)?.checked_mul(5)?;
        let traffic = read_bound.checked_mul(4)?.checked_mul(19)?;
        let path = FixedCredentialDirectoryV1::HostNoApplyRoot.path();
        let memory = u64::try_from(std::mem::size_of::<Self>())
            .ok()?
            .checked_mul(2)?
            .checked_add(buffers)?
            .checked_add(files.checked_mul(4096)?)?
            .checked_add(u64::try_from(path.as_os_str().len()).ok()?.checked_mul(2)?)?
            .checked_add(
                u64::try_from(std::mem::size_of::<Sha256>())
                    .ok()?
                    .checked_mul(2)?,
            )?;
        Some(
            ResourceVector::ZERO
                .with(D::MemoryBytes, memory)
                .with(D::OpenFiles, files)
                .with(D::MetadataEntries, namespace)
                .with(D::OutputBytes, traffic),
        )
    }

    /// Captures exactly the fixed protected80-byte public input and named post.
    ///
    /// # Errors
    /// Retains unsafe ancestry, owner/mode/link/extent/read failure, changed
    /// original/name, a non-root caller or repeated capture. The independent
    /// named post runs after every entered capture outcome.
    pub fn capture_once_v2(&mut self) -> Result<(), HostNoApplyRootPublicCredentialClosedV2> {
        if self.entered {
            self.first.get_or_insert(First::Order);
            return Err(HostNoApplyRootPublicCredentialClosedV2);
        }
        self.entered = true;
        self.capture = Some((|| {
            if rustix::process::geteuid().as_raw() != 0 {
                return Err(credential_state_rejected());
            }
            capture_fixed_credential_originals(
                FixedCredentialDirectoryV1::HostNoApplyRoot,
                0,
                &NAMES,
                &MAXIMUM_BYTES,
                &mut self.originals,
                &mut self.ancestors,
            )?;
            let public = self.originals[0]
                .public
                .as_ref()
                .ok_or_else(credential_state_rejected)?;
            if public.bytes().len() != ROOT_NO_APPLY_PUBLIC_PIN_BYTES_V2
                || public.file_identity.2 != 0
                || public.file_identity.3 != 0
                || public.file_identity.4 & 0o7777 != 0o400
            {
                return Err(credential_state_rejected());
            }
            Ok(())
        })());
        if !matches!(self.capture, Some(Ok(()))) {
            self.first.get_or_insert(First::Capture);
        }
        self.initial_post = Some(observe_fixed_credential_readback(
            FixedCredentialDirectoryV1::HostNoApplyRoot,
            0,
            &NAMES,
            &MAXIMUM_BYTES,
            &mut self.originals,
            &self.ancestors,
            &mut self.initial_readback,
        ));
        if matches!(self.initial_post, Some(Ok(()))) {
            self.initial_readback = CredentialReadback::new();
        } else {
            self.first.get_or_insert(First::InitialPost);
        }
        self.require_positive()
    }

    /// Compares the fixed pin before preliminary42 and arms its owed after.
    ///
    /// # Errors
    /// Retains native refusal; rejects a failed original or wrong turn order.
    pub fn preliminary_before_once_v2(
        &mut self,
    ) -> Result<(), HostNoApplyRootPublicCredentialClosedV2> {
        self.before_once(0)
    }

    /// Runs preliminary42's prepaid after despite its primary or before failure.
    ///
    /// # Errors
    /// Retains changed native custody, earlier failure or missing/repeated debt.
    pub fn preliminary_after_once_v2(
        &mut self,
    ) -> Result<(), HostNoApplyRootPublicCredentialClosedV2> {
        self.after_once(1)
    }

    /// Compares the fixed pin before nonce43 and arms its owed after.
    ///
    /// # Errors
    /// Retains native refusal; rejects a failed original or wrong turn order.
    pub fn nonce_before_once_v2(&mut self) -> Result<(), HostNoApplyRootPublicCredentialClosedV2> {
        self.before_once(2)
    }

    /// Runs nonce43's prepaid after despite its primary or before failure.
    ///
    /// # Errors
    /// Retains changed native custody, earlier failure or missing/repeated debt.
    pub fn nonce_after_once_v2(&mut self) -> Result<(), HostNoApplyRootPublicCredentialClosedV2> {
        self.after_once(3)
    }

    /// Compares the fixed pin before floor-seal42 and arms its owed after.
    ///
    /// # Errors
    /// Retains native refusal; rejects a failed original or wrong turn order.
    pub fn floor_before_once_v2(&mut self) -> Result<(), HostNoApplyRootPublicCredentialClosedV2> {
        self.before_once(4)
    }

    /// Runs floor-seal42's prepaid after despite its primary or before failure.
    ///
    /// # Errors
    /// Retains changed native custody, earlier failure or missing/repeated debt.
    pub fn floor_after_once_v2(&mut self) -> Result<(), HostNoApplyRootPublicCredentialClosedV2> {
        self.after_once(5)
    }

    /// Compares the fixed pin before ACK42 and arms its owed after.
    ///
    /// # Errors
    /// Retains native refusal; rejects a failed original or wrong turn order.
    pub fn ack_before_once_v2(&mut self) -> Result<(), HostNoApplyRootPublicCredentialClosedV2> {
        self.before_once(6)
    }

    /// Runs ACK42's prepaid after despite its primary or before failure.
    ///
    /// # Errors
    /// Retains changed native custody, earlier failure or missing/repeated debt.
    pub fn ack_after_once_v2(&mut self) -> Result<(), HostNoApplyRootPublicCredentialClosedV2> {
        self.after_once(7)
    }

    fn before_once(&mut self, index: usize) -> Result<(), HostNoApplyRootPublicCredentialClosedV2> {
        if self.first.is_some() || !self.entered || self.next != index || self.owed.is_some() {
            self.first.get_or_insert(First::Order);
            return Err(HostNoApplyRootPublicCredentialClosedV2);
        }
        self.owed = Some(index + 1);
        self.observe_post(index)
    }

    fn after_once(&mut self, index: usize) -> Result<(), HostNoApplyRootPublicCredentialClosedV2> {
        if !self.entered || self.next != index || self.owed != Some(index) {
            self.first.get_or_insert(First::Order);
            return Err(HostNoApplyRootPublicCredentialClosedV2);
        }
        self.owed = None;
        self.observe_post(index)
    }

    fn observe_post(
        &mut self,
        index: usize,
    ) -> Result<(), HostNoApplyRootPublicCredentialClosedV2> {
        self.next += 1;
        self.results[index] = Some(observe_fixed_credential_readback(
            FixedCredentialDirectoryV1::HostNoApplyRoot,
            0,
            &NAMES,
            &MAXIMUM_BYTES,
            &mut self.originals,
            &self.ancestors,
            &mut self.readbacks[index],
        ));
        if matches!(self.results[index], Some(Ok(()))) {
            // Only exclusive scratch retires after the complete native join.
            // The same original ancestry/file and every spent debit remain.
            self.readbacks[index] = CredentialReadback::new();
        } else {
            self.first.get_or_insert(First::Post(index));
        }
        self.require_positive()
    }

    fn require_positive(&self) -> Result<(), HostNoApplyRootPublicCredentialClosedV2> {
        if self.first.is_none()
            && matches!(self.capture, Some(Ok(())))
            && matches!(self.initial_post, Some(Ok(())))
        {
            Ok(())
        } else {
            Err(HostNoApplyRootPublicCredentialClosedV2)
        }
    }

    #[cfg(test)]
    pub(super) fn fixture_owed_after_entered_v2(&self) -> bool {
        self.results[1].is_some()
    }

    /// Borrows exact public envelope DATA only from the healthy held original.
    #[must_use]
    pub fn bytes_v2(&self) -> Option<&[u8]> {
        self.require_positive().ok()?;
        Some(self.originals[0].public.as_ref()?.bytes())
    }

    /// Borrows the first actual native refusal without replacing its custody.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        let cause = match self.first? {
            First::Capture => self.capture.as_ref()?.as_ref().err(),
            First::InitialPost => self.initial_post.as_ref()?.as_ref().err(),
            First::Post(index) => self.results[index].as_ref()?.as_ref().err(),
            First::Order => None,
        };
        cause
            .map(|cause| cause as _)
            .or(Some(&HostNoApplyRootPublicCredentialClosedV2))
    }
}

impl Default for HostNoApplyRootPublicCredentialOriginalV2 {
    fn default() -> Self {
        Self::new()
    }
}
