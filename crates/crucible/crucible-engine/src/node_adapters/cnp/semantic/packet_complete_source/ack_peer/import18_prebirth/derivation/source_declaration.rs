//! Lends the accepted pre-report bank while retaining its genuine Birth guard.
//!
//! The worker's original completion owns the unchanged SourceBirth6..12 bytes.
//! Its trusted installed algorithm supplies their derivation. The parent never
//! parses that response or SourceBirth bank. Native retains its independent
//! full semantic checks.
//! Every serialization authenticates the original Source, launch, completion,
//! private executable and both Birth banks before and after the actual writer.

use super::*;
use crucible_node_transport::reference_packet::service::complete_restore::import18::{
    PacketNativeImport18SourceDeclarationView, native_import18_source_declaration_bank_view_data,
    native_import18_source_declaration_counter_scratch_data,
};
use serde::{Serialize, Serializer, ser::Error};
use std::{cell::Ref, mem::size_of};

#[path = "source_declaration/encoding.rs"]
mod encoding;

#[path = "source_declaration/initial_projection.rs"]
mod initial_projection;

#[path = "source_declaration/initial_funding.rs"]
mod initial_funding;

#[path = "source_declaration/launch_identity.rs"]
mod launch_identity;

#[path = "source_declaration/mapping_nonce.rs"]
mod mapping_nonce;

#[path = "source_declaration/mapping_custody.rs"]
mod mapping_custody;

const UNAVAILABLE: &str = "original import18 declaration unavailable";
const CHANGED: &str = "original import18 declaration changed";

struct OriginalSourceDeclarationLoan<'a> {
    source: &'a PacketCompleteSemanticSource,
    birth: Ref<'a, birth::OriginalAckPeerBirth>,
    declaration: PacketNativeImport18SourceDeclarationView<'a>,
}

impl OriginalSourceDeclarationLoan<'_> {
    fn authenticate(&self) -> Result<(), RuntimeError> {
        let (source, registration) = self.source.native_import18_derived_banks_data()?;
        let state = self
            .source
            .native_import18_derivation
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        let original = state
            .original_launch
            .as_ref()
            .ok_or(RuntimeError::ForeignAuthority)?;
        self.source
            .authenticate_import18_birth_source_data(original.original())?;
        self.birth.authenticate_isolated_declaration_banks_data(
            state
                .private_launch
                .as_ref()
                .ok_or(RuntimeError::OwnerUnavailable)?,
            &original.original().controller_executable,
            source,
            registration,
        )
    }
}

impl Serialize for OriginalSourceDeclarationLoan<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.authenticate()
            .map_err(|_| S::Error::custom(UNAVAILABLE))?;
        let serialized = self.declaration.serialize(serializer);
        // Always measure the terminal original, including a failed write. The
        // first serializer failure stays first; neither result releases custody.
        let current = self.authenticate().map_err(|_| S::Error::custom(CHANGED));
        match serialized {
            Err(error) => Err(error),
            Ok(output) => current.map(|()| output),
        }
    }
}

impl PacketCompleteSemanticSource {
    /// Lends unchanged pre-report bytes from the original accepted worker result.
    ///
    /// The opaque serializer retains a shared loan of the actual private Birth.
    /// It authenticates complete original launch/completion/executable custody
    /// before and after serialization. It creates no DOM or byte copy. Callers
    /// admit its fixed construction row before entry and independently fund the
    /// actual formatter, serializer, error and output owners before writing.
    /// This loan creates no Initial, Recipe, native startup or readiness grant.
    ///
    /// # Errors
    /// Refuses absent, foreign, failed, cancelled, started or finalized custody,
    /// changed original banks or executable, and a conflicting Birth loan.
    pub fn native_import18_source_declaration_data(
        &self,
    ) -> Result<impl Serialize + '_, RuntimeError> {
        self.original_source_declaration_loan()
    }

    fn original_source_declaration_loan(
        &self,
    ) -> Result<OriginalSourceDeclarationLoan<'_>, RuntimeError> {
        let (source, _) = self.native_import18_derived_banks_data()?;
        let state = self
            .native_import18_derivation
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        let original = state
            .original_launch
            .as_ref()
            .ok_or(RuntimeError::ForeignAuthority)?;
        let slot = self
            .ack_peer_birth
            .try_borrow()
            .map_err(|_| RuntimeError::OutstandingObligations)?;
        let birth =
            Ref::filter_map(slot, Option::as_ref).map_err(|_| RuntimeError::OwnerUnavailable)?;
        let declaration =
            native_import18_source_declaration_bank_view_data(source, original.original())
                .map_err(|_| RuntimeError::InvalidReceipt)?;
        let loan = OriginalSourceDeclarationLoan {
            source: self,
            birth,
            declaration,
        };
        loan.authenticate()?;
        Ok(loan)
    }

    /// Names this allocation-free loan's actual construction and guard work.
    ///
    /// The original Source, completion and Birth retain their existing backing.
    /// Actual serialization has separate formatter/output/error rows and the
    /// same guard workspace, which callers must keep admitted while writing.
    pub fn native_import18_source_declaration_construction_data() -> [usize; 3] {
        let transient = size_of::<OriginalSourceDeclarationLoan<'static>>()
            // Concrete helper return and the public opaque forwarding result.
            + size_of::<Result<OriginalSourceDeclarationLoan<'static>, RuntimeError>>() * 2;
        let scratch = Self::isolated_derivation_counter_scratch_data()
            + birth::OriginalAckPeerBirth::isolated_declaration_counter_scratch_data()
            + native_import18_source_declaration_counter_scratch_data()
            + size_of::<&Self>()
            + size_of::<&OriginalSourceDeclarationLoan<'static>>()
            + size_of::<&NativeImport18DerivationState>()
            + size_of::<&OriginalSourceBirthLaunch>()
            + size_of::<Ref<'static, Option<birth::OriginalAckPeerBirth>>>()
            + size_of::<Ref<'static, birth::OriginalAckPeerBirth>>()
            + size_of::<
                Result<Ref<'static, Option<birth::OriginalAckPeerBirth>>, std::cell::BorrowError>,
            >()
            + size_of::<
                Result<
                    Ref<'static, birth::OriginalAckPeerBirth>,
                    Ref<'static, Option<birth::OriginalAckPeerBirth>>,
                >,
            >()
            + size_of::<(&[u8], &[u8])>()
            + size_of::<Result<(&[u8], &[u8]), RuntimeError>>()
            + size_of::<Result<(), RuntimeError>>();
        [0, transient, scratch]
    }
}
