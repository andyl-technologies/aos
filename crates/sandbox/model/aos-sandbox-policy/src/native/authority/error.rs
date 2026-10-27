//! Preserves the actual Root Authority failure and canonical input leaf.

use aos_sandbox_ledger_replay::data::SourceSuccessorDataErrorV2;

use crate::controller_readback::ControllerHoldReadbackDataErrorV1;
use crate::native::PolicyNativeJournalErrorV1;

/// Reports a refused native Root Authority operation without discarding custody.
///
/// Entered native originals and failed post destinations remain with their
/// owning operation. This error moves the actual typed cause; it does not
/// stand in for those originals or create a retry permission.
#[derive(Debug, thiserror::Error)]
pub enum RootAuthorityErrorV1 {
    /// A fixed field or complete role association is noncanonical.
    #[error("invalid Source genesis record or exact owner join")]
    NonCanonical,
    /// A project or retained operation has a different original association.
    #[error("Source genesis project or flight conflicts with retained state")]
    Conflict,
    /// The actual fixed writer or independent role original changed.
    #[error("Source genesis owner or credential is not current")]
    Stale,
    /// New admission is unavailable; historical validation remains separate.
    #[error("new Source genesis admission is unavailable")]
    AdmissionClosed,
    /// The actual ordinary opening retains its complete failed native prefix.
    #[error(transparent)]
    GenesisOpening(Box<super::genesis::RootGenesisOpeningFailureV1>),
    /// The actual strict ordinary mutation retains its entered native prefix.
    #[error(transparent)]
    GenesisMutation(super::genesis::RootStrictGenesisFailureV1),
    /// The genuine kernel clock observation failed at the actual native frontier.
    #[error(transparent)]
    Kernel(#[from] aos_linux_descriptors::Error),
    /// The canonical saved floor/Tree comparison refused the current Source cut.
    #[error(transparent)]
    SavedFloorData(#[from] aos_sandbox_ledger_replay::replay::root_saved_floor::RootSavedFloorComparisonDataErrorV1),
    /// The genuine fixed Root writer, replay or financial original refused.
    #[error(transparent)]
    Journal(#[from] PolicyNativeJournalErrorV1),
    /// The entered native currentness destination retains its actual failure.
    #[error(transparent)]
    Currentness(#[from] super::currentness::RootAuthorityCurrentFailureV1),
    /// The same genuine selected native Origin retained its actual refusal.
    #[error(transparent)]
    Origin(#[from] aos_sandbox_broker::receiving::RootQ04OriginErrorV1),
    /// The same actual native Origin is already mutably borrowed.
    #[error(transparent)]
    OriginBorrow(#[from] std::cell::BorrowMutError),
    /// The independently installed administrative original failed revalidation.
    #[error(transparent)]
    Credential(#[from] aos_sandbox_protocol::public_api_session_data::PublicApiSessionError),
    /// The original administrative seed failed its canonical verification.
    #[error(transparent)]
    Seed(#[from] aos_sandbox_protocol::controller_source_seed::ControllerSourceTreeSeedErrorV1),
    /// The canonical project administrative authorization failed decoding.
    #[error(transparent)]
    Authorization(
        #[from]
        aos_sandbox_protocol::source_project_authorization::ProjectAuthorizationSourceDataErrorV2,
    ),
    /// The separate pinned administrative signature failed verification.
    #[error(transparent)]
    AuthorizationSignature(
        #[from]
        aos_sandbox_protocol::publisher_project_authorization::ProjectAuthorizationSignatureErrorV2,
    ),
    /// The independently held Controller public credential is malformed.
    #[error(transparent)]
    Controller(#[from] ControllerHoldReadbackDataErrorV1),
    /// The original Controller genesis signature or signed association is invalid.
    #[error(transparent)]
    ControllerGenesis(#[from] aos_sandbox_ledger_replay::source_signer_data::SourceSignerGenesisDataErrorV1),
    /// The independently held Source public credential is malformed.
    #[error(transparent)]
    Source(#[from] aos_sandbox_ledger_replay::source_signer_data::SourceHoldReadbackErrorV1),
    /// A canonical Q04 packet or binding comparison refused the original cut.
    #[error(transparent)]
    Q04Data(#[from] crate::q04_data::PolicyQ04DataErrorV1),
    /// The independently pinned Controller project packet failed verification.
    #[error(transparent)]
    ControllerProject(#[from] crate::controller_project_readback::ControllerProjectAdmissionDataErrorV1),
    /// The independently pinned Cache observation packet failed verification.
    #[error(transparent)]
    CacheReadback(#[from] aos_sandbox_protocol::cache_owner_readback::CacheOwnerReadbackDataErrorV1),
    /// The actual fixed readonly Cache journals failed their original replay.
    #[error(transparent)]
    CacheNative(#[from] aos_sandbox_cache::CacheResidencyProtectedJournalErrorV1),
    /// The retained signed project or deployment input failed verification.
    #[error(transparent)]
    SignedInput(#[from] crate::signed_inputs::SignedPolicyInputDataErrorV1),
    /// The actual original authenticated stream or bounded native operation failed.
    #[error(transparent)]
    Transport(#[from] std::io::Error),
    /// The actual bounded receiving collection could not reserve its backing.
    #[error(transparent)]
    Allocation(#[from] std::collections::TryReserveError),
}

impl From<aos_sandbox_broker::canonical_journal::CanonicalJournalMechanicalErrorV1>
    for RootAuthorityErrorV1
{
    fn from(
        error: aos_sandbox_broker::canonical_journal::CanonicalJournalMechanicalErrorV1,
    ) -> Self {
        Self::Journal(PolicyNativeJournalErrorV1::Mechanical(error))
    }
}

impl From<SourceSuccessorDataErrorV2> for RootAuthorityErrorV1 {
    fn from(error: SourceSuccessorDataErrorV2) -> Self {
        match error {
            SourceSuccessorDataErrorV2::NonCanonical => Self::NonCanonical,
            SourceSuccessorDataErrorV2::Conflict => Self::Conflict,
            SourceSuccessorDataErrorV2::Seed(error) => Self::Seed(error),
            SourceSuccessorDataErrorV2::Authorization(error) => Self::Authorization(error),
            SourceSuccessorDataErrorV2::AuthorizationSignature(error) => {
                Self::AuthorizationSignature(error)
            }
        }
    }
}

impl From<aos_sandbox_protocol::source_genesis_acceptance::ControllerSourceGenesisAcceptanceDataErrorV1>
    for RootAuthorityErrorV1
{
    fn from(error: aos_sandbox_protocol::source_genesis_acceptance::ControllerSourceGenesisAcceptanceDataErrorV1) -> Self {
        SourceSuccessorDataErrorV2::from(error).into()
    }
}

impl From<aos_sandbox_protocol::policy_data::binding_v2::BindingDataErrorV1>
    for RootAuthorityErrorV1
{
    fn from(error: aos_sandbox_protocol::policy_data::binding_v2::BindingDataErrorV1) -> Self {
        match error {
            aos_sandbox_protocol::policy_data::binding_v2::BindingDataErrorV1::UnauthenticatedCandidate =>
                Self::Q04Data(crate::q04_data::PolicyQ04DataErrorV1::UnauthenticatedCandidate),
        }
    }
}

impl From<aos_sandbox_protocol::domain_ledger::create_q04_history::Q04HistoryDataErrorV1>
    for RootAuthorityErrorV1
{
    fn from(
        error: aos_sandbox_protocol::domain_ledger::create_q04_history::Q04HistoryDataErrorV1,
    ) -> Self {
        Self::Q04Data(crate::q04_data::PolicyQ04DataErrorV1::History(error))
    }
}

impl From<aos_sandbox_protocol::domain_ledger::JournalTransactionDataError>
    for RootAuthorityErrorV1
{
    fn from(error: aos_sandbox_protocol::domain_ledger::JournalTransactionDataError) -> Self {
        Self::Q04Data(crate::q04_data::PolicyQ04DataErrorV1::Transaction(error))
    }
}

impl From<aos_sandbox_protocol::domain_ledger::ProtectedHistoryDataErrorV1>
    for RootAuthorityErrorV1
{
    fn from(error: aos_sandbox_protocol::domain_ledger::ProtectedHistoryDataErrorV1) -> Self {
        Self::Q04Data(crate::q04_data::PolicyQ04DataErrorV1::ProtectedHistory(
            error,
        ))
    }
}

impl From<aos_sandbox_ledger_replay::genesis::SourceGenesisReceiptDataErrorV1>
    for RootAuthorityErrorV1
{
    fn from(error: aos_sandbox_ledger_replay::genesis::SourceGenesisReceiptDataErrorV1) -> Self {
        match error {
            aos_sandbox_ledger_replay::genesis::SourceGenesisReceiptDataErrorV1::NonCanonical => Self::NonCanonical,
        }
    }
}

impl From<crate::controller_successor_data::ControllerSuccessorReadbackDataErrorV1>
    for RootAuthorityErrorV1
{
    fn from(error: crate::controller_successor_data::ControllerSuccessorReadbackDataErrorV1) -> Self {
        use crate::controller_successor_data::ControllerSuccessorReadbackDataErrorV1 as Data;
        match error {
            Data::NonCanonical => Self::NonCanonical,
            Data::Conflict => Self::Conflict,
            Data::Stale => Self::Stale,
            Data::AdmissionClosed => Self::AdmissionClosed,
            Data::Source(cause) => Self::from(cause),
            Data::Mechanical(cause) => Self::from(cause),
        }
    }
}
