//! Native Source-genesis owner failures and shared internal field helpers.
//!
//! Canonical immutable acceptance DATA lives in Protocol. This module preserves
//! the native Source/Root error classes at the actual owner boundaries; parsing
//! DATA alone cannot retain a writer, authenticate current heads, or append.

use aos_sandbox_protocol::source_genesis_wire as genesis_wire;

use aos_sandbox_protocol::domain_ledger::JournalTransactionDataError;

use aos_sandbox_protocol::source_project_authorization::ProjectAuthorizationSourceDataErrorV2;
use aos_sandbox_protocol::source_genesis_acceptance::ControllerSourceGenesisAcceptanceDataErrorV1;


use aos_sandbox_protocol::controller_source_seed::ControllerSourceTreeSeedErrorV1;
use crate::journal::JournalError;
use crate::publisher_admin::policy::{ProjectAuthorizationSourceErrorV2, PublisherPolicyError};

/// Reports a refused or incomplete held Source-genesis flight.
#[derive(Debug, thiserror::Error)]
pub enum SourceGenesisErrorV1 {
    /// A record, packet, sentinel, or exact graph join is invalid.
    #[error("invalid Source genesis record or exact owner join")]
    NonCanonical,
    /// A project or pending flight already belongs to a different exact input.
    #[error("Source genesis project or flight conflicts with retained state")]
    Conflict,
    /// The independently configured role or fixed owner custody changed.
    #[error("Source genesis owner or credential is not current")]
    Stale,
    /// Positive genesis admission is unavailable; historical recovery is separate.
    #[error("new Source genesis admission is unavailable")]
    AdmissionClosed,
    /// Protected journal replay, capacity, append, or readback failed.
    #[error(transparent)]
    Journal(#[from] JournalError),
    /// A genuine lower Root Authority retains its new native failure category.
    #[cfg(target_os = "linux")]
    #[error(transparent)]
    NativeAuthority(aos_sandbox_policy::native::RootAuthorityErrorV1),
    /// Canonical hierarchy replay or member construction failed.
    #[error(transparent)]
    Hierarchy(#[from] super::protected_journal::HierarchyProtectedJournalErrorV1),
    /// Publisher ownership or canonical current-state validation failed.
    #[error(transparent)]
    Publisher(#[from] PublisherPolicyError),
    /// The independently pinned administrative seed failed verification.
    #[error(transparent)]
    Seed(#[from] ControllerSourceTreeSeedErrorV1),
    /// The separate project administrative authorization failed verification.
    #[error(transparent)]
    Authorization(#[from] ProjectAuthorizationSourceErrorV2),
    /// The original authenticated Root flight failed or was lost.
    #[error(transparent)]
    Transport(#[from] std::io::Error),
    /// A genuine kernel peer, cgroup, boot, or descriptor observation failed.
    #[cfg(target_os = "linux")]
    #[error(transparent)]
    Kernel(#[from] aos_linux_descriptors::Error),
    /// A stream fragment violated its strict kernel-subject profile.
    #[cfg(target_os = "linux")]
    #[error(transparent)]
    Subject(#[from] aos_sandbox_linux::seqpacket::SeqpacketError),
}

impl From<aos_sandbox_broker::controller_receiving::profile::root_flight::ControllerRootFlightErrorV1>
    for SourceGenesisErrorV1
{
    fn from(error: aos_sandbox_broker::controller_receiving::profile::root_flight::ControllerRootFlightErrorV1) -> Self {
        use aos_sandbox_broker::controller_receiving::profile::root_flight::ControllerRootFlightErrorV1;
        match error {
            ControllerRootFlightErrorV1::Stale => Self::Stale,
            ControllerRootFlightErrorV1::Transport(error) => Self::Transport(error),
            ControllerRootFlightErrorV1::Kernel(error) => Self::Kernel(error),
            ControllerRootFlightErrorV1::Subject(error) => Self::Subject(error),
        }
    }
}

impl From<JournalTransactionDataError> for SourceGenesisErrorV1 {
    fn from(error: JournalTransactionDataError) -> Self {
        <Self as From<JournalError>>::from(JournalError::from(error))
    }
}

impl From<ProjectAuthorizationSourceDataErrorV2> for SourceGenesisErrorV1 {
    fn from(error: ProjectAuthorizationSourceDataErrorV2) -> Self {
        // Pure decoding retains the original administrative-role error class.
        Self::Authorization(error.into())
    }
}

pub(crate) use aos_sandbox_ledger_replay::data::{digest_at, hash};

pub(crate) fn take<const N: usize>(bytes: &[u8], offset: usize) -> Result<[u8; N], SourceGenesisErrorV1> {
    aos_sandbox_ledger_replay::data::take(bytes, offset).map_err(SourceGenesisErrorV1::from)
}

impl From<aos_sandbox_ledger_replay::data::SourceSuccessorDataErrorV2> for SourceGenesisErrorV1 {
    fn from(error: aos_sandbox_ledger_replay::data::SourceSuccessorDataErrorV2) -> Self {
        use aos_sandbox_ledger_replay::data::SourceSuccessorDataErrorV2;

        match error {
            SourceSuccessorDataErrorV2::NonCanonical => Self::NonCanonical,
            SourceSuccessorDataErrorV2::Conflict => Self::Conflict,
            SourceSuccessorDataErrorV2::Seed(error) => Self::Seed(error),
            SourceSuccessorDataErrorV2::Authorization(error) => Self::Authorization(error.into()),
            SourceSuccessorDataErrorV2::AuthorizationSignature(error) => Self::Authorization(error.into()),
        }
    }
}

impl From<aos_sandbox_ledger_replay::genesis::SourceGenesisReceiptDataErrorV1> for SourceGenesisErrorV1 {
    fn from(error: aos_sandbox_ledger_replay::genesis::SourceGenesisReceiptDataErrorV1) -> Self {
        match error {
            aos_sandbox_ledger_replay::genesis::SourceGenesisReceiptDataErrorV1::NonCanonical => Self::NonCanonical,
        }
    }
}

impl From<ControllerSourceGenesisAcceptanceDataErrorV1> for SourceGenesisErrorV1 {
    fn from(error: ControllerSourceGenesisAcceptanceDataErrorV1) -> Self {
        match error {
            ControllerSourceGenesisAcceptanceDataErrorV1::NonCanonical => Self::NonCanonical,
            ControllerSourceGenesisAcceptanceDataErrorV1::Seed(error) => Self::Seed(error),
            ControllerSourceGenesisAcceptanceDataErrorV1::Authorization(error) => {
                Self::Authorization(error.into())
            }
        }
    }
}

impl From<crate::publisher_admin::policy::PublisherProjectGenesisErrorV1> for SourceGenesisErrorV1 {
    fn from(error: crate::publisher_admin::policy::PublisherProjectGenesisErrorV1) -> Self {
        use crate::publisher_admin::policy::PublisherProjectGenesisErrorV1;

        match error {
            PublisherProjectGenesisErrorV1::NonCanonical => Self::NonCanonical,
            PublisherProjectGenesisErrorV1::Stale => Self::Stale,
            PublisherProjectGenesisErrorV1::Publisher(error) => Self::Publisher(error),
            PublisherProjectGenesisErrorV1::Seed(error) => Self::Seed(error),
            PublisherProjectGenesisErrorV1::Authorization(error) => Self::Authorization(error),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::publisher_admin::policy::PublisherProjectGenesisErrorV1;

    #[test]
    fn publisher_historical_native_error_keeps_the_actual_inner_cause() {
        let native = std::io::Error::other(std::io::Error::from_raw_os_error(9));
        let original = native.get_ref().unwrap() as *const _;
        let publisher = PublisherPolicyError::Journal(JournalError::Io(native));
        let projected = SourceGenesisErrorV1::from(
            PublisherProjectGenesisErrorV1::from(publisher),
        );

        let SourceGenesisErrorV1::Publisher(PublisherPolicyError::Journal(
            JournalError::Io(actual),
        )) = projected else {
            panic!("Publisher historical error changed its native Source category");
        };
        assert!(std::ptr::eq(original, actual.get_ref().unwrap() as *const _));
        assert_eq!(
            actual.get_ref().unwrap().downcast_ref::<std::io::Error>().unwrap().raw_os_error(),
            Some(9),
        );
    }

    #[test]
    fn source_data_boundary_preserves_the_existing_native_error_categories() {
        use aos_sandbox_ledger_replay::data::SourceSuccessorDataErrorV2;

        let malformed = SourceGenesisErrorV1::from(SourceSuccessorDataErrorV2::NonCanonical);
        let authorization = SourceGenesisErrorV1::from(SourceSuccessorDataErrorV2::Authorization(
            ProjectAuthorizationSourceDataErrorV2::NonCanonical,
        ));

        assert!(matches!(malformed, SourceGenesisErrorV1::NonCanonical));
        assert!(matches!(authorization, SourceGenesisErrorV1::Authorization(
            ProjectAuthorizationSourceErrorV2::NonCanonical,
        )));
    }

    #[test]
    fn source_owned_receipt_failure_keeps_native_noncanonical_classification() {
        let data = aos_sandbox_ledger_replay::genesis::SourceTreeGenesisReceiptV1::decode(&[])
            .unwrap_err();
        let native = SourceGenesisErrorV1::from(data);

        assert!(matches!(native, SourceGenesisErrorV1::NonCanonical));
    }

    #[test]
    fn publisher_local_refusals_preserve_native_source_categories() {
        let stale = SourceGenesisErrorV1::from(PublisherProjectGenesisErrorV1::Stale);
        let malformed = SourceGenesisErrorV1::from(
            PublisherProjectGenesisErrorV1::from(
                ProjectAuthorizationSourceDataErrorV2::NonCanonical,
            ),
        );
        let seed = SourceGenesisErrorV1::from(PublisherProjectGenesisErrorV1::Seed(
            ControllerSourceTreeSeedErrorV1::Signature,
        ));

        assert!(matches!(stale, SourceGenesisErrorV1::Stale));
        assert!(matches!(malformed, SourceGenesisErrorV1::Authorization(
            ProjectAuthorizationSourceErrorV2::NonCanonical,
        )));
        assert!(matches!(seed, SourceGenesisErrorV1::Seed(
            ControllerSourceTreeSeedErrorV1::Signature,
        )));
    }
}

#[cfg(test)]
mod signature_error_projection_tests {
    use super::*;
    use aos_sandbox_protocol::publisher_project_authorization::ProjectAuthorizationSignatureErrorV2;
    use aos_sandbox_ledger_replay::data::SourceSuccessorDataErrorV2;

    #[test]
    fn lower_signature_leaf_restores_the_existing_native_authorization_category() {
        for (index, error) in [ProjectAuthorizationSignatureErrorV2::NonCanonical,
            ProjectAuthorizationSignatureErrorV2::Stale, ProjectAuthorizationSignatureErrorV2::Signature].into_iter().enumerate() {
            let projected = SourceGenesisErrorV1::from(SourceSuccessorDataErrorV2::from(error));

            let SourceGenesisErrorV1::Authorization(actual) = projected else {
                panic!("signature leaf changed native category");
            };
            assert!(match index {
                0 =>
                    matches!(actual, ProjectAuthorizationSourceErrorV2::NonCanonical),
                1 =>
                    matches!(actual, ProjectAuthorizationSourceErrorV2::Stale),
                _ =>
                    matches!(actual, ProjectAuthorizationSourceErrorV2::Signature),
            });
        }
    }
}

impl From<aos_sandbox_ledger_replay::source_signer_data::SourceSignerGenesisDataErrorV1> for SourceGenesisErrorV1 {
    fn from(error: aos_sandbox_ledger_replay::source_signer_data::SourceSignerGenesisDataErrorV1) -> Self {
        use aos_sandbox_ledger_replay::source_signer_data::SourceSignerGenesisDataErrorV1;
        match error {
            SourceSignerGenesisDataErrorV1::NonCanonical => Self::NonCanonical,
            SourceSignerGenesisDataErrorV1::Conflict => Self::Conflict,
            SourceSignerGenesisDataErrorV1::Mechanical(cause) => Self::Journal(JournalError::from(cause)),
            SourceSignerGenesisDataErrorV1::History(cause) => Self::Journal(JournalError::from(cause)),
            SourceSignerGenesisDataErrorV1::SourceData(cause) => Self::from(cause),
        }
    }
}


pub(crate) fn project_source_genesis_wire_error_v1(
    cause: genesis_wire::SourceGenesisWireErrorV1,
) -> SourceGenesisErrorV1 {
    match cause {
        genesis_wire::SourceGenesisWireErrorV1::NonCanonical =>
            SourceGenesisErrorV1::NonCanonical,
    }
}

#[cfg(target_os = "linux")]
impl From<aos_sandbox_policy::native::RootAuthorityErrorV1> for SourceGenesisErrorV1 {
    fn from(error: aos_sandbox_policy::native::RootAuthorityErrorV1) -> Self {
        use aos_sandbox_policy::native::RootAuthorityErrorV1 as Native;
        use aos_sandbox_policy::native::PolicyNativeJournalErrorV1 as JournalNative;
        use aos_sandbox_ledger_replay::data::SourceSuccessorDataErrorV2 as Data;

        match error {
            Native::NonCanonical => Self::NonCanonical,
            Native::Conflict => Self::Conflict,
            Native::Stale => Self::Stale,
            Native::AdmissionClosed => Self::AdmissionClosed,
            Native::Journal(JournalNative::Mechanical(cause)) => Self::Journal(JournalError::from(cause)),
            Native::Journal(JournalNative::Root(cause)) => Self::Journal(JournalError::RootNative(cause)),
            Native::Journal(JournalNative::Financial(cause)) => Self::Journal(JournalError::RootFinancial(cause)),
            Native::Seed(cause) => Self::Seed(cause),
            Native::Authorization(cause) => Self::from(Data::Authorization(cause)),
            Native::AuthorizationSignature(cause) => Self::from(Data::AuthorizationSignature(cause)),
            Native::ControllerGenesis(cause) => Self::from(cause),
            Native::Transport(cause) => Self::Transport(cause),
            Native::Kernel(cause) => Self::Kernel(cause),
            cause @ (Native::Journal(JournalNative::Q04Current(_))
                | Native::Journal(JournalNative::RootAppend(_))
                | Native::Journal(JournalNative::NativePost(_))
                | Native::Journal(JournalNative::TargetCurrent(_))
                | Native::Currentness(_) | Native::Origin(_) | Native::OriginBorrow(_)
                | Native::Credential(_) | Native::Controller(_) | Native::Source(_)
                | Native::Q04Data(_) | Native::ControllerProject(_) | Native::CacheReadback(_)
                | Native::CacheNative(_) | Native::SignedInput(_) | Native::Allocation(_)
                | Native::GenesisOpening(_) | Native::GenesisMutation(_) | Native::SavedFloorData(_)) => Self::NativeAuthority(cause),
        }
    }
}

#[cfg(target_os = "linux")]
impl From<aos_sandbox_policy::controller_successor_data::ControllerSuccessorReadbackDataErrorV1>
    for SourceGenesisErrorV1
{
    fn from(error: aos_sandbox_policy::controller_successor_data::ControllerSuccessorReadbackDataErrorV1) -> Self {
        use aos_sandbox_policy::controller_successor_data::ControllerSuccessorReadbackDataErrorV1 as Data;
        match error {
            Data::NonCanonical => Self::NonCanonical,
            Data::Conflict => Self::Conflict,
            Data::Stale => Self::Stale,
            Data::AdmissionClosed => Self::AdmissionClosed,
            Data::Source(cause) => Self::from(cause),
            Data::Mechanical(cause) => Self::Journal(JournalError::from(cause)),
        }
    }
}
