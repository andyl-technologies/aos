//! Protected, same-session Storage readback of a Host output reservation.
//!
//! This is a necessary observation, never Storage writer admission. Method 48
//! remains absent from production hello; a future Controller issuer must sign
//! it from AOSCST01 before the closed Host responder can participate in any
//! AOSEOR03 admission.

use aos_proto::aos::sandbox::local::v1::BrokerMethod;
use aos_sandbox_linux::boot::KernelBootId;
use aos_sandbox_protocol::authenticated_session::all_methods::{
    AuthenticatedBrokerMethodOutcomeV1, AuthenticatedBrokerMethodResultV1,
    AuthenticatedBrokerOutcomeDirectionV1, AuthenticatedBrokerRequestDirectionV1,
};
use aos_sandbox_protocol::host_storage_output_readback::{
    ValidatedHostStorageOutputReadbackV1, decode_host_storage_output_readback_request_v1,
    decode_host_storage_output_readback_response_v1,
};
use rustix::time::{ClockId, clock_gettime};

use crate::{
    BrokerSessionSecurityError, DormantAuthenticatedBrokerSessionV1,
    ProtectedBrokerOutcomeCurrentV1, ProtectedBrokerOutcomeCurrentnessOwnerV1,
};

/// Retains one signed Host terminal and the move-only protected session head.
///
/// The checked scalar readback is not a Storage output writer permit. Its
/// Controller AOSCST01-based issuance and a held Storage writer admission are
/// still absent from the production path.
#[must_use = "revalidate the signed Host terminal before any future Storage join"]
pub struct ProtectedHostStorageOutputReadbackV1 {
    outcome: AuthenticatedBrokerMethodOutcomeV1,
    currentness: ProtectedBrokerOutcomeCurrentnessOwnerV1,
    readback: ValidatedHostStorageOutputReadbackV1,
}

/// Holds an exclusive protected journal borrow for one exact Host terminal.
///
/// This type has no Storage mutation method and cannot create AOSEOR03.
#[must_use = "retain the protected journal borrow through a future writer admission"]
pub struct ProtectedHostStorageOutputCurrentV1<'session> {
    current: ProtectedBrokerOutcomeCurrentV1<'session>,
    readback: ValidatedHostStorageOutputReadbackV1,
}

impl ProtectedHostStorageOutputReadbackV1 {
    /// Retains a signed Storage-audience Host success with exact original identity.
    ///
    /// # Errors
    ///
    /// Rejects a foreign method, direction, boot, unsuccessful terminal, or a
    /// response that diverges from the request's canonical record preimages.
    pub fn from_authenticated_response(
        outcome: AuthenticatedBrokerMethodOutcomeV1,
        currentness: ProtectedBrokerOutcomeCurrentnessOwnerV1,
    ) -> Result<Self, BrokerSessionSecurityError> {
        if outcome.method() != BrokerMethod::BROKER_METHOD_HOST_OBSERVE_STORAGE_OUTPUT
            || outcome.direction() != AuthenticatedBrokerOutcomeDirectionV1::ClientReceive
        {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        let AuthenticatedBrokerMethodResultV1::Success { exact_body, .. } = outcome.result() else {
            return Err(BrokerSessionSecurityError::Currentness);
        };
        let request = outcome.request();
        if request.method() != BrokerMethod::BROKER_METHOD_HOST_OBSERVE_STORAGE_OUTPUT
            || request.direction() != AuthenticatedBrokerRequestDirectionV1::ClientSend
        {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        let now = clock_gettime(ClockId::Boottime);
        let now = u64::try_from(now.tv_sec)
            .ok()
            .and_then(|seconds| seconds.checked_mul(1_000_000_000))
            .and_then(|seconds| {
                u64::try_from(now.tv_nsec)
                    .ok()
                    .and_then(|nanos| seconds.checked_add(nanos))
            })
            .ok_or(BrokerSessionSecurityError::Currentness)?;
        let original = decode_host_storage_output_readback_request_v1(
            request.exact_body(),
            request.peer(),
            request.peer_policy(),
            now,
        )
        .map_err(|_| BrokerSessionSecurityError::Currentness)?;
        let readback = decode_host_storage_output_readback_response_v1(exact_body, &original)
            .map_err(|_| BrokerSessionSecurityError::Currentness)?;
        if KernelBootId::current()
            .map_err(|_| BrokerSessionSecurityError::Currentness)?
            .into_bytes()
            != original.records().host_locator().host_boot_id()
        {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        Ok(Self {
            outcome,
            currentness,
            readback,
        })
    }

    /// Rechecks the exact terminal and live peer against the protected head.
    ///
    /// # Errors
    ///
    /// Rejects replay, supersession, or a changed peer or session transcript.
    pub fn join_current<'session>(
        self,
        session: &'session mut DormantAuthenticatedBrokerSessionV1,
    ) -> Result<ProtectedHostStorageOutputCurrentV1<'session>, BrokerSessionSecurityError> {
        let current = session.revalidate_broker_outcome(self.currentness)?;
        if current.authenticated_outcome() != &self.outcome {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        Ok(ProtectedHostStorageOutputCurrentV1 {
            current,
            readback: self.readback,
        })
    }
}

impl ProtectedHostStorageOutputCurrentV1<'_> {
    /// Returns the signed Host observation while retaining the journal borrow.
    #[must_use]
    pub const fn readback(&self) -> ValidatedHostStorageOutputReadbackV1 {
        self.readback
    }

    /// Rechecks that the journal head and connected Host remain current.
    ///
    /// # Errors
    ///
    /// Rejects a superseded terminal or changed protected peer state.
    pub fn recheck(&mut self) -> Result<(), BrokerSessionSecurityError> {
        self.current.revalidate()
    }
}
