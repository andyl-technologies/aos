//! Retains a fresh same-socket observation separately from passive association.
//!
//! The shared IO stage owns the returned error, including the original kernel
//! errno. The native cookie check is independently reached after an earlier
//! DATA mismatch and never depends on healthy Controller financial state.

use super::*;

/// Retains the exact native socket observation and preceding DATA comparison.
///
/// Only the actual completed Network association performs this observation.
/// The shared IO stage retains the whole error; the passive SDK Session getter
/// uses a different method that performs no syscall.
#[doc(hidden)]
#[derive(Debug)]
pub struct StartResourceSessionCurrentnessErrorV4 {
    data: Result<(), ResourceReservationErrorV1>,
    binding: Option<Result<(), RecordBindingError>>,
    kernel: Option<Result<u64, aos_sandbox_linux::Error>>,
}

impl Error for StartResourceSessionCurrentnessErrorV4 {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.data.as_ref().err().map(|cause| cause as &(dyn Error + 'static))
            .or_else(|| self.kernel.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| cause as &(dyn Error + 'static)))
            .or_else(|| self.binding.as_ref().and_then(|result| result.as_ref().err()).map(|cause| cause as &(dyn Error + 'static)))
    }
}

impl std::fmt::Display for StartResourceSessionCurrentnessErrorV4 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.source() {
            Some(cause) => std::fmt::Display::fmt(cause, formatter),
            None => formatter.write_str("the original Start Network socket observation is unavailable"),
        }
    }
}

impl StartResourceSessionAssociationV4 {
    /// Observes the same actual socket into the shared IO stage's owning result.
    ///
    /// The fresh cookie check always runs after the passive DATA comparison.
    /// It requires no healthy Controller gate and cannot suppress an owed IO
    /// after-observation when a prior financial or body operation has failed.
    ///
    /// # Errors
    /// Returns the whole original DATA comparison, native binding refusal and
    /// reached kernel errno; neither the socket nor association is replaced.
    pub(crate) fn require_current_session_v4(
        &self,
        journal: &Journal,
        socket: &SeqpacketSocket,
        transcript: &VerifiedBrokerSessionTranscriptV1,
    ) -> Result<(), StartResourceSessionCurrentnessErrorV4> {
        let data = self.require_same_session_v4(journal, socket, transcript);
        StartResourceSessionCurrentnessErrorV4::observe_same_origin_v4(data, Some(&self.socket), socket)
    }
}

impl StartResourceSessionCurrentnessErrorV4 {
    // Both fresh resource Sessions and the continuously held Create Storage
    // Session delegate this same native cookie engine after passive DATA.
    pub(in crate::controller_resource_reservation::create_intake)
    fn observe_same_origin_v4(
        data: Result<(), ResourceReservationErrorV1>,
        origin: Option<&StorageSeqpacketSessionOriginV1>,
        socket: &SeqpacketSocket,
    ) -> Result<(), Self> {
        let mut kernel = None;
        let binding = origin.map(|origin|
            origin.require_same_socket_retaining_v4(socket, &mut kernel));
        if data.is_err() || !matches!(binding, Some(Ok(()))) {
            return Err(Self { data, binding, kernel });
        }
        Ok(())
    }
}

impl StartResourceSessionAssociationV4 {
    pub(in crate::controller_resource_reservation::create_intake::provisioning::receiving::start_entry)
    fn observe_completed_endpoint_retaining_v2(&self,
        original: &mut aos_sandbox_linux::self_execution::SelfExecutionObservationV1,
    ) -> Result<(), aos_sandbox_linux::self_execution::SelfExecutionObservationError> {
        self.custody.validate_current_retaining(original)
    }
}
