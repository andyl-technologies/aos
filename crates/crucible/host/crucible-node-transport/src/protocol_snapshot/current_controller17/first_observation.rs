//! Joins the actual first restored Observe owner to its complete SDK journal.
//!
//! This distinct historical reader consumes the defining once-owner tuple. It
//! never converts it to a recurring suffix attempt, a live SDK owner, or a claim.
//! The Source/native reader separately authenticates the private proof chain.

use super::*;
use crate::bodies::{decode_request, decode_response};
use crate::envelope::{MessageKind, Method, RequestOrigin};
use crate::reference_packet::service::complete_restore::restoration_observe::PacketRestorationObservationRequest;

/// Retains exact checked first-observation correspondence as inert history.
///
/// Its private constructor checks the saved completion frontier and both actual
/// Controller journal originals. It supplies no current SDK frontier assertion,
/// native authentication, Source loan, readiness, or execution permission.
pub struct ValidatedHistoricalFirstRestorationObservation17 {
    original: Envelope,
    terminal: Envelope,
    response: ResponseBody,
    request: PacketRestorationObservationRequest,
    frontier: U64,
}

impl ValidatedHistoricalFirstRestorationObservation17 {
    /// Checks the defining completed first-observation owner and actual journal.
    ///
    /// The enclosing reader admits the independent typed/DOM validation row
    /// before calling and retains its full original Controller bytes on error.
    ///
    /// # Errors
    /// Refuses incomplete state, missing saved frontier, an unrelated request,
    /// different raw/typed reply, foreign original route, changed journal hash,
    /// or any completion frontier outside this same historical Controller cut.
    pub fn validate_data(
        controller: &ValidatedControllerSettledHistory17,
    ) -> Result<Self, ProviderError> {
        let root = controller.parts_data()?.as_object().ok_or_else(invalid)?;
        let history = tuple(field(root, "observation")?, 13)?;
        text(
            &history[0],
            "source-private.sdk-first-observation-current/17",
        )?;
        text(&history[8], "complete")?;
        let frontier: U64 = read(&history[12])?;
        let request: PacketRestorationObservationRequest = read(&history[2])?;
        request.validate_data()?;
        let body: ObserveRequest = read(&history[1])?;
        request.authenticate_body_data(&body)?;
        let original: Envelope = read(&history[4])?;
        let terminal: Envelope = read(&history[9])?;
        original.validate()?;
        terminal.validate()?;
        original.matches_response(&terminal)?;
        let session = field(root, "session")?.as_object().ok_or_else(invalid)?;
        let sequence: U64 = read(field(session, "sequence")?)?;
        let node: Id = read(field(root, "node")?)?;
        let owner: Id = read(field(root, "execution_owner")?)?;
        if original.message != MessageKind::Request
            || original.method != Method::Observe
            || original.operation_id.0.is_some()
            || original.node_id.0.as_ref() != Some(&node)
            || original.execution_owner_id.0.as_ref() != Some(&owner)
            || original.capture_owner_id.0.is_some()
            || frontier <= original.sequence
            || frontier > sequence
        {
            return Err(invalid());
        }
        let id = original.request_id.0.as_ref().ok_or_else(invalid)?;
        let custody = tuple(field(root, "custody")?, 6)?;
        let journal = custody[3].as_object().ok_or_else(invalid)?;
        let actual = object(
            journal.get(id.as_str()).ok_or_else(invalid)?,
            &["request", "identity", "response"],
        )?;
        if field(actual, "request")? != &history[4]
            || field(actual, "response")? != &history[9]
            || read::<HashRef>(field(actual, "identity")?)?
                != original.request_hash(RequestOrigin::Controller)?
        {
            return Err(invalid());
        }
        let response = decode_response(
            &decode_request(original.method, &original.body)?,
            &terminal.body,
        )?;
        if serde_json::to_value(crate::retained_metadata::historical_response_body_data(
            &response,
        )?)
        .map_err(crucible_node_format::ContractError::from)?
            != history[10]
        {
            return Err(invalid());
        }
        let Some(MethodResult::Observe(observed)) = response.result.as_ref() else {
            return Err(invalid());
        };
        let [batch] = observed.observations.as_slice() else {
            return Err(invalid());
        };
        if !matches!(
            &response.shape,
            crate::bodies::ResponseShape::Completed {
                operation_state: crate::bodies::OperationState::Completed,
                ..
            }
        ) {
            return Err(invalid());
        }
        super::suffix_pair::authenticate_content_root_data(&custody[5], &batch.measurement_ref)?;
        Ok(Self {
            original,
            terminal,
            response,
            request,
            frontier,
        })
    }

    /// Borrows the actual original, terminal and independently decoded reply.
    pub fn completed_pair_data(&self) -> (&Envelope, &Envelope, &ResponseBody) {
        (&self.original, &self.terminal, &self.response)
    }

    /// Borrows the defining first-observation request retained before assignment.
    pub fn request_data(&self) -> &PacketRestorationObservationRequest {
        &self.request
    }

    /// Counts the actual independent typed history backing without encoding it.
    ///
    /// The containing reader separately counts this result's inline header.
    ///
    /// # Errors
    /// Refuses metadata traversal or checked layout overflow.
    pub fn retained_metadata_data(
        &self,
    ) -> Result<crate::retained_metadata::RetainedProtocolMetadataFacts, ProviderError> {
        let mut observer = crate::retained_metadata::MetadataObserver::new();
        observer.observe(&self.original)?;
        observer.observe(&self.terminal)?;
        observer.observe(&self.request)?;
        crate::retained_metadata::historical_response_body_data(&self.response)?
            .observe_retained_metadata_data(&mut observer)?;
        Ok(observer.finish())
    }

    /// Returns the actual saved post-evidence completion frontier as history.
    pub const fn completed_frontier_data(&self) -> U64 {
        self.frontier
    }
}

impl ValidatedControllerSettledHistory17 {
    /// Checks membership in this actual hash-verified completed object dictionary.
    ///
    /// The strict Controller reader already verified each complete fullref/body
    /// pair and alias. This check performs no Blob fetch and creates no content
    /// ownership, currentness assertion, or live SDK/native permission.
    ///
    /// # Errors
    /// Refuses a missing completed object or a different complete reference,
    /// including equal digest text paired with another media type or length.
    pub fn authenticate_completed_content_reference_data(
        &self,
        reference: &ContentRef,
    ) -> Result<(), ProviderError> {
        let root = self.parts_data()?.as_object().ok_or_else(invalid)?;
        let custody = tuple(field(root, "custody")?, 6)?;
        super::suffix_pair::authenticate_content_root_data(&custody[5], reference)
    }
}
