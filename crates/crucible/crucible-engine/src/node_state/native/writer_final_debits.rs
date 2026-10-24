//! Historical final writer accounts borrowed from authenticated native archives.
//!
//! This distinct draft codec links complete original requests, responses,
//! custody, image rosters, installed policy and final attempted debit bytes.
//! Its installed factory hook defaults to refusal. A successful parser supplies
//! preservation data only; it does not qualify a fresh peer or reset an account.
//!
//! ```text
//! writer-codec -> capture-request, capture-response, native-custody,
//!                process-closure, policy, pre-capture-account, final-account
//! final-account -> exact final debit body and the same original capture roots
//! ```

use crucible_node_format::{ContentRef, Id, Position, U64, Validate};
use serde::Deserialize;

use crate::{node_admission::AdmittedGraph, node_contract::NativeStateKey};

use super::{
    AuthenticatedNativeSource, NativeArtifactState, NativeOwnerState, NativeWorldFactory,
    StateError, refused,
};

#[path = "writer_history.rs"]
mod history;

use history::WriterHistory;

const MAXIMUM_CODEC_BYTES: usize = 4 * 1024 * 1024;
const MAXIMUM_ENVELOPE_BYTES: usize = 16 * 1024;
#[path = "writer_exchange.rs"]
mod exchange;

use exchange::OriginalFinalExchange;

#[path = "writer_terminal_park.rs"]
mod terminal;

use terminal::OriginalTerminalControlPark;

#[path = "writer_delivery.rs"]
mod delivery;

use delivery::OriginalWriterDelivery;

const FINAL_DEBIT_MEDIA: &str = "application/vnd.crucible.dmtcp-writer-final-debits.v3";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WriterCodec {
    schema: String,
    key: NativeStateKey,
    owner: Id,
    incarnation: Id,
    generation: U64,
    cut: Position,
    capture: Id,
    capture_request: ContentRef,
    capture_response: ContentRef,
    native_custody: ContentRef,
    process_closure: ContentRef,
    installed_policy: ContentRef,
    pre_capture_history: ContentRef,
    final_account: ContentRef,
    final_delivery: ContentRef,
    native_final_exchange: ContentRef,
    control_history: ContentRef,
    terminal_park: ContentRef,
    artifacts: Vec<NativeArtifactState>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FinalAccount {
    schema: String,
    capture: Id,
    original_process: U64,
    capture_request: ContentRef,
    capture_response: ContentRef,
    native_custody: ContentRef,
    process_closure: ContentRef,
    installed_policy: ContentRef,
    pre_capture_history: ContentRef,
    final_history: ContentRef,
    final_delivery: ContentRef,
    native_final_exchange: ContentRef,
    control_history: ContentRef,
    terminal_park: ContentRef,
}

/// Retains exact historical debit and original capture ancestry as borrowed data.
///
/// Only an actual authenticated native source can construct this value. The
/// complete source-installed semantic verifier must additionally authenticate
/// its policy, actual capture outcome and whole control/image closure.
pub struct OriginalWriterFinalDebitSource<'a> {
    owner: &'a NativeOwnerState,
    codec_body: &'a [u8],
    codec: WriterCodec,
    account_body: &'a [u8],
    account: FinalAccount,
    final_history: WriterHistory<'a>,
    delivery: OriginalWriterDelivery<'a>,
    native_exchange: OriginalFinalExchange<'a>,
    control_body: &'a [u8],
    terminal_park: OriginalTerminalControlPark<'a>,
}

impl OriginalWriterFinalDebitSource<'_> {
    /// Borrows the unchanged original capture owner and native key.
    pub fn owner(&self) -> &NativeOwnerState {
        self.owner
    }

    /// Borrows the exact source codec bytes, never a reserialized replacement.
    pub fn codec_body(&self) -> &[u8] {
        self.codec_body
    }

    /// Borrows the exact final-account envelope retained by the source archive.
    pub fn account_body(&self) -> &[u8] {
        self.account_body
    }

    /// Borrows complete attempted writer debits, including failed writes.
    pub fn final_history_body(&self) -> &[u8] {
        self.final_history.body()
    }

    /// Borrows the exact controller delivery before its source semantic check.
    pub fn final_delivery_body(&self) -> &[u8] {
        self.delivery.body()
    }

    /// Borrows the original compiled getter value for exact installed comparison.
    ///
    /// This historical scalar is not a current admission or capacity allowance.
    pub fn original_native_account_bytes(&self) -> u64 {
        self.delivery.native_account_bytes()
    }

    /// Borrows the complete native final exchange, including original headers.
    pub fn native_final_exchange_body(&self) -> &[u8] {
        self.native_exchange.body()
    }

    /// Borrows the complete original control history without native reencoding.
    pub fn control_history_body(&self) -> &[u8] {
        self.control_body
    }

    /// Borrows the exact source terminal seal, not proof of an entered wait.
    pub fn terminal_control_park_body(&self) -> &[u8] {
        self.terminal_park.body()
    }

    /// Borrows the original capture identity for installed semantic verification.
    pub fn capture(&self) -> &Id {
        &self.codec.capture
    }

    /// Borrows the exact installed writer-policy content reference.
    pub fn installed_policy(&self) -> &ContentRef {
        &self.account.installed_policy
    }

    /// Borrows original request, response, native custody and closure references.
    pub fn capture_roots(&self) -> [&ContentRef; 4] {
        [
            &self.account.capture_request,
            &self.account.capture_response,
            &self.account.native_custody,
            &self.account.process_closure,
        ]
    }
}

/// Retains source-approved historical writer data without granting execution.
///
/// It cannot serialize itself, spawn a child, construct a live certificate or
/// reset native debit state. The native early-rebind consumer remains absent.
pub struct AuthenticatedWriterFinalDebits<'a> {
    source: OriginalWriterFinalDebitSource<'a>,
}

impl AuthenticatedWriterFinalDebits<'_> {
    /// Borrows source-approved original history for a separately checked rebind.
    pub fn source(&self) -> &OriginalWriterFinalDebitSource<'_> {
        &self.source
    }
}

impl AuthenticatedNativeSource<'_> {
    /// Borrows final writer records under the distinct original archive codec.
    ///
    /// No source path is read. The complete typed dependency rows, owner/cut,
    /// original activation identity and exact artifact census must agree.
    ///
    /// # Errors
    /// Refuses legacy codecs, unbounded or absent bodies, changed typed roles,
    /// incomplete dependencies, dropped attempted debits or active writers.
    pub fn original_writer_final_debits(
        &self,
    ) -> Result<OriginalWriterFinalDebitSource<'_>, StateError> {
        let codec_body = self.native()?;
        if codec_body.len() > MAXIMUM_CODEC_BYTES {
            return Err(refused("writer codec exceeds its selected record credit"));
        }
        let codec: WriterCodec = serde_json::from_slice(codec_body)
            .map_err(|_| refused("distinct writer source codec malformed"))?;
        let original_owner = self
            .runtime()
            .source_activation
            .owners
            .iter()
            .find(|owner| owner.owner == self.owner().owner)
            .ok_or_else(|| refused("original writer activation owner absent"))?;
        if codec.schema != "crucible.gem5.cfi-writer-archive.v3"
            || codec.key != self.owner().key
            || codec.owner != self.owner().owner
            || codec.incarnation != original_owner.incarnation
            || codec.generation != original_owner.generation
            || codec.cut != self.owner().cut
            || codec.artifacts != self.owner().artifacts
            || codec.final_account.media_type != FINAL_DEBIT_MEDIA
            || !self.owner().evidence.contains(&codec.final_account)
        {
            return Err(refused("writer codec differs from sealed complete owner"));
        }
        codec.capture.validate().map_err(super::super::schema)?;
        let roots = [
            &codec.capture_request,
            &codec.capture_response,
            &codec.native_custody,
            &codec.process_closure,
            &codec.installed_policy,
            &codec.pre_capture_history,
            &codec.final_account,
            &codec.final_delivery,
            &codec.native_final_exchange,
            &codec.control_history,
            &codec.terminal_park,
        ];
        exact_dependencies(self, &self.owner().state, &roots)?;
        let account_body = original_body(self, &codec.final_account, MAXIMUM_ENVELOPE_BYTES)?;
        let account: FinalAccount = serde_json::from_slice(account_body)
            .map_err(|_| refused("original final writer envelope malformed"))?;
        if account.schema != "crucible.dmtcp.writer-final-account.v3"
            || account.capture != codec.capture
            || account.capture_request != codec.capture_request
            || account.capture_response != codec.capture_response
            || account.native_custody != codec.native_custody
            || account.process_closure != codec.process_closure
            || account.installed_policy != codec.installed_policy
            || account.pre_capture_history != codec.pre_capture_history
            || account.final_delivery != codec.final_delivery
            || account.native_final_exchange != codec.native_final_exchange
            || account.control_history != codec.control_history
            || account.terminal_park != codec.terminal_park
            || account.terminal_park.media_type
                != "application/vnd.crucible.dmtcp-terminal-control-park.v1"
            || account.final_delivery.media_type
                != "application/vnd.crucible.gem5-writer-delivery.v3"
            || account.native_final_exchange.media_type
                != "application/vnd.crucible.dmtcp-final-exchange.v1"
            || account.control_history.media_type
                != "application/vnd.crucible.dmtcp-control-history.v1"
            || account.final_history.media_type
                != "application/vnd.crucible.dmtcp-writer-history.v1"
            || account.pre_capture_history.media_type
                != "application/vnd.crucible.dmtcp-writer-history.v1"
        {
            return Err(refused(
                "final writer envelope changed original capture roots",
            ));
        }
        exact_dependencies(
            self,
            &codec.final_account,
            &[
                &account.capture_request,
                &account.capture_response,
                &account.native_custody,
                &account.process_closure,
                &account.installed_policy,
                &account.pre_capture_history,
                &account.final_history,
                &account.final_delivery,
                &account.native_final_exchange,
                &account.control_history,
                &account.terminal_park,
            ],
        )?;
        let earlier_body = original_body(self, &account.pre_capture_history, 2 * 1024 * 1024)?;
        let final_body = original_body(self, &account.final_history, 2 * 1024 * 1024)?;
        let earlier = WriterHistory::parse(earlier_body).map_err(refused)?;
        let final_history = WriterHistory::parse(final_body).map_err(refused)?;
        final_history.preserves(&earlier).map_err(refused)?;
        if final_history.process() != account.original_process.get() {
            return Err(refused("writer original process identity differs"));
        }
        let delivery_body = original_body(self, &account.final_delivery, 4 * 1024 * 1024)?;
        let exchange_body =
            original_body(self, &account.native_final_exchange, 2 * 1024 * 1024 + 8192)?;
        let native_exchange =
            OriginalFinalExchange::parse(exchange_body, final_body, account.original_process.get())
                .map_err(refused)?;
        let control_body = original_body(self, &account.control_history, 5 * 1024 * 1024)?;
        exchange::validate_control_history(control_body, account.original_process.get())
            .map_err(refused)?;
        let park_body = original_body(self, &account.terminal_park, 64)?;
        let terminal_park = OriginalTerminalControlPark::parse(
            park_body,
            final_body,
            control_body,
            account.original_process.get(),
        )
        .map_err(refused)?;
        let delivery = OriginalWriterDelivery::parse(
            delivery_body,
            codec.capture.as_str(),
            earlier_body,
            final_body,
            exchange_body,
            control_body,
            park_body,
        )
        .map_err(refused)?;
        Ok(OriginalWriterFinalDebitSource {
            owner: self.owner(),
            codec_body,
            codec,
            account_body,
            account,
            final_history,
            delivery,
            native_exchange,
            control_body,
            terminal_park,
        })
    }

    /// Obtains installed source approval of complete original writer ancestry.
    ///
    /// The trusted factory hook must authenticate the full selected profile,
    /// original capture response and all image/control dependencies. Existing
    /// factories refuse by default; this API cannot promote an old SE profile.
    ///
    /// # Errors
    /// Refuses malformed original records or absent installed semantic approval.
    pub fn authenticate_writer_final_debits(
        &self,
        graph: &AdmittedGraph,
        factory: &dyn NativeWorldFactory,
    ) -> Result<AuthenticatedWriterFinalDebits<'_>, StateError> {
        let original = self.original_writer_final_debits()?;
        factory.authenticate_writer_final_debit_source(graph, self, &original)?;
        Ok(AuthenticatedWriterFinalDebits { source: original })
    }
}

fn original_body<'a>(
    source: &'a AuthenticatedNativeSource<'_>,
    reference: &ContentRef,
    maximum: usize,
) -> Result<&'a [u8], StateError> {
    reference.validate().map_err(super::super::schema)?;
    if reference.length.get() > maximum as u64 {
        return Err(refused("writer original body exceeds borrowed byte credit"));
    }
    let body = source
        .content()
        .get(reference)
        .ok_or_else(|| refused("typed original writer object absent"))?;
    // The opaque source already verified its complete typed identity.
    // No path, expected digest or freshly encoded DTO is used as an authority.
    if body.len() as u64 != reference.length.get() {
        return Err(refused("original writer body extent differs"));
    }
    Ok(body)
}

fn exact_dependencies(
    source: &AuthenticatedNativeSource<'_>,
    reference: &ContentRef,
    expected: &[&ContentRef],
) -> Result<(), StateError> {
    let actual = &source
        .archive()
        .index
        .objects
        .iter()
        .find(|object| object.reference == *reference)
        .ok_or_else(|| refused("writer original typed object absent"))?
        .dependencies;
    if actual.len() != expected.len()
        || expected
            .iter()
            .enumerate()
            .any(|(index, value)| expected[..index].contains(value) || !actual.contains(value))
    {
        return Err(refused("writer direct typed dependency census differs"));
    }
    for dependency in actual {
        original_body(source, dependency, 5 * 1024 * 1024)?;
    }
    Ok(())
}
