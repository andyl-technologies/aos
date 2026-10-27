//! Owns native17 raw and typed partials without live installation rights.
//!
//! A complete reader installs its once-attempt before copying signed input.
//! Completed child owners stay in that attempt before later correspondence
//! checks. These types contain no stream, private key issuer, physical Hold,
//! registrar, native reservation or Source Capture claim.

#[path = "sealed/capacities.rs"]
mod capacities;

use super::*;
use crate::reference_packet::continuation_models::settled_reader::PacketSettledModel17Data;
use crate::reference_packet::control::PacketNative5UnderlyingRecord;
use crate::reference_packet::service::complete_restore::{
    PacketNativeRestoredRecord, transfer::PacketCompleteRestorePrepareRequest,
};
use crate::retained_metadata::{
    MetadataObserver, requested_storage::requested_metadata_backing_storage_data,
};
use crucible_node_format::{Validate, canonical};

#[path = "sealed/model_adoption18.rs"]
mod model_adoption18;
pub(crate) use model_adoption18::RestoredSettledNative18ModelAdoption;

#[path = "sealed/model_construction18.rs"]
mod model_construction18;
pub use model_construction18::RestoredSettledNativeImportModelConstructionData;

#[path = "sealed/boundary_construction18.rs"]
mod boundary_construction18;

#[path = "sealed_graph_cache.rs"]
mod graph_cache;
use graph_cache::NativeGraph17DecodeCache;

#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) enum DecodeStage {
    Receiving,
    Framed,
    Validated,
    Failed,
}

/// Retains all raw and completed typed native17 children on later refusal.
///
/// Its private constructor is available only to the defining native readers.
/// The post-confirmation output plan can install this partial owner before raw
/// copies and DOM parsing. Only the complete semantic reader can validate it;
/// creating a slot or decoding bytes issues no live authority.
pub struct RestoredSettledNative17DecodeAttempt {
    pub(super) references: [Option<ContentRef>; 5],
    pub(super) raw: [Vec<u8>; 5],
    pub(super) before_encoded: Vec<u8>,
    pub(super) before_native_graph: NativeGraph17DecodeCache,
    pub(super) native_graph: NativeGraph17DecodeCache,
    pub(super) immutable: Vec<(ContentRef, Vec<u8>)>,
    pub(super) aliases: Vec<super::aliases::RestoredSettledNative17AliasSummary>,
    pub(super) limits: Option<RestoredSettledNative17Limits>,
    pub(super) stage: DecodeStage,
}

impl RestoredSettledNative17DecodeAttempt {
    pub(super) fn new() -> Self {
        Self {
            references: std::array::from_fn(|_| None),
            raw: std::array::from_fn(|_| Vec::new()),
            before_encoded: Vec::new(),
            before_native_graph: NativeGraph17DecodeCache::new(),
            native_graph: NativeGraph17DecodeCache::new(),
            immutable: Vec::new(),
            aliases: Vec::new(),
            limits: None,
            stage: DecodeStage::Receiving,
        }
    }

    // Reference strings belong to the actual attempt before any reservation.
    // A later allocation refusal must retain each already-initialized bank.
    pub(super) fn retain_reference_data(
        &mut self,
        index: usize,
        reference: &ContentRef,
        maximum: usize,
    ) -> Result<(), ProviderError> {
        reference.validate()?;

        let destination = self.references.get_mut(index).ok_or_else(invalid)?;
        if destination.is_some() {
            return Err(invalid());
        }
        *destination = Some(ContentRef {
            hash: crucible_node_format::HashRef {
                algorithm: String::new(),
                domain: String::new(),
                digest: String::new(),
            },
            length: reference.length,
            media_type: String::new(),
        });
        for (field, source) in [
            reference.hash.algorithm.as_str(),
            reference.hash.domain.as_str(),
            reference.hash.digest.as_str(),
            reference.media_type.as_str(),
        ]
        .into_iter()
        .enumerate()
        {
            let retained = self.retained_requested_storage_data(maximum)?;
            if retained.checked_add(source.len()).ok_or_else(invalid)? > maximum {
                return Err(invalid());
            }
            {
                let reference = self.references[index].as_mut().ok_or_else(invalid)?;
                reference_string_data(reference, field)?
                    .try_reserve_exact(source.len())
                    .map_err(|_| invalid())?;
            }
            // Account the allocator's actual requested capacity before filling.
            self.retained_requested_storage_data(maximum)?;
            let reference = self.references[index].as_mut().ok_or_else(invalid)?;
            reference_string_data(reference, field)?.push_str(source);
        }
        Ok(())
    }

    /// Counts actual initialized raw/typed backing, including partials.
    ///
    /// The enclosing cache/Source root separately charges `size_of::<Self>()`.
    /// This method includes both independently retained graph caches; encoded
    /// bytes do not stand in for their capacities or map-node allocations.
    ///
    /// # Errors
    /// Refuses checked requested-layout overflow, invalid child capacity data
    /// or backing beyond the caller's independently admitted maximum.
    pub fn retained_requested_storage_data(&self, maximum: usize) -> Result<usize, ProviderError> {
        let mut observer = MetadataObserver::new();
        for reference in &self.references {
            observer.observe(reference)?;
        }
        for raw in &self.raw {
            observer.observe(raw)?;
        }
        observer.observe(&self.before_encoded)?;
        observer.vector::<super::aliases::RestoredSettledNative17AliasSummary>(
            self.aliases.capacity(),
        )?;
        observer.vector::<(ContentRef, Vec<u8>)>(self.immutable.capacity())?;
        for (reference, bytes) in &self.immutable {
            observer.observe(reference)?;
            observer.observe(bytes)?;
        }
        let mut requested = requested_metadata_backing_storage_data(&observer.finish())?;
        for graph in [&self.before_native_graph, &self.native_graph] {
            let remaining = maximum.checked_sub(requested).ok_or_else(invalid)?;
            requested = requested
                .checked_add(graph.retained_requested_storage_data(remaining)?)
                .ok_or_else(invalid)?;
        }
        if requested > maximum {
            return Err(invalid());
        }
        Ok(requested)
    }

    /// Reports completion of the whole semantic reader, never live adoption.
    pub const fn is_validated_data(&self) -> bool {
        matches!(self.stage, DecodeStage::Validated)
    }
}

/// Keeps the successfully checked inert current native17 graph and raw bodies.
///
/// Only the defining whole reader may construct this owner. A separate genuine
/// fresh target grant/Factory operation is required to create current native
/// state; historical keys, role names and saved ledger data are never permits.
pub struct SealedHistoricalRestoredSettledNative17 {
    pub(super) decoded: RestoredSettledNative17DecodeAttempt,
}

impl SealedHistoricalRestoredSettledNative17 {
    /// Quotes native-private cold Source verification from completed owners.
    ///
    /// The counter borrows actual native/Controller body shapes and the cached
    /// original birth inputs. It does not construct the Source association or
    /// run any proof validator. The caller separately funds exact selected
    /// Source parsing, custom formatter strings, public proof canonical banks,
    /// the first underlying-model reparse and supplied launch comparisons.
    /// These allocations are not represented by a successful native decoder or
    /// by this owner's retained-storage census.
    ///
    /// # Errors
    /// Refuses incomplete native or Controller history, missing required cached
    /// phases, arithmetic/layout overflow or a quote beyond the independent
    /// requested-storage ceiling. No live permission follows from the row.
    pub fn source_history17_authentication_geometry_data(
        &self,
        controller: &crate::protocol_snapshot::current_controller17::ValidatedControllerSettledHistory17,
        capture: &crate::protocol_snapshot::current_controller17::ValidatedHistoricalRestoredSettledCapture17,
        maximum_requested_bytes: usize,
    ) -> Result<
        super::historical_auth::construction::RestoredSettledSourceHistory17AuthGeometryData,
        ProviderError,
    > {
        let graph = self.validated_native_graph_data()?;
        graph.source_history17_authentication_geometry_data(
            controller,
            capture,
            maximum_requested_bytes,
        )
    }

    /// Checks the full first-observation history against the sealed native graph.
    ///
    /// The actual ACK, Prepare, Commit, Arm, World and first Observe proofs,
    /// original pairs, cached receipts and shared-root relationships remain
    /// native-owned historical DATA. This comparison grants no new action.
    ///
    /// # Errors
    /// Refuses an incomplete graph, changed Source history, proof, full reference,
    /// selected scope, original assignment or native cached receipt.
    pub fn authenticate_restored_observation_history_data(
        &self,
        source: &super::historical_auth::HistoricalRestoredObservation17Data<'_>,
    ) -> Result<(), ProviderError> {
        let graph = self.validated_native_graph_data()?;
        let restoration = graph.historical_restoration17_data(source.association)?;
        let maximum_frame_bytes =
            usize::try_from(restoration.ack.bindings.authority.limits.frame_bytes.get())
                .map_err(|_| invalid())?;
        super::historical_auth::authenticate_historical_restored_observation_data(
            graph.historical_private_key17_data()?,
            source,
            &restoration,
            graph.restoration_stages17_data()?,
            super::historical_auth::HistoricalAuthLimits17 {
                maximum_frame_bytes,
                maximum_evidence_bytes: 65_536,
            },
        )
    }

    fn validated_native_graph_data(
        &self,
    ) -> Result<
        &crate::protocol_snapshot::native_wholegraph17::NativeCurrentGraph17Data,
        ProviderError,
    > {
        self.ensure_validated()?;
        let graph = self.decoded.native_graph.as_ref().ok_or_else(invalid)?;
        graph.validate_data()?;
        graph.completed_data().ok_or_else(invalid)
    }

    /// Borrows the actual archived Prepare request from the completed native graph.
    ///
    /// The request retains its original full input references and allocation
    /// contract. This DATA loan grants no fresh restoration or construction.
    ///
    /// # Errors
    /// Refuses an incomplete seal or an absent or unfinished cached Prepare slot.
    pub fn restoration_prepare_request_data(
        &self,
    ) -> Result<&PacketCompleteRestorePrepareRequest, ProviderError> {
        self.validated_native_graph_data()?
            .restoration_prepare_request_data()
    }

    /// Returns the exact archived carrier's declared normalization ceiling.
    ///
    /// This scalar comes from the same sealed native graph, without replacing
    /// its declaration with a current launch limit or a format-wide maximum.
    ///
    /// # Errors
    /// Refuses an incomplete seal or an invalid archived carrier contract.
    pub fn archived_normalization_maximum_data(
        &self,
    ) -> Result<crucible_node_format::U64, ProviderError> {
        self.validated_native_graph_data()?
            .archived_normalization_maximum_data()
    }

    /// Borrows the actual authenticated startup suffix request ceiling.
    ///
    /// This immutable limit comes from the same completed native Boot's sealed
    /// reservation. Source counters and caller-provided limits cannot replace
    /// that declaration or renew its already-used request allowance.
    ///
    /// # Errors
    /// Refuses incomplete native lineage, an absent or failed startup suffix,
    /// or disagreement between its actual reservation and sealed bank.
    pub fn restored_suffix_maximum_originals_data(
        &self,
    ) -> Result<crucible_node_format::U64, ProviderError> {
        self.validated_native_graph_data()?
            .restored_suffix_maximum_originals_data()
    }

    /// Checks the exact original archived launch against its native Boot bytes.
    ///
    /// The caller admits the bounded launch JSON verification temporary before
    /// this comparison. No new typed launch, selector or native grant is issued.
    ///
    /// # Errors
    /// Refuses an incomplete native graph, oversized launch, or any changed
    /// field in the actual original canonical launch declaration.
    pub fn authenticate_original_launch_data(
        &self,
        launch: &crate::reference_packet::service::PacketNative5SourceLaunch,
    ) -> Result<(), ProviderError> {
        self.validated_native_graph_data()?
            .authenticate_original_launch_data(launch)
    }

    /// Borrows the actual retained restoration Hold evidence as historical data.
    ///
    /// # Errors
    /// Refuses incomplete native lineage or an absent actual Commit Hold.
    pub fn restoration_hold_data(
        &self,
    ) -> Result<
        &crate::reference_packet::service::complete_restore::PacketNativeRestoredCommitHold,
        ProviderError,
    > {
        self.validated_native_graph_data()?.restoration_hold_data()
    }

    /// Borrows this archived native Boot's actual original-spend ledger.
    ///
    /// These per-Boot facts are distinct from Source semantic operation counts.
    /// They preserve the recorded once phase and do not issue future credit.
    ///
    /// # Errors
    /// Refuses an incomplete graph or unavailable actual reserve history.
    pub fn archived_original_spend_ledger_data(
        &self,
    ) -> Result<
        &crate::protocol_snapshot::restored_suffix_history::HistoricalRestoredSuffixLedger,
        ProviderError,
    > {
        self.validated_native_graph_data()?
            .archived_spend_ledger_data()
    }

    /// Rechecks actual SDK Capture history against the same sealed native cuts.
    ///
    /// Source supplies its genuine strict Controller and completed Capture
    /// loans. This comparison cannot reconstruct live SDK or native owners.
    ///
    /// # Errors
    /// Refuses incomplete cold roles, another Controller history, changed
    /// literals/fullrefs, or any native two-cut proof disagreement.
    pub fn authenticate_restored_capture_history_data(
        &self,
        sdk: &crate::protocol_snapshot::current_controller17::ValidatedHistoricalRestoredSettledCapture17,
        controller: &crate::protocol_snapshot::current_controller17::ValidatedControllerSettledHistory17,
    ) -> Result<(), ProviderError> {
        self.ensure_validated()?;
        let limits = self.decoded.limits.as_ref().ok_or_else(invalid)?;
        let input = self.retained_input_data()?;
        let plan = super::cold::RestoredSettledNative17Plan::validate_data(&input, limits)?;
        plan.authenticate_completed_sdk_data(sdk)?;
        for (original, terminal, _) in [sdk.capture_pair_data(), sdk.confirmation_pair_data()] {
            controller.authenticate_historical_controller_pair17_data(original, terminal)?;
        }
        plan.authenticate_native_outputs_data(&self.decoded, sdk)
    }

    pub(super) fn retained_input_data(
        &self,
    ) -> Result<RestoredSettledNative17Input<'_>, ProviderError> {
        Ok(RestoredSettledNative17Input {
            snapshot: (
                self.decoded.references[0].as_ref().ok_or_else(invalid)?,
                &self.decoded.raw[0],
            ),
            current_protocol: (
                self.decoded.references[1].as_ref().ok_or_else(invalid)?,
                &self.decoded.raw[1],
            ),
            control: (
                self.decoded.references[2].as_ref().ok_or_else(invalid)?,
                &self.decoded.raw[2],
            ),
            anchor: (
                self.decoded.references[3].as_ref().ok_or_else(invalid)?,
                &self.decoded.raw[3],
            ),
            journal: (
                self.decoded.references[4].as_ref().ok_or_else(invalid)?,
                &self.decoded.raw[4],
            ),
        })
    }

    /// Borrows the exact verified current-protocol full reference.
    ///
    /// # Errors
    /// Refuses an incomplete internal owner rather than fabricating a reference.
    pub fn body_reference(&self) -> Result<&ContentRef, ProviderError> {
        self.ensure_validated()?;
        self.decoded.references[1].as_ref().ok_or_else(invalid)
    }

    /// Borrows the exact retained current-protocol body with no mutable escape.
    ///
    /// # Errors
    /// Refuses an incomplete owner or absent raw current-protocol bytes.
    pub fn encoded_body(&self) -> Result<&[u8], ProviderError> {
        self.ensure_validated()?;
        if self.decoded.raw[1].is_empty() {
            return Err(invalid());
        }
        Ok(&self.decoded.raw[1])
    }

    /// Returns the full retained current model cut as inert data.
    ///
    /// # Errors
    /// Refuses an incomplete owner or a missing current model in its native graph.
    pub fn current_position_data(&self) -> Result<crucible_node_format::Position, ProviderError> {
        self.ensure_validated()?;
        Ok(self
            .validated_native_graph_data()?
            .current_model17_data()?
            .current_position_data())
    }

    /// Derives the current inventory boundary before its model leaves the archive.
    ///
    /// The genuine installer independently admits complete graph/model validation
    /// and canonical inventory work. This DATA does not authenticate fresh Source
    /// custody, issue native credit or replace the original restoration boundary.
    ///
    /// # Errors
    /// Refuses an incomplete archive, invalid current graph or inventory encoding.
    pub(crate) fn installation_boundary18_data(
        &self,
    ) -> Result<
        crate::reference_packet::continuation_models::PacketModelCaptureBoundaryData,
        ProviderError,
    > {
        self.validated_native_graph_data()?
            .current_model17_data()?
            .installation_boundary18_data()
    }

    /// Compares the complete pre-Capture checkpoint with the retained model.
    ///
    /// The Source supplies its actually retained latest retired Observe proof;
    /// the complete reader has already joined the signed Capture request to
    /// this same owner. Capture and confirmation may add protocol history but
    /// must not advance the model, change inventory, or create a grant. This is
    /// a DATA comparison; the real SDK completed pair and current SourceRead
    /// fences are still required before issuing the separate admin bridge.
    ///
    /// The caller admits independent canonical Value/byte temporaries for both
    /// bounded 65,536-byte proof objects before calling this method.
    ///
    /// # Errors
    /// Refuses incomplete native17 state, any changed immutable Commit ancestry,
    /// owner/World/current proof reference, non-Observe proof, current grant,
    /// model inventory/cursor difference, or invalid/corrupted canonical refs.
    pub fn authenticate_current_checkpoint_data(
        &self,
        restored: &PacketNativeRestoredRecord,
        underlying: &PacketNative5UnderlyingRecord,
        measurement: &ContentRef,
    ) -> Result<(), ProviderError> {
        self.ensure_validated()?;
        authenticate_current_checkpoint_data(&self.decoded, restored, underlying, measurement)
    }

    /// Starts a closed historical Producer1 signature comparison.
    ///
    /// The caller streams the exact defining A transcript after its fixed
    /// domain, slot little-endian bytes and previous digest. Neither a raw key
    /// nor a computed MAC is exposed. Verification cannot create a fresh Source,
    /// administrative Capture claim, runtime grant or native reservation.
    ///
    /// # Errors
    /// Refuses incomplete native17/birth correspondence or a zero transcript
    /// ceiling. The caller independently admits its serialization work first.
    pub fn restored_producer_history_verifier_data(
        &self,
        slot: usize,
        previous: &[u8; 32],
        maximum_transcript_bytes: usize,
    ) -> Result<RestoredSettledHistoryVerifierData, ProviderError> {
        self.ensure_validated()?;
        if maximum_transcript_bytes == 0 {
            return Err(invalid());
        }
        let key = self
            .validated_native_graph_data()?
            .historical_private_key17_data()?;
        let mut hash = blake3::Hasher::new_keyed(key);
        hash.update(b"crucible.source-restored-producer-history/1");
        hash.update(&slot.to_le_bytes());
        hash.update(previous);
        Ok(RestoredSettledHistoryVerifierData {
            hash,
            maximum: maximum_transcript_bytes,
            written: 0,
            failed: false,
        })
    }

    /// Compares the defining initial restored-suffix checkpoint signature.
    ///
    /// The Source streams the exact restoration, native and observation digests
    /// followed by its reached position in the defining binary order. This
    /// comparison exposes neither signing material nor a fresh checkpoint.
    ///
    /// # Errors
    /// Refuses an incomplete native/birth graph or an empty transcript ceiling.
    pub fn restored_suffix_seed_history_verifier_data(
        &self,
        maximum_transcript: usize,
    ) -> Result<RestoredSettledHistoryVerifierData, ProviderError> {
        self.history_verifier_data(
            b"aos.restored-suffix.initial-current.v1\0",
            maximum_transcript,
        )
    }

    /// Compares the Source's exact recurring-observation history transcript.
    ///
    /// The caller writes the defining original, terminal, restored proof and
    /// scheduling sequence. This verifier exposes no key or computed MAC and
    /// establishes no current native proof or live execution permission.
    ///
    /// # Errors
    /// Refuses an incomplete native/birth graph or an empty transcript ceiling.
    pub fn restored_current_observation_history_verifier_data(
        &self,
        ordinal: u64,
        previous: &[u8; 32],
        maximum_transcript: usize,
    ) -> Result<RestoredSettledHistoryVerifierData, ProviderError> {
        let mut verifier = self.history_verifier_data(
            b"aos.restored-suffix.current-observation.v1\0",
            maximum_transcript,
        )?;
        verifier.hash.update(&ordinal.to_le_bytes());
        verifier.hash.update(previous);
        Ok(verifier)
    }

    /// Compares the Source's exact post-confirmation administrative bridge.
    ///
    /// Source writes its defining complete tuple including both actual SDK
    /// pairs and the fourth native reference. A match authenticates historical
    /// bytes only; current World/Window and native receipt checks stay separate.
    ///
    /// # Errors
    /// Refuses an incomplete native/birth graph or an empty transcript ceiling.
    pub fn restored_capture_bridge_history_verifier_data(
        &self,
        maximum_transcript: usize,
    ) -> Result<RestoredSettledHistoryVerifierData, ProviderError> {
        self.history_verifier_data(
            b"crucible.source-restored-capture-admin-bridge/17",
            maximum_transcript,
        )
    }

    fn history_verifier_data(
        &self,
        domain: &'static [u8],
        maximum: usize,
    ) -> Result<RestoredSettledHistoryVerifierData, ProviderError> {
        self.ensure_validated()?;
        if maximum == 0 {
            return Err(invalid());
        }
        let key = self
            .validated_native_graph_data()?
            .historical_private_key17_data()?;
        let mut hash = blake3::Hasher::new_keyed(key);
        hash.update(domain);
        Ok(RestoredSettledHistoryVerifierData {
            hash,
            maximum,
            written: 0,
            failed: false,
        })
    }

    /// Counts all actual backing without counting this inline wrapper twice.
    ///
    /// # Errors
    /// Refuses incomplete internal state, invalid capacity/layout arithmetic
    /// or a separately admitted maximum smaller than the actual backing.
    pub fn retained_requested_storage_data(&self, maximum: usize) -> Result<usize, ProviderError> {
        self.ensure_validated()?;
        self.decoded.retained_requested_storage_data(maximum)
    }

    fn ensure_validated(&self) -> Result<(), ProviderError> {
        if !self.decoded.is_validated_data() {
            return Err(invalid());
        }
        Ok(())
    }
}

fn reference_string_data(
    reference: &mut ContentRef,
    field: usize,
) -> Result<&mut String, ProviderError> {
    match field {
        0 => Ok(&mut reference.hash.algorithm),
        1 => Ok(&mut reference.hash.domain),
        2 => Ok(&mut reference.hash.digest),
        3 => Ok(&mut reference.media_type),
        _ => Err(invalid()),
    }
}

/// Bounds concrete by-value outputs during lazy native decoder construction.
///
/// The retained heap slot is independently funded in R. This T window names the
/// `Option::None` output formed by the slot initializer, the native attempt's
/// `Default` output, and its `Option::Some` output before installation. Their
/// sum conservatively covers those constructor outputs without estimating
/// compiler-generated stack copies or retaining pure temporary DATA as state.
/// The two native cuts are constructed sequentially and reuse this T window.
pub const fn restored_settled_native17_decode_construction_transient_bytes_data() -> usize {
    use crate::protocol_snapshot::native_wholegraph17::NativeCurrentGraph17DecodeAttempt;
    std::mem::size_of::<Option<NativeCurrentGraph17DecodeAttempt>>()
        + std::mem::size_of::<NativeCurrentGraph17DecodeAttempt>()
        + std::mem::size_of::<Option<NativeCurrentGraph17DecodeAttempt>>()
}

pub(super) const fn counter_scratch_data() -> usize {
    use std::mem::size_of;
    size_of::<RestoredSettledNative17DecodeAttempt>()
        + size_of::<SealedHistoricalRestoredSettledNative17>()
        + graph_cache::counter_scratch_data()
        // The retained census walks immutable pairs and both actual graph banks.
        + size_of::<&RestoredSettledNative17DecodeAttempt>()
        + size_of::<std::slice::Iter<'static, (ContentRef, Vec<u8>)>>()
        + size_of::<(&ContentRef, &Vec<u8>)>()
        + size_of::<[&NativeGraph17DecodeCache; 2]>()
        + size_of::<std::array::IntoIter<&NativeGraph17DecodeCache, 2>>()
        + size_of::<&NativeGraph17DecodeCache>()
        + size_of::<[usize; 2]>()
        + size_of::<Option<usize>>()
        + size_of::<MetadataObserver<'static>>()
        + size_of::<crate::retained_metadata::RetainedProtocolMetadataFacts>()
        + size_of::<std::slice::Iter<'static, Option<ContentRef>>>()
        + size_of::<std::slice::Iter<'static, Vec<u8>>>()
        + size_of::<Option<&PacketSettledModel17Data>>()
        + size_of::<Result<usize, ProviderError>>()
        + size_of::<Result<(), ProviderError>>()
        + size_of::<RestoredSettledHistoryVerifierData>()
        + size_of::<Result<RestoredSettledHistoryVerifierData, ProviderError>>()
        + size_of::<std::io::Result<usize>>()
        + size_of::<std::io::Result<()>>()
        + size_of::<[&str; 4]>()
        + size_of::<std::iter::Enumerate<std::array::IntoIter<&str, 4>>>()
        + size_of::<Result<&mut String, ProviderError>>()
        + size_of::<[u8; std::mem::size_of::<usize>()]>()
}

// The enclosing Source row prices these actual independent Value and canonical
// banks. A fullref comparison never relabels an original body or reads a path.
fn authenticate_canonical_reference_data(
    value: &impl serde::Serialize,
    reference: &ContentRef,
) -> Result<(), ProviderError> {
    crate::connection::serialized_credit(value, 65_536)?;
    let value = serde_json::to_value(value).map_err(crucible_node_format::ContractError::from)?;
    let bytes = canonical::canonical_json(&value)?;
    if bytes.len() > 65_536 {
        return Err(invalid());
    }
    reference.verify(&bytes)?;
    Ok(())
}

/// Compares a bounded exact historical transcript without exposing a signing key.
///
/// Only a complete native17 owner can construct this inert comparison. It
/// implements `Write` for the same defining serde sequence as the original
/// Source; canonicalizing/reordering those fields would compare other bytes.
pub struct RestoredSettledHistoryVerifierData {
    hash: blake3::Hasher,
    maximum: usize,
    written: usize,
    failed: bool,
}

impl std::io::Write for RestoredSettledHistoryVerifierData {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if self.failed {
            return Err(std::io::Error::other(
                "native17 historical transcript failed",
            ));
        }
        self.failed = true;
        let next = self
            .written
            .checked_add(bytes.len())
            .filter(|next| *next <= self.maximum)
            .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::InvalidData))?;
        self.hash.update(bytes);
        self.written = next;
        self.failed = false;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        if self.failed {
            return Err(std::io::Error::other(
                "native17 historical transcript failed",
            ));
        }
        Ok(())
    }
}

impl RestoredSettledHistoryVerifierData {
    /// Compares only the supplied historical signature and consumes the verifier.
    ///
    /// # Errors
    /// Refuses an interrupted/empty transcript or a different exact MAC. The
    /// computed digest is not returned and cannot sign another history entry.
    pub fn verify_data(self, expected: &[u8; 32]) -> Result<(), ProviderError> {
        if self.failed || self.written == 0 || self.hash.finalize().as_bytes() != expected {
            return Err(invalid());
        }
        Ok(())
    }
}

// Both result families have independently authenticated the same complete native
// current graph. Only the cold family additionally requires final Source Journal.
pub(super) fn authenticate_current_checkpoint_data(
    decoded: &RestoredSettledNative17DecodeAttempt,
    restored: &PacketNativeRestoredRecord,
    underlying: &PacketNative5UnderlyingRecord,
    measurement: &ContentRef,
) -> Result<(), ProviderError> {
    restored.validate_data()?;
    measurement.validate()?;
    let before = decoded.before_native_graph.as_ref().ok_or_else(invalid)?;
    before.validate_data()?;
    let artifact = before
        .completed_data()
        .ok_or_else(invalid)?
        .current_capture_artifact17_data()?;
    artifact.validate_data()?;
    let request = &artifact.request;
    let receipt = &restored.native_receipt;
    let target = &request.scope.target;
    let initial = &request.scope.restoration;
    if &request.current_record != measurement
        || request.current_model != receipt.native_record
        || restored.physical_gate_held
        || restored.captured_owner_state != initial.captured_owner_state
        || restored.captured_journal != initial.captured_journal
        || restored.mapping != initial.mapping
        || restored.restore_commit != initial.commit_request
        || restored.restore_response != initial.commit_response
        || restored.context_digest != initial.context_digest
        || receipt.native_pid != target.native_pid
        || receipt.session != target.session
        || receipt.incarnation != target.incarnation
        || receipt.node != target.node
        || receipt.owner != target.owner
        || receipt.owner_generation != target.owner_generation
        || receipt.binding_hash != target.binding_hash
        || receipt.world != target.world
    {
        return Err(invalid());
    }
    authenticate_canonical_reference_data(restored, measurement)?;
    let original = match underlying {
        PacketNative5UnderlyingRecord::Producer(record) => {
            authenticate_canonical_reference_data(record.as_ref(), &receipt.native_record)?;
            if record.grant.is_some() {
                return Err(invalid());
            }
            &record.original
        }
        PacketNative5UnderlyingRecord::Reactive(record) => {
            authenticate_canonical_reference_data(record.as_ref(), &receipt.native_record)?;
            if record.grant.is_some() {
                return Err(invalid());
            }
            &record.original
        }
    };
    if original != &receipt.original {
        return Err(invalid());
    }
    let graph = decoded.native_graph.as_ref().ok_or_else(invalid)?;
    graph.validate_data()?;
    let model = graph
        .completed_data()
        .ok_or_else(invalid)?
        .current_model17_data()?;
    model.authenticate_current_data()?;
    model.authenticate_record_data(
        underlying,
        original,
        target.native_pid,
        crate::reference_packet::continuation_models::PacketModelRecordExpectation::FinalObservation,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn verifier(domain: &[u8], maximum: usize) -> RestoredSettledHistoryVerifierData {
        let mut hash = blake3::Hasher::new_keyed(&[19; 32]);
        hash.update(domain);
        RestoredSettledHistoryVerifierData {
            hash,
            maximum,
            written: 0,
            failed: false,
        }
    }

    #[test]
    fn reference_copy_retains_initialized_prefix_when_a_later_bank_refuses() {
        let reference = canonical::content_ref(b"{}", "application/json").unwrap();
        let mut attempt = RestoredSettledNative17DecodeAttempt::new();

        assert!(attempt.retain_reference_data(0, &reference, 64).is_err());
        let partial = attempt.references[0].as_ref().unwrap();
        assert_eq!(partial.hash.algorithm, reference.hash.algorithm);
        assert_eq!(partial.hash.domain, reference.hash.domain);
        assert!(partial.hash.digest.is_empty());
        assert!(partial.media_type.is_empty());
        assert!(attempt.retained_requested_storage_data(64).unwrap() > 0);
        assert!(attempt.retain_reference_data(0, &reference, 4096).is_err());
    }

    #[test]
    fn incomplete_native_seal_cannot_lend_prepare_or_normalization() {
        let reference = canonical::content_ref(b"{}", "application/json").unwrap();
        let mut decoded = RestoredSettledNative17DecodeAttempt::new();
        assert!(decoded.retain_reference_data(0, &reference, 64).is_err());
        let sealed = SealedHistoricalRestoredSettledNative17 { decoded };
        let before = sealed.decoded.retained_requested_storage_data(64).unwrap();

        assert!(sealed.restoration_prepare_request_data().is_err());
        assert!(sealed.archived_normalization_maximum_data().is_err());

        assert_eq!(
            sealed.decoded.retained_requested_storage_data(64).unwrap(),
            before
        );
        let partial = sealed.decoded.references[0].as_ref().unwrap();
        assert_eq!(partial.hash.algorithm, reference.hash.algorithm);
        assert_eq!(partial.hash.domain, reference.hash.domain);
        assert!(partial.hash.digest.is_empty());
        assert!(partial.media_type.is_empty());
    }

    #[test]
    fn historical_verifier_compares_exact_defining_domain_and_transcript() {
        let domain = b"aos.restored-suffix.initial-current.v1\0";
        let transcript = [7; 114];
        let mut expected = blake3::Hasher::new_keyed(&[19; 32]);
        expected.update(domain);
        expected.update(&transcript);
        let signature = *expected.finalize().as_bytes();

        let mut actual = verifier(domain, transcript.len());
        actual.write_all(&transcript[..32]).unwrap();
        actual.write_all(&transcript[32..]).unwrap();
        actual.verify_data(&signature).unwrap();

        let mut foreign = verifier(
            b"aos.restored-suffix.current-observation.v1\0",
            transcript.len(),
        );
        foreign.write_all(&transcript).unwrap();
        assert!(foreign.verify_data(&signature).is_err());
    }

    #[test]
    fn over_ceiling_write_permanently_refuses_even_the_prior_valid_prefix() {
        let domain = b"aos.restored-suffix.initial-current.v1\0";
        let mut expected = blake3::Hasher::new_keyed(&[19; 32]);
        expected.update(domain);
        expected.update(b"first");
        let signature = *expected.finalize().as_bytes();
        let mut actual = verifier(domain, 5);
        actual.write_all(b"first").unwrap();

        assert!(actual.write_all(b"extra").is_err());
        assert!(actual.write(b"").is_err());
        assert!(actual.flush().is_err());
        assert!(actual.verify_data(&signature).is_err());
    }

    #[test]
    fn empty_historical_transcript_cannot_validate_its_seed_digest() {
        let domain = b"aos.restored-suffix.initial-current.v1\0";
        let actual = verifier(domain, 1);
        let signature = *actual.hash.clone().finalize().as_bytes();

        assert!(actual.verify_data(&signature).is_err());
    }
}
