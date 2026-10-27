//! Shares complete protected preopen replay geometry as nonauthorizing DATA.
//!
//! Every private binding supplies its actual compiled replay, opening, error,
//! Source cache and history-control types. The recipe performs checked scalar
//! arithmetic only; it opens no file, creates no loan and admits no growth.

/// Defines complete preopen DATA using the caller's actual lexical type names.
///
/// The binding must provide JournalError, JournalLimits, RecordNamespace,
/// JournalRecord, NativePendingTransaction, ObservedReplayStateV1,
/// OriginalReleaseControllerCutCaptureV1, ProtectedWriterOpenOriginalsV1,
/// ReadOnlyProtectedJournal, RecoveryReport, ProtectedJournalLocation,
/// ReadOnlyJournalNameWitness, Frame, HEADER_BYTES, fs, io, source_history,
/// ordinary_reread, ResourceVector and D. Its validate_limits,
/// native_release_replay_work_v1 and semantic_representation_demand_v1 names
/// resolve directly to the existing complete compiled suppliers.
///
/// These are compile-time concrete bindings, not runtime callbacks or supplied
/// control-byte amounts. An extent remains writable comparison DATA; only its
/// genuine caller can join the actual captured prefix to its original payer.
/// The explicit arm accepts only compile-time concrete owner/error/control types
/// and the existing pure replay-control supplier path. Its type lists expand
/// directly into the same checked_add chain; no runtime header array, callback,
/// byte-count parameter, Result-returning adapter or supplied paid shape exists.
/// A native binding must list its actual native opening/cold/audit/model owners,
/// omit nonexistent success-return planes and retain all-family Source types.
///
#[macro_export]
macro_rules! define_protected_preopen_geometry_data_v1 {
    () => {
        $crate::define_protected_preopen_geometry_data_v1! {
            replay_before_control = [ObservedReplayStateV1, (Vec<JournalRecord>, NativePendingTransaction)],
            replay_control = ordinary_reread::receiving_control_bytes_v1,
            replay_after_control = [OriginalReleaseControllerCutCaptureV1],
            source_checkpoint = source_history::SourceOriginalChallengeCheckpointV5,
            source_cache = source_history::replay::SourceOriginalReplayCacheV5,
            native_owner = ProtectedWriterOpenOriginalsV1,
            native_first = Result<(ReadOnlyProtectedJournal, RecoveryReport), JournalError>,
            native_before_fixed = [
                Result<ObservedReplayStateV1, JournalError>,
                ProtectedJournalLocation, ReadOnlyJournalNameWitness, Frame,
                std::cell::Cell<bool>,
            ],
            native_after_fixed = [Result<fs::Metadata, io::Error>],
        }
    };
    (
        replay_before_control = [$($replay_before:ty),* $(,)?],
        replay_control = $replay_control:path,
        replay_after_control = [$($replay_after:ty),* $(,)?],
        source_checkpoint = $source_checkpoint:ty,
        source_cache = $source_cache:ty,
        native_owner = $native_owner:ty,
        native_first = $native_first:ty,
        native_before_fixed = [$($native_before:ty),* $(,)?],
        native_after_fixed = [$($native_after:ty),* $(,)?],
    ) => {
        /// Carries configured initial-replay representation DATA before a protected open.
        ///
        /// These separate terms describe logical bytes and inline representations, not
        /// allocator RAM, a service budget, a paid loan, or permission to open. They may
        /// overcount shared storage. Every consumer must also cover [`Self::unpriced`]
        /// before treating an aggregate as a prepaid service extent.
        #[cfg(target_os = "linux")]
        #[derive(Clone, Copy, Debug, Eq, PartialEq)]
        pub struct ProtectedJournalPreopenReplayExtentV1 {
            /// Preserves the exact limits supplied to the native opener.
            pub limits: JournalLimits,
            /// Bounds the configured native prefix; this is disk input, not heap storage.
            pub native_bytes: u64,
            /// Reuses the original Release replay's logical map, frame and owner charge.
            pub native_replay_representation_bytes: usize,
            /// Identifies the physical-clipped pending term already included above.
            ///
            /// A complete initial receiving demand replaces this term with
            /// `declared_pending_record_bytes`; it does not omit the full BEGIN reserve.
            pub clipped_native_pending_record_bytes: usize,
            /// Covers reached frame Vec capacity plus the shared fixed read scratch.
            ///
            /// The incremental frame reader grows only after bytes are read; the full
            /// advertised payload is a wire limit, not an absent-byte allocation.
            pub native_frame_read_memory_bytes: usize,
            /// Preserves the unchanged advertised frame payload wire ceiling.
            pub maximum_advertised_payload_bytes: usize,
            /// Covers the full BEGIN reservation, irrespective of physical frame count.
            pub declared_pending_record_bytes: usize,
            /// Covers insertion of one extra transaction ID before count refusal.
            pub reached_transaction_id_bytes: usize,
            /// Covers intermediate map cells before all transaction deletions apply.
            pub reached_materialized_cell_bytes: usize,
            /// Bounds committed transactions reached before the count check can refuse.
            pub source_transactions: usize,
            /// Covers conservative inline cache copies, including the pending marker.
            pub source_cache_copies: usize,
            /// Bounds original checkpoint rows from this configured native file.
            pub source_checkpoint_rows: usize,
            /// Covers this file's original checkpoint rows and one independent copy.
            pub source_checkpoint_representation_bytes: usize,
            /// Covers initial cache owners whose physical-history collections stay empty.
            pub source_cache_metadata_bytes: usize,
            /// Covers inline native opener, replay, metadata, result and error owners.
            pub native_owner_result_bytes: usize,
            /// Requires independent bounds for all representations not priced here.
            pub unpriced: ProtectedJournalPreopenUnpricedPrerequisitesV1,
        }

        /// Identifies obligations that configured journal limits alone cannot price.
        ///
        /// Collection spare capacity, BTree nodes, Arc control blocks and allocator
        /// overhead need separate conservative service provision and physical backstops.
        /// Decoder/validator temporaries and owning error payloads need their own bounds,
        /// as do native descriptors, kernel state, path/name allocations and service work.
        /// The parser checks initial file metadata, so growing input needs independently
        /// enforced containment or a stable-prefix prerequisite. Initial replay has no
        /// external challenge witness; the legacy marker name does not add the separate
        /// later replay's external-history demand to this phase.
        ///
        /// The ordinary read-only opener drops its local files and partial replay on
        /// failure. This marker neither retains those locals nor changes their lifetime.
        #[cfg(target_os = "linux")]
        #[derive(Clone, Copy, Debug, Eq, PartialEq)]
        pub enum ProtectedJournalPreopenUnpricedPrerequisitesV1 {
            /// Requires conservative allocator, decoder/error and native/containment bounds.
            AllocatorDecoderErrorsNativePathsAndExternalChallenges,
        }

        /// Computes replay representation DATA for an already captured physical prefix.
        ///
        /// The caller retains the genuine original metadata and bounds its reader to
        /// this same length. A scalar alone authenticates neither that prefix nor a
        /// payer. BEGIN count storage retains its full configured maximum independently
        /// of the prefix; frame Vec capacity follows reached bytes plus fixed scratch.
        ///
        /// # Errors
        /// Rejects invalid limits, an excessive captured prefix, or checked overflow.
        #[cfg(target_os = "linux")]
        pub fn protected_journal_preopen_replay_extent_for_prefix_v1(
            limits: JournalLimits,
            native_prefix_bytes: u64,
        ) -> Result<ProtectedJournalPreopenReplayExtentV1, JournalError> {
            validate_limits(limits)?;
            let limit = || JournalError::LimitExceeded("protected journal pre-open replay extent");
            if native_prefix_bytes > limits.maximum_journal_bytes {
                return Err(JournalError::JournalTooLarge);
            }
            let physical = usize::try_from(native_prefix_bytes).map_err(|_| limit())?;
            let frames = physical / HEADER_BYTES;
            let source_transactions = limits.maximum_transactions.checked_add(1)
                .ok_or_else(limit)?.min(frames);
            let source_checkpoint_rows = frames;
            let source_cache_copies = 3_usize;
            let map_entry = std::mem::size_of::<((RecordNamespace, Vec<u8>), Vec<u8>)>();

            // BEGIN reserves its bounded declared count before reading its records.
            // The shared frame reader instead grows only after actual bytes arrive;
            // its reached Vec capacity and fixed read scratch are already in Native work.
            let native_work = native_release_replay_work_v1(physical, limits)?;
            let native_replay_representation_bytes = native_work.replay_indexes
                .checked_add(native_work.pending_records)
                .and_then(|bytes| bytes.checked_add(native_work.frame_payload))
                $(.and_then(|bytes| bytes.checked_add(std::mem::size_of::<$replay_before>())))*
                .and_then(|bytes| bytes.checked_add($replay_control()?))
                $(.and_then(|bytes| bytes.checked_add(std::mem::size_of::<$replay_after>())))*
                .ok_or_else(limit)?;
            let maximum_advertised_payload_bytes = limits.maximum_record_bytes.checked_add(7).ok_or_else(limit)?;
            let declared_pending_record_bytes = limits.maximum_records_per_transaction
                .checked_mul(std::mem::size_of::<JournalRecord>()).ok_or_else(limit)?;
            let reached_transaction_id_bytes = std::mem::size_of::<[u8; 16]>();
            let reached_materialized_cell_bytes = limits.maximum_records_per_transaction
                .checked_mul(map_entry).and_then(|bytes| bytes.checked_mul(2)).ok_or_else(limit)?;

            // This runs independently of the optional external challenge witness.
            // Retain its committed-frame rows even when Source replay remains pending.
            let source_checkpoint_representation_bytes = source_checkpoint_rows
                .checked_mul(std::mem::size_of::<$source_checkpoint>())
                .and_then(|bytes| bytes.checked_add(physical))
                .and_then(|bytes| bytes.checked_mul(2)).ok_or_else(limit)?;
            // replay_transaction(None) returns before origins, cuts, retirements or
            // their maps are retained. observe_compaction likewise only sets pending;
            // its temporary prospective map remains in the native replay allowance.
            let source_cache_metadata_bytes = std::mem::size_of::<$source_cache>()
                .checked_mul(source_cache_copies)
                .ok_or_else(limit)?;

            // Price simultaneous inline representations conservatively. Ordinary
            // recovery still transfers its maps and drops its failure locals unchanged.
            let native_owner_result_bytes = std::mem::size_of::<$native_owner>()
                .checked_add(std::mem::size_of::<$native_first>())
                $(.and_then(|bytes| bytes.checked_add(std::mem::size_of::<$native_before>())))*
                .and_then(|bytes| bytes.checked_add(HEADER_BYTES))
                $(.and_then(|bytes| bytes.checked_add(std::mem::size_of::<$native_after>())))*
                .ok_or_else(limit)?;

            Ok(ProtectedJournalPreopenReplayExtentV1 {
                limits,
                native_bytes: native_prefix_bytes,
                native_replay_representation_bytes,
                clipped_native_pending_record_bytes: native_work.pending_records,
                native_frame_read_memory_bytes: native_work.frame_payload,
                maximum_advertised_payload_bytes,
                declared_pending_record_bytes,
                reached_transaction_id_bytes,
                reached_materialized_cell_bytes,
                source_transactions,
                source_cache_copies,
                source_checkpoint_rows,
                source_checkpoint_representation_bytes,
                source_cache_metadata_bytes,
                native_owner_result_bytes,
                unpriced: ProtectedJournalPreopenUnpricedPrerequisitesV1::AllocatorDecoderErrorsNativePathsAndExternalChallenges,
            })
        }

        impl ProtectedJournalPreopenReplayExtentV1 {
            /// Prices the common Native replay representations without clipping EOF work.
            ///
            /// Release work contains physical-clipped pending records but already
            /// includes the shared incremental reader's reached Vec capacity and fixed
            /// scratch. BEGIN can reserve its complete declared count before EOF, so
            /// only that pending term is replaced with its independent full maximum.
            /// Absent advertised payload bytes receive no allocation or semantic charge.
            /// Reached map/checkpoint owners remain separately priced.
            ///
            /// Only an extent borrowed from the actual staged original can be joined
            /// to a payer. Writable DATA fields and this calculation create no authority.
            /// Semantic decoded models and collections need their own conservative
            /// shape allowance. Strict parsers and the genuine service cgroup back
            /// residual allocator metadata and kernel/page-cache overhead (RFC-0006).
            ///
            /// # Errors
            /// Refuses inconsistent clipped terms, checked overflow, or an extent whose
            /// complete logical receiving terms cannot be represented by the vector.
            pub fn dominant_native_receiving_demand_v1(&self) -> Result<ResourceVector, JournalError> {
                let invalid = || JournalError::LimitExceeded("native receiving replay demand");
                let physical = usize::try_from(self.native_bytes).map_err(|_| invalid())?;
                let advertised = self.limits.maximum_record_bytes.checked_add(7).ok_or_else(invalid)?;
                let frame = aos_sandbox_journal::framing::reached_frame_read_memory_bound_v1(
                    advertised, physical,
                ).map_err(|_| invalid())?;
                if self.clipped_native_pending_record_bytes > self.declared_pending_record_bytes
                    || self.maximum_advertised_payload_bytes != advertised
                    || self.native_frame_read_memory_bytes != frame
                    || self.native_replay_representation_bytes < frame
                {
                    return Err(invalid());
                }
                let memory = self.native_replay_representation_bytes
                    .checked_sub(self.clipped_native_pending_record_bytes)
                    .and_then(|bytes| bytes.checked_add(self.declared_pending_record_bytes))
                    .and_then(|bytes| bytes.checked_add(self.reached_transaction_id_bytes))
                    .and_then(|bytes| bytes.checked_add(self.reached_materialized_cell_bytes))
                    .and_then(|bytes| bytes.checked_add(self.source_checkpoint_representation_bytes))
                    .and_then(|bytes| bytes.checked_add(self.source_cache_metadata_bytes))
                    .and_then(|bytes| bytes.checked_add(self.native_owner_result_bytes))
                    .ok_or_else(invalid)?;
                let memory = u64::try_from(memory).map_err(|_| invalid())?;
                let metadata = self.source_checkpoint_rows.checked_mul(2)
                    .and_then(|count| count.checked_add(self.source_transactions))
                    .and_then(|count| count.checked_add(self.limits.maximum_records_per_transaction))
                    .and_then(|count| count.checked_add(1)).ok_or_else(invalid)?;
                Ok(ResourceVector::ZERO
                    .with(D::MemoryBytes, memory)
                    .with(D::MetadataEntries, u64::try_from(metadata).map_err(|_| invalid())?))
            }
        }

        impl ProtectedJournalPreopenReplayExtentV1 {
            /// Prices initial replay's canonical models, graph copies and encoded work.
            ///
            /// A completed semantic record needs a complete native header. The actual
            /// held prefix therefore bounds possible rows even for malformed history;
            /// a BEGIN or partial payload receives no semantic expansion until a full
            /// frame exists. The shared Native demand separately prices those complete
            /// advertised negative reservations, including at an empty prefix.
            ///
            /// Thirty-two simultaneous row slots conservatively cover the live and
            /// prospective maps, capacity-family vectors, Root canonical and legacy
            /// graphs, optional v1 diagnostics, the two reconstructed cuts, response
            /// projection, rederived transition maps and their comparison/key sets.
            /// The largest relevant row includes the fixed twelve-control, three-section
            /// nested archive geometry. Source initial replay has no external challenge
            /// history and does not enter its separate physical-history cache path.
            ///
            /// The 128 encoded copies cover owned byte/string collections, geometric
            /// spare capacity, JSON/hex reencoding, nested canonical archives and the
            /// simultaneous graph/prospective/transition copies. Binary catalog and
            /// inventory decoders check complete count-derived byte lengths before
            /// allocation; native suffix counts and sections have fixed 12/3 limits.
            /// Strict decoder limits and the genuine service cgroup cover residual
            /// parser, allocator metadata, page faults and kernel residency (RFC-0006).
            ///
            /// This intentionally refuses some large native histories under a smaller
            /// whole-service envelope. It never selects a cheaper parser or drops an
            /// existing namespace, validator, recovery rule or first cause.
            ///
            /// # Errors
            /// Rejects inconsistent bounds or checked representation overflow.
            pub fn dominant_semantic_receiving_demand_v1(&self) -> Result<ResourceVector, JournalError> {
                let invalid = || JournalError::LimitExceeded("native semantic receiving demand");
                if self.native_bytes > self.limits.maximum_journal_bytes {
                    return Err(invalid());
                }
                let physical = usize::try_from(self.native_bytes).map_err(|_| invalid())?;
                let rows = physical.checked_div(HEADER_BYTES).ok_or_else(invalid)?;
                semantic_representation_demand_v1(physical, rows)
            }
        }
    };
}
