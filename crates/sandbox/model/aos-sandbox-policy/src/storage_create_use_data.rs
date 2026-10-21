//! Shares Create U comparison geometry without native ownership.
//!
//! The Security layout is passive DATA from the existing installed supplier.
//! The lexical recipe preserves each caller's concrete full replay and native
//! layout suppliers; it cannot issue a receiving permit or complete a role.

/// Describes actual private compiled Security owners without granting a loan.
///
/// Both real peers obtain the same value from the installed Security supplier.
/// Rust field/control storage is bytes; these values are not namespace entries.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StorageCreateUseSecurityShapeDataV1 {
    /// The actual retained private flight's compiled inline width.
    pub actual_flight_bytes: usize,
    /// Actual construction/disposal overlap beyond its resident destination.
    pub actual_construction_bytes: usize,
    /// Additional retained native/replay error and temporary backing bytes.
    pub actual_failure_bytes: usize,
    /// Actual native endpoint destinations retained by the three private capsules.
    pub actual_endpoint_open_files: usize,
}

/// Expands the existing Controller profile-row comparison calculation.
///
/// The fixed 64 KiB materialization bound belongs to the existing Controller
/// observer. Both underlying archive calculations remain in Broker. Error
/// projections are lexical expressions at their original row and multiplication
/// frontiers; no observer, account, role loan or receiving permit is constructed.
#[macro_export]
macro_rules! define_storage_create_use_profile_rows_v1 {
    (
        $visibility:vis fn $name:ident,
        error = $error:ty,
        row_error = $row_error:expr,
        multiply_error = $multiply_error:expr $(,)?
    ) => {
        $visibility fn $name(
            rows: usize,
        ) -> Result<aos_sandbox_model::ResourceVector, $error> {
            let row = aos_sandbox_broker::receiving::growing_fixed_property_archive_demand_v1(
                64 * 1024,
            ).map_err($row_error)?;
            aos_sandbox_broker::receiving::FixedPropertyArchiveV1::
                multiply_receiving_demand_data_v1(row, rows).map_err($multiply_error)
        }
    };
}

/// Expands the complete existing prefix, continuation and signing calculations.
///
/// Every supplier is a concrete lexical path, with no runtime callback or
/// authority trait. Callers bind the actual full Session/Controller extent,
/// compiled Security shape and native component suppliers at their old slots.
/// The incomplete prefix remains incomplete; no supplied vector proves payment.
#[macro_export]
macro_rules! define_storage_create_use_receiving_v1 {
    (
        ResourceVector = $ResourceVector:ident,
        D = $D:ident,
        RecordShape = $RecordShape:ident,
        ProtectedJournalPreopenReplayExtentV1 = $ProtectedJournalPreopenReplayExtentV1:ident,
        StorageSessionGeometryRefusalV1 = $StorageSessionGeometryRefusalV1:ident,
        StorageCreateUseSecurityShapeDataV1 = $StorageCreateUseSecurityShapeDataV1:ident,
        storage_create_use_prefix_receiving_demand_v1 = $storage_create_use_prefix_receiving_demand_v1:ident,
        storage_create_use_receiving_demand_v1 = $storage_create_use_receiving_demand_v1:ident,
        storage_create_use_signing_receiving_demand_v1 = $storage_create_use_signing_receiving_demand_v1:ident,
        invalid = $invalid:path,
        add = $add:path,
        sum = $sum:path,
        checked_prefix = $checked_prefix:path,
        as_u64 = $as_u64:path,
        response_packet_bytes = $response_packet_bytes:path,
        encoded_transaction_append_bytes = $encoded_transaction_append_bytes:path,
        storage_create_prepare_client_request_demand_v1 = $storage_create_prepare_client_request_demand_v1:path,
        storage_create_prepare_client_positive_outcome_demand_v1 = $storage_create_prepare_client_positive_outcome_demand_v1:path,
        storage_retained_current_replay_demand_v1 = $storage_retained_current_replay_demand_v1:path,
        storage_retained_traffic_reconstruction_demand_v1 = $storage_retained_traffic_reconstruction_demand_v1:path,
        schema_demand = $schema_demand:path,
        full_preopen = $full_preopen:path,
        names = $names:path,
        preparation_io = $preparation_io:path,
        cache_fixed = $cache_fixed:path,
        cache_dynamic = $cache_dynamic:path,
        producer_traffic = $producer_traffic:path,
        preparation_originals = $preparation_originals:path,
        root_tail = $root_tail:path,
        history_pair = $history_pair:path,
        profile_rows = $profile_rows:path,
        commit = $commit:path,
        held_release = $held_release:path,
        signing_originals = $signing_originals:path,
    ) => {
        use aos_sandbox_protocol::authenticated_session::all_methods::{
            request_capture::AuthenticatedBrokerMethodRequestCaptureV1,
            outcome_capture::AuthenticatedBrokerMethodOutcomeCaptureV1,
        };
        use aos_sandbox_protocol::domain_ledger::resource_bank::{ACCOUNT_HEAD_BYTES_V1,
            CLAIM_BYTES_V1, CREATE_STORAGE_USE_BINDING_BYTES_V1};
        use aos_sandbox_protocol::domain_ledger::create_storage_history::{HEAD_BYTES,
            KEY_BYTES, transport::FRAME_HEADER_BYTES,
            use_reserved::{ROOT_VALIDATED_RECORD_BYTES_V1, USE_RESERVED_RECORD_BYTES_V1,
                USE_RESERVED_RECEIPT_BYTES_V1, USE_CURRENT_PROOFS_BYTES_V1}};

        /// Prices the current concrete use prefix without completing the U ceiling.
        ///
        /// Session/Controller prefixes come from the genuine held owners; the five
        /// Cache extents come from the same completed held/current receipt supplier.
        /// Request width is the common normalized nonissuing Prepare shape. The real
        /// issuer independently compares originals and the FINAL complete requirement
        /// before any purpose15 reservation. This passive function admits no work.
        ///
        /// # Errors
        /// Rejects invalid actual prefixes/widths or checked representation overflow.
        pub fn $storage_create_use_prefix_receiving_demand_v1(
            session_extent: &$ProtectedJournalPreopenReplayExtentV1,
            request_shape_bytes: usize,
            controller_extent: &$ProtectedJournalPreopenReplayExtentV1,
            cache_extents: &[aos_sandbox_broker::canonical_journal::CanonicalReplayExtentDataV1; 5],
            private: $StorageCreateUseSecurityShapeDataV1,
        ) -> Result<$ResourceVector, $StorageSessionGeometryRefusalV1> {
            if private.actual_flight_bytes == 0 { return Err($invalid()); }
            let request = $storage_create_prepare_client_request_demand_v1(session_extent, request_shape_bytes)?;
            let outcome = $storage_create_prepare_client_positive_outcome_demand_v1(session_extent, request_shape_bytes)?;
            let growth = $add(request.get($D::StorageBytes), outcome.get($D::StorageBytes))?;
            let future = $full_preopen(
                session_extent.limits, $add($checked_prefix(session_extent)?, growth)?,
            ).map_err(|_| $invalid())?;
            let p = usize::try_from($checked_prefix(&future)?).map_err(|_| $invalid())?;
            let one_replay = $storage_retained_current_replay_demand_v1(&future)?
                .checked_add($storage_retained_traffic_reconstruction_demand_v1(&future)?)
                .map_err(|_| $invalid())?
                .checked_add(AuthenticatedBrokerMethodOutcomeCaptureV1::dynamic_receiving_demand_v1(p)
                    .ok_or_else($invalid)?).map_err(|_| $invalid())?;
            let terminal_readback = $schema_demand(&future)?;
            let method = AuthenticatedBrokerMethodRequestCaptureV1::dynamic_receiving_demand_v1(p)
                .ok_or_else($invalid)?;
            let mut complete = request.checked_add(outcome).map_err(|_| $invalid())?;
            // Before signing, before send and after authenticated terminal each retain
            // their complete canonical predecessor. This uses the forecast actual
            // positive successor width, never an absent maximum-size native history.
            for _ in 0..3 { complete = complete.checked_add(one_replay).map_err(|_| $invalid())?; }
            complete = complete.checked_add(method).map_err(|_| $invalid())?;
            complete = complete.checked_add(terminal_readback).map_err(|_| $invalid())?;
            let names = $names().map_err(|_| $invalid())?;
            complete = complete.checked_add(names).map_err(|_| $invalid())?.checked_add(names).map_err(|_| $invalid())?;

            complete = complete.checked_add($storage_create_use_signing_receiving_demand_v1(
                request_shape_bytes, private,
            )?).map_err(|_| $invalid())?;
            complete = complete.checked_add($preparation_io().map_err(|_| $invalid())?)
                .map_err(|_| $invalid())?;

            complete = complete.checked_add($cache_fixed().map_err(|_| $invalid())?)
                .map_err(|_| $invalid())?.checked_add($cache_dynamic(cache_extents).map_err(|_| $invalid())?)
                .map_err(|_| $invalid())?;

            let (wire, logs) = $producer_traffic(7).ok_or_else($invalid)?;
            complete = complete.checked_add($ResourceVector::ZERO
                .with($D::NetworkBytes, wire).with($D::LogBytes, logs)).map_err(|_| $invalid())?;

            let pair = |record| $encoded_transaction_append_bytes([
                $RecordShape { key_bytes: KEY_BYTES, value_bytes: Some(record) },
                $RecordShape { key_bytes: KEY_BYTES, value_bytes: Some(HEAD_BYTES) },
            ].into_iter()).map_err(|_| $invalid());
            let reserve = $encoded_transaction_append_bytes([
                $RecordShape { key_bytes: 17, value_bytes: Some(ACCOUNT_HEAD_BYTES_V1) },
                $RecordShape { key_bytes: 17, value_bytes: Some(CLAIM_BYTES_V1) },
                $RecordShape { key_bytes: 17, value_bytes: Some(CREATE_STORAGE_USE_BINDING_BYTES_V1) },
            ].into_iter()).map_err(|_| $invalid())?;
            let commit = $encoded_transaction_append_bytes([
                $RecordShape { key_bytes: 17, value_bytes: Some(ACCOUNT_HEAD_BYTES_V1) },
                $RecordShape { key_bytes: 17, value_bytes: Some(CLAIM_BYTES_V1) },
            ].into_iter()).map_err(|_| $invalid())?;
            // Controller extent denotes the actual InputsReady cut on BOTH peers.
            // RootValidated is an exact typed forecast here, actual returned position
            // at C; later Signed/terminal rows must be added by their format providers.
            let controller_growth = $sum(&[pair(ROOT_VALIDATED_RECORD_BYTES_V1)?, reserve,
                pair(USE_RESERVED_RECORD_BYTES_V1)?, commit])?;
            let controller = $full_preopen(
                controller_extent.limits, $add(controller_extent.native_bytes, controller_growth)?,
            ).map_err(|_| $invalid())?;
            let replay = controller.dominant_native_receiving_demand_v1().map_err(|_| $invalid())?
                .checked_add(controller.dominant_semantic_receiving_demand_v1().map_err(|_| $invalid())?)
                .map_err(|_| $invalid())?;
            // Independent reserve and final positive-commit readbacks coexist. Map and
            // parser overhead use the common dominant recipe, not symbolic Result fees.
            complete = complete.checked_add(replay).map_err(|_| $invalid())?
                .checked_add(replay).map_err(|_| $invalid())?;
            let frames = USE_RESERVED_RECEIPT_BYTES_V1.checked_add(USE_CURRENT_PROOFS_BYTES_V1)
                .and_then(|n| n.checked_add(2 * FRAME_HEADER_BYTES)).ok_or_else($invalid)?;
            let packet = $response_packet_bytes($as_u64(aos_sandbox_protocol::semantics::storage_prepare::
                storage_catalog_preparation_response_body_bound_v1())?)?;
            complete.checked_add($ResourceVector::ZERO
                .with($D::StorageBytes, $add(reserve, $add(pair(USE_RESERVED_RECORD_BYTES_V1)?, commit)?)?)
                .with($D::MetadataEntries, 3)
                .with($D::NetworkBytes, $sum(&[$as_u64(frames)?, $as_u64(request_shape_bytes)?, packet])?)
                .with($D::OutputBytes, $add($as_u64(frames)?, $as_u64(request_shape_bytes)?)?))
                .map_err(|_| $invalid())
        }

        /// Prices the complete owned Create U continuation without issuing authority.
        ///
        /// Both real peers independently supply the same held Session and InputsReady
        /// extents, normalized full request width, five actual Cache extents and actual
        /// compiled Security layout. The genuine issuer must still match every original
        /// and compare this whole amount before reserve. Root's own independent reads,
        /// compiler and signer-side F are separately funded; this prices the Controller
        /// continuation through its positive U commit and complete terminal transport.
        ///
        /// Clean selected-C Producer scopes retain their own real C admission and
        /// dispose positive scratch before reuse. Their cumulative traffic is included
        /// by the concrete tail supplier; no per-byte intake archive is fabricated.
        /// The conservative full fragmentation traffic is intentional. An insufficient
        /// configured bank refuses; this helper does not shrink traffic or raise caps.
        ///
        /// # Errors
        /// Rejects invalid actual prefixes, zero or overflowing request shape, native
        /// record/prefix bounds, unavailable compiled suppliers or checked arithmetic.
        pub fn $storage_create_use_receiving_demand_v1(
            session_extent: &$ProtectedJournalPreopenReplayExtentV1,
            request_shape_bytes: usize,
            controller_extent: &$ProtectedJournalPreopenReplayExtentV1,
            source_extent: &$ProtectedJournalPreopenReplayExtentV1,
            cache_extents: &[aos_sandbox_broker::canonical_journal::CanonicalReplayExtentDataV1; 5],
            private: $StorageCreateUseSecurityShapeDataV1,
        ) -> Result<$ResourceVector, $StorageSessionGeometryRefusalV1> {
            use aos_sandbox_protocol::domain_ledger::create_storage_history::{
                RECORD_OVERHEAD_BYTES,
                continuation::SIGNED_PREPARATION_PREFIX_BYTES_V1,
                controller_use::{SIGNED_BODY_PREFIX_BYTES_V1, DISPATCH_BOUND_BODY_BYTES_V1,
                    SESSION_RESERVED_BODY_BYTES_V1},
                outcome::{CONTROLLER_OUTCOME_RECORD_BYTES_V1, HANDOFF_RETAINED_RECORD_BYTES_V1},
            };
            use aos_sandbox_protocol::domain_ledger::resource_bank::PhysicalHistory;

            if request_shape_bytes == 0 { return Err($invalid()); }
            let mut complete = $storage_create_use_prefix_receiving_demand_v1(
                session_extent, request_shape_bytes, controller_extent, cache_extents, private,
            )?;
            complete = complete.checked_add($preparation_originals()
                .map_err(|_| $invalid())?).map_err(|_| $invalid())?;
            let tail = $root_tail(request_shape_bytes)
                .map_err(|_| $invalid())?;

            // The prefix already counted frames6/7. The concrete tail now owns their
            // entire stream grammar, including both invitations and every later frame.
            let repeated_frames = USE_RESERVED_RECEIPT_BYTES_V1.checked_add(USE_CURRENT_PROOFS_BYTES_V1)
                .and_then(|bytes| bytes.checked_add(2 * FRAME_HEADER_BYTES)).ok_or_else($invalid)?;
            complete = complete.checked_sub($ResourceVector::ZERO
                .with($D::NetworkBytes, $as_u64(repeated_frames)?)).map_err(|_| $invalid())?;
            complete = complete.checked_add(tail.receiving).map_err(|_| $invalid())?;

            let signed = request_shape_bytes.checked_mul(3)
                .and_then(|bytes| bytes.checked_add(SIGNED_PREPARATION_PREFIX_BYTES_V1))
                .and_then(|bytes| bytes.checked_add(SIGNED_BODY_PREFIX_BYTES_V1))
                .and_then(|bytes| bytes.checked_add(RECORD_OVERHEAD_BYTES)).ok_or_else($invalid)?;
            let records = [USE_RESERVED_RECORD_BYTES_V1, signed,
                RECORD_OVERHEAD_BYTES.checked_add(DISPATCH_BOUND_BODY_BYTES_V1).ok_or_else($invalid)?,
                RECORD_OVERHEAD_BYTES.checked_add(SESSION_RESERVED_BODY_BYTES_V1).ok_or_else($invalid)?,
                CONTROLLER_OUTCOME_RECORD_BYTES_V1, HANDOFF_RETAINED_RECORD_BYTES_V1];
            let pair = |record| $encoded_transaction_append_bytes([
                $RecordShape { key_bytes: KEY_BYTES, value_bytes: Some(record) },
                $RecordShape { key_bytes: KEY_BYTES, value_bytes: Some(HEAD_BYTES) },
            ].into_iter()).map_err(|_| $invalid());
            let bank_pair = |binding| {
                if binding {
                    $encoded_transaction_append_bytes([
                        $RecordShape { key_bytes: 17, value_bytes: Some(ACCOUNT_HEAD_BYTES_V1) },
                        $RecordShape { key_bytes: 17, value_bytes: Some(CLAIM_BYTES_V1) },
                        $RecordShape { key_bytes: 17, value_bytes: Some(CREATE_STORAGE_USE_BINDING_BYTES_V1) },
                    ].into_iter()).map_err(|_| $invalid())
                } else {
                    $encoded_transaction_append_bytes([
                        $RecordShape { key_bytes: 17, value_bytes: Some(ACCOUNT_HEAD_BYTES_V1) },
                        $RecordShape { key_bytes: 17, value_bytes: Some(CLAIM_BYTES_V1) },
                    ].into_iter()).map_err(|_| $invalid())
                }
            };
            let reserve = bank_pair(true)?;
            let commit = bank_pair(false)?;
            let mut controller_growth = $sum(&[pair(ROOT_VALIDATED_RECORD_BYTES_V1)?, reserve, commit])?;
            for record in records { controller_growth = $add(controller_growth, pair(record)?)?; }
            let future = $full_preopen(
                controller_extent.limits, $add($checked_prefix(controller_extent)?, controller_growth)?,
            ).map_err(|_| $invalid())?;
            let semantic = future.dominant_semantic_receiving_demand_v1().map_err(|_| $invalid())?;

            // Actual UseReserved immediately uses this same fixed/pair/semantic recipe.
            // Each subsequent once-only pair retains its own record and owed posts.
            // Compiled controls are bytes; real semantic-map/index cardinalities and
            // the six new historical rows retain their separate namespace budgets.
            let old_pair = pair(USE_RESERVED_RECORD_BYTES_V1)?;
            complete = complete.checked_sub($ResourceVector::ZERO
                .with($D::StorageBytes, old_pair).with($D::MetadataEntries, 1))
                .map_err(|_| $invalid())?;
            for record in records {
                complete = complete.checked_add($history_pair(record, &semantic)
                        .map_err(|_| $invalid())?).map_err(|_| $invalid())?;
            }
            // Three profile comparisons per pair, each using two actual retained rows.
            // This is the real intake archive route, distinct from clean operation
            // Producer scopes. Its buffer recipe is shared with actual grow admission.
            let rows = records.len().checked_mul(6).ok_or_else($invalid)?;
            complete = complete.checked_add($profile_rows(rows).map_err(|_| $invalid())?)
                .map_err(|_| $invalid())?;

            // Extend both bank readback ceilings to the complete actual Controller tail.
            // The prefix's earlier forecast already paid reserve/commit representation;
            // only the checked increment is added, avoiding unrelated spare credit.
            let old_growth = $sum(&[pair(ROOT_VALIDATED_RECORD_BYTES_V1)?, reserve,
                pair(USE_RESERVED_RECORD_BYTES_V1)?, commit])?;
            let old = $full_preopen(
                controller_extent.limits, $add($checked_prefix(controller_extent)?, old_growth)?,
            ).map_err(|_| $invalid())?;
            let replay = |extent: &$ProtectedJournalPreopenReplayExtentV1| {
                extent.dominant_native_receiving_demand_v1().map_err(|_| $invalid())?
                    .checked_add(extent.dominant_semantic_receiving_demand_v1().map_err(|_| $invalid())?)
                    .map_err(|_| $invalid())
            };
            let increment = replay(&future)?.checked_sub(replay(&old)?).map_err(|_| $invalid())?;
            complete = complete.checked_add(increment).map_err(|_| $invalid())?
                .checked_add(increment).map_err(|_| $invalid())?;

            // Each existing canonical binding occupies at least168 native value bytes.
            // The new reservation adds one. Native still admits its actual-state helper
            // before observing real physical progress; this forecast creates no entry.
            let count = usize::try_from($checked_prefix(controller_extent)? /
                $as_u64(CREATE_STORAGE_USE_BINDING_BYTES_V1)?).map_err(|_| $invalid())?
                .checked_add(1).ok_or_else($invalid)?;
            let progress = PhysicalHistory::additional_use_receiving_demand_for_count_v1(count)
                .map_err(|_| $invalid())?;
            complete = complete.checked_add(progress).map_err(|_| $invalid())?
                .checked_add(progress).map_err(|_| $invalid())?;
            complete = complete.checked_add($commit()
                .map_err(|_| $invalid())?).map_err(|_| $invalid())?;
            complete = complete.checked_add($held_release(
                source_extent, cache_extents).map_err(|_| $invalid())?).map_err(|_| $invalid())?;

            // Six C rows and the U claim/binding were counted at their actual append
            // suppliers. Keep every additional resident map/index/catalog/pathname
            // cardinality from the complete lower recipes; these are not Rust fields.
            Ok(complete)
        }

        /// Prices the actual once-only Controller signing phase without granting it.
        ///
        /// The same final U recipe and genuine Root8 signing admission delegate here.
        /// The concrete Security shape comes from the installed no-argument supplier;
        /// model/key/message construction begins only after the same U accepts this
        /// whole bound. Root peer scratch stays in the existing genuine resident peak;
        /// its additional before/after traffic belongs to the concrete tail supplier.
        ///
        /// # Errors
        /// Rejects zero compiled flight/request width or checked representation errors.
        pub fn $storage_create_use_signing_receiving_demand_v1(
            request_shape_bytes: usize,
            private: $StorageCreateUseSecurityShapeDataV1,
        ) -> Result<$ResourceVector, $StorageSessionGeometryRefusalV1> {
            if request_shape_bytes == 0 || private.actual_flight_bytes == 0 {
                return Err($invalid());
            }
            // These dominant canonical plan/statement/message/signature/body/envelope
            // planes retain the existing full normalized request bound. Private policy
            // planes use the already-existing immutable decoder ceiling, not a new cap.
            let policy = aos_sandbox_protocol::authorization_artifact::SigningAuthority::
                maximum_canonical_policy_bytes_v1();
            let bytes = request_shape_bytes.checked_mul(16)
                .and_then(|bytes| bytes.checked_add(policy.checked_mul(4)?))
                .and_then(|bytes| bytes.checked_add(private.actual_flight_bytes.checked_mul(2)?))
                .and_then(|bytes| bytes.checked_add(private.actual_construction_bytes))
                .and_then(|bytes| bytes.checked_add(private.actual_failure_bytes))
                .ok_or_else($invalid)?;
            $ResourceVector::ZERO.with($D::MemoryBytes, $as_u64(bytes)?)
                .with($D::OpenFiles, $as_u64(private.actual_endpoint_open_files)?)
                .checked_add($signing_originals().map_err(|_| $invalid())?)
                .map_err(|_| $invalid())
        }
    };
}
