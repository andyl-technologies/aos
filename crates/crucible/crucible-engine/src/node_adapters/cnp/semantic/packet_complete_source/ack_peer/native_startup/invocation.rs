//! Retains actual invocation Source15 before encoding or private boot7 effects.
//!
//! Only the new private Core invocation admission calls this constructor. It
//! first moves the already spent original member through the existing baseline
//! finalizer. The new complete Value and raw bank then remain Source-owned;
//! failure cannot fall back to the old completed birth or renew its occurrence.

use super::*;
use crucible_node_transport::reference_packet::service::native_startup::{
    PACKET_NATIVE_INVOCATION_SOURCE_BINDING_SCHEMA, PacketNativeInvocationPurposeData,
};

impl PacketCompleteSemanticSource {
    pub(crate) fn finalize_original_native_invocation_birth(
        self: &Rc<Self>,
        member: OriginalNativeStartupMember,
        launch: &PacketNative5SourceLaunch,
        purpose: &PacketNativeInvocationPurposeData,
    ) -> Result<(), RuntimeError> {
        // Core derives the choice from the actual registered holder. DATA is
        // compared only after its private member has authenticated this Source.
        member.authenticate(self)?;
        if !member.requires_original_invocation_data()? {
            return Err(RuntimeError::ForeignAuthority);
        }
        purpose
            .authenticate_target_data(launch)
            .map_err(|_| RuntimeError::ForeignAuthority)?;
        self.finalize_original_native_startup_birth(member, launch)?;
        let mut slot = self
            .ack_peer_birth
            .try_borrow_mut()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        let birth = slot.as_mut().ok_or(RuntimeError::OwnerUnavailable)?;
        let result = (|| {
            let state = birth
                .native_startup
                .as_mut()
                .ok_or(RuntimeError::OwnerUnavailable)?;
            if state.complete
                || state.body.is_some()
                || state.additions.is_some()
                || birth.failed
                || birth.boot_started.get()
            {
                return Err(RuntimeError::DuplicateOperation);
            }
            // Store each actual Value before the next allocating operation.
            state.body = Some(
                canonical::parse_json(&birth.source_birth, birth.source_birth.len())
                    .map_err(|_| RuntimeError::ResourceLimit)?,
            );
            state.additions =
                Some(serde_json::to_value(purpose).map_err(|_| RuntimeError::ResourceLimit)?);
            let body = state
                .body
                .as_mut()
                .and_then(serde_json::Value::as_object_mut)
                .ok_or(RuntimeError::ForeignAuthority)?;
            if body.len() != 18
                || body.get("schema").and_then(serde_json::Value::as_str)
                    != Some(PACKET_NATIVE_STARTUP_SOURCE_BINDING_SCHEMA)
            {
                return Err(RuntimeError::ForeignAuthority);
            }
            body.insert(
                "schema".into(),
                PACKET_NATIVE_INVOCATION_SOURCE_BINDING_SCHEMA.into(),
            );
            body.insert(
                "invocation".into(),
                state
                    .additions
                    .take()
                    .ok_or(RuntimeError::OwnerUnavailable)?,
            );
            if body.len() != 19 {
                return Err(RuntimeError::ForeignAuthority);
            }
            let capacity = birth.source_birth.capacity();
            state
                .replacement
                .try_reserve_exact(capacity)
                .map_err(|_| RuntimeError::ResourceLimit)?;
            if state.replacement.capacity() > capacity {
                return Err(RuntimeError::ResourceLimit);
            }
            super::super::super::encode_canonical_birth_bank(
                state.body.as_ref().ok_or(RuntimeError::OwnerUnavailable)?,
                capacity,
                &mut state.replacement,
            )
            .map_err(|_| RuntimeError::ResourceLimit)?;
            std::mem::swap(&mut birth.source_birth, &mut state.replacement);
            state.replacement.clear();
            state.replacement = Vec::new();
            // The exact complete Source15 Value stays retained for purpose
            // authentication; a later old finalizer cannot interpret it as absent.
            Ok(())
        })();
        if result.is_err() {
            birth.failed = true;
        }
        result
    }

    pub(crate) fn complete_original_native_invocation_birth(
        self: &Rc<Self>,
    ) -> Result<(), RuntimeError> {
        self.storage_origin_with_error::<RuntimeError>()?;
        {
            let slot = self
                .ack_peer_birth
                .try_borrow()
                .map_err(|_| RuntimeError::OwnerBusy)?;
            let birth = slot.as_ref().ok_or(RuntimeError::OwnerUnavailable)?;
            let state = birth
                .native_startup
                .as_ref()
                .ok_or(RuntimeError::OwnerUnavailable)?;
            state.member.authenticate(self)?;
            if !state.member.requires_original_invocation_data()? {
                return Err(RuntimeError::ForeignAuthority);
            }
            let value = state.body.as_ref().ok_or(RuntimeError::OwnerUnavailable)?;
            if value.get("schema").and_then(serde_json::Value::as_str)
                != Some(PACKET_NATIVE_INVOCATION_SOURCE_BINDING_SCHEMA)
                || value.as_object().is_none_or(|body| body.len() != 19)
            {
                return Err(RuntimeError::ForeignAuthority);
            }
            PacketNativeInvocationPurposeData::from_original_value_data(
                value
                    .get("invocation")
                    .ok_or(RuntimeError::OwnerUnavailable)?,
            )
            .map_err(|_| RuntimeError::ForeignAuthority)?;
        }
        let mut slot = self
            .ack_peer_birth
            .try_borrow_mut()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        let birth = slot.as_mut().ok_or(RuntimeError::OwnerUnavailable)?;
        let state = birth
            .native_startup
            .as_mut()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        if state.complete
            || state.body.is_none()
            || state.additions.is_some()
            || !state.replacement.is_empty()
            || birth.failed
            || birth.boot_started.get()
        {
            return Err(RuntimeError::OwnerUnavailable);
        }
        state.complete = true;
        Ok(())
    }
}

impl OriginalNativeStartupFinalization {
    pub(in crate::node_adapters::cnp::semantic::packet_complete_source::ack_peer) fn original_invocation_data(
        &self,
    ) -> Result<Option<PacketNativeInvocationPurposeData>, RuntimeError> {
        let Some(body) = invocation_body_at_edition_data(
            self.member.requires_original_invocation_data()?,
            self.body.as_ref(),
        )?
        else {
            return Ok(None);
        };
        if body.get("schema").and_then(serde_json::Value::as_str)
            != Some(PACKET_NATIVE_INVOCATION_SOURCE_BINDING_SCHEMA)
            || body.as_object().is_none_or(|fields| fields.len() != 19)
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        PacketNativeInvocationPurposeData::from_original_value_data(
            body.get("invocation")
                .ok_or(RuntimeError::OwnerUnavailable)?,
        )
        .map(Some)
        .map_err(|_| RuntimeError::ForeignAuthority)
    }
}

impl PacketCompleteSemanticSource {
    /// Names additional fixed Source15/wire15 views before their observers run.
    ///
    /// # Errors
    /// Refuses checked layout arithmetic overflow.
    pub fn original_native_invocation_source_counter_scratch_data() -> Result<usize, RuntimeError> {
        [
            std::mem::size_of::<PacketNativeInvocationPurposeData>(),
            3 * std::mem::size_of::<&serde_json::Map<String, serde_json::Value>>(),
            std::mem::size_of::<std::cell::Ref<'_, Option<OriginalAckPeerBirth>>>(),
            std::mem::size_of::<std::cell::RefMut<'_, Option<OriginalAckPeerBirth>>>(),
            super::super::native_wire::original_native_invocation_wire_counter_scratch_data(),
        ]
        .into_iter()
        .try_fold(0usize, |sum, n| {
            sum.checked_add(n).ok_or(RuntimeError::ResourceLimit)
        })
    }
}

impl PacketCompleteSemanticSource {
    /// Authenticates the same pre-Child restoration purpose against actual owners.
    ///
    /// This raw borrowed comparison grants no Prepare, publication, installation
    /// or activation permission. The installed restoration window authenticates
    /// its controller/query/current kernel and separately admits all new owners.
    /// Final OriginalLineageRestoration is deliberately not a prerequisite for
    /// the first Prepare; the actual inactive runtime supplies its target origin.
    ///
    /// # Errors
    /// Refuses foreign process/thread, plan, source/ticket/archive allocation,
    /// runtime/activation origin, incomplete private birth, original-execution
    /// purpose or any changed full runtime/native reference or target owner.
    pub fn authenticate_original_restoration_target_data(
        &self,
        ticket: &crate::node_state::CompleteOriginalNativeTicket,
        archive: &crate::node_state::CompleteOriginalRestorationSource,
        runtime: &crate::node_contract::ConformanceRuntime,
        plan: &crate::node_admission::InstalledConformancePlan,
        activation: &crate::node_contract::ActivationRecord,
    ) -> Result<(), RuntimeError> {
        self.storage_origin_with_error::<RuntimeError>()?;
        ticket.authenticate_source(archive)?;
        runtime.authenticate_original_restoration_target_data(archive, plan, activation)?;
        {
            let slot = self
                .ack_peer_birth
                .try_borrow()
                .map_err(|_| RuntimeError::OwnerBusy)?;
            let birth = slot.as_ref().ok_or(RuntimeError::OwnerUnavailable)?;
            let state = birth
                .native_startup
                .as_ref()
                .ok_or(RuntimeError::OwnerUnavailable)?;
            state
                .member
                .authenticate_original_invocation_target_plan_data(self, plan)?;
            if !state.complete || birth.failed || !birth.boot_started.get() {
                return Err(RuntimeError::OwnerUnavailable);
            }
            let purpose = state
                .original_invocation_data()?
                .ok_or(RuntimeError::ForeignAuthority)?;
            let owner = ticket.owner()?;
            let target = &self.installation().owner.owner;
            if owner.owner != target.id || owner.participants != target.participant_ids {
                return Err(RuntimeError::ForeignAuthority);
            }
            purpose
                .authenticate_restoration_source_data(
                    ticket.runtime_object()?,
                    &owner.state,
                    &owner.owner,
                )
                .map_err(|_| RuntimeError::ForeignAuthority)?;
            let installation = self.installation();
            authenticate_target_activation_data(
                &installation.world_binding_hash,
                &installation.owner.owner.id,
                &installation.binding.authority.incarnation_id,
                installation.binding.authority.owner_generation,
                state
                    .body
                    .as_ref()
                    .and_then(|body| body.get("invocation"))
                    .ok_or(RuntimeError::ForeignAuthority)?,
                activation,
            )?;
        }
        // No ReadOwner, native callback, serialization, hashing or I/O runs
        // under the birth loan. The same runtime/ticket origins are rechecked
        // after releasing that loan, before the caller can use the comparison.
        ticket.authenticate_source(archive)?;
        runtime.authenticate_original_restoration_target_data(archive, plan, activation)?;
        self.storage_origin_with_error::<RuntimeError>()
    }

    /// Names the fixed borrowed target-authentication views before that check.
    ///
    /// Recursive compiler frames and the caller's installed action are separate.
    pub fn original_restoration_target_counter_scratch_data() -> usize {
        crucible_node_transport::reference_packet::service::native_startup::original_native_invocation_counter_scratch_data()
            + std::mem::size_of::<std::cell::Ref<'_, Option<OriginalAckPeerBirth>>>()
            + std::mem::size_of::<Result<Option<PacketNativeInvocationPurposeData>, RuntimeError>>()
            + std::mem::size_of::<&crate::node_state::NativeOwnerState>()
            + std::mem::size_of::<[&Self; 2]>()
            + std::mem::size_of::<[&crate::node_admission::InstalledConformancePlan; 2]>()
            + std::mem::size_of::<[&crate::node_contract::ConformanceRuntime; 2]>()
            + std::mem::size_of::<[&crate::node_contract::ActivationRecord; 2]>()
            + crate::node_contract::ConformanceRuntime::original_restoration_target_counter_scratch_data()
            + 2 * std::mem::size_of::<&serde_json::Map<String, serde_json::Value>>()
            + std::mem::size_of::<[(&str, &str); 3]>()
            + std::mem::size_of::<std::slice::Iter<'_, crate::node_contract::OwnerIdentity>>()
            + 2 * std::mem::size_of::<Option<&crate::node_contract::OwnerIdentity>>()
            + std::mem::size_of::<Result<u64, std::num::ParseIntError>>()
    }
}

impl PacketCompleteSemanticSource {
    // Legacy editions keep their existing query guards without receiving any
    // invocation interpretation. Only Source15's actual private, completed,
    // started member can supply the new target-purpose conjunction.
    /// Quotes the fixed borrowed views used by the Source invocation Query guard.
    ///
    /// The installed host window adds this term before quoting or calling Query.
    /// It covers the birth loan, the initial-lifecycle validator's private input
    /// result, and the simultaneously borrowed finalization, body and purpose
    /// views. It grants no Query or restoration permission.
    ///
    /// # Errors
    /// Returns `ResourceLimit` if checked layout arithmetic overflows.
    pub fn original_fresh_query_invocation_counter_scratch_data() -> Result<usize, RuntimeError> {
        [
            size_of::<std::cell::Ref<'_, Option<OriginalAckPeerBirth>>>(),
            size_of::<
                Result<std::cell::Ref<'_, Option<OriginalAckPeerBirth>>, std::cell::BorrowError>,
            >(),
            size_of::<super::super::OriginalAckPeerInputs<'_>>(),
            size_of::<Result<super::super::OriginalAckPeerInputs<'_>, RuntimeError>>(),
            size_of::<&OriginalAckPeerBirth>(),
            size_of::<&OriginalNativeStartupFinalization>(),
            2 * size_of::<&serde_json::Value>(),
            2 * size_of::<&serde_json::Map<String, serde_json::Value>>(),
            3 * size_of::<Option<&serde_json::Value>>(),
            2 * size_of::<Option<&str>>(),
            size_of::<&PacketCompleteSemanticSource>(),
            size_of::<std::thread::ThreadId>(),
            size_of::<Result<(), RuntimeError>>(),
            size_of::<Result<bool, RuntimeError>>(),
            size_of::<Result<Option<&serde_json::Value>, RuntimeError>>(),
        ]
        .into_iter()
        .try_fold(0usize, |sum, bytes| {
            sum.checked_add(bytes).ok_or(RuntimeError::ResourceLimit)
        })
    }

    pub(crate) fn authenticate_original_fresh_query_invocation_data(
        &self,
    ) -> Result<(), RuntimeError> {
        self.storage_origin_with_error::<RuntimeError>()?;
        let slot = self
            .ack_peer_birth
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        let birth = slot.as_ref().ok_or(RuntimeError::OwnerUnavailable)?;
        birth.authenticate_original_initial_lifecycle_data()?;
        let Some(state) = birth.native_startup.as_ref() else {
            return Ok(());
        };
        state
            .member
            .authenticate_original_invocation_source_identity_data(self)?;
        if !state.complete {
            return Err(RuntimeError::OwnerUnavailable);
        }
        let Some(body) = invocation_body_at_edition_data(
            state.member.requires_original_invocation_data()?,
            state.body.as_ref(),
        )?
        else {
            return Ok(());
        };
        if !state.complete
            || body.as_object().is_none_or(|fields| fields.len() != 19)
            || body.get("schema").and_then(serde_json::Value::as_str)
                != Some(PACKET_NATIVE_INVOCATION_SOURCE_BINDING_SCHEMA)
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        let purpose = body
            .get("invocation")
            .ok_or(RuntimeError::ForeignAuthority)?;
        if purpose.get("schema").and_then(serde_json::Value::as_str)
            != Some("source-owned.packet-native-invocation-purpose/1")
            || purpose.get("purpose").and_then(serde_json::Value::as_str)
                != Some("restoration_target")
            || !purpose
                .get("source")
                .is_some_and(serde_json::Value::is_object)
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        Ok(())
    }
}

// Compares borrowed DATA only. The public entry reaches this leaf after the
// genuine inactive runtime, archive ticket and private Source member checks.
fn authenticate_target_activation_data(
    world: &crucible_node_format::HashRef,
    owner: &crucible_node_format::Id,
    incarnation: &crucible_node_format::Id,
    generation: crucible_node_format::U64,
    purpose: &serde_json::Value,
    activation: &crate::node_contract::ActivationRecord,
) -> Result<(), RuntimeError> {
    let target = purpose
        .get("target")
        .ok_or(RuntimeError::ForeignAuthority)?;
    let target_world = target.get("world").ok_or(RuntimeError::ForeignAuthority)?;
    if activation.world_binding_hash != *world
        || target.get("owner").and_then(serde_json::Value::as_str) != Some(owner.as_str())
        || target
            .get("incarnation")
            .and_then(serde_json::Value::as_str)
            != Some(incarnation.as_str())
        || target
            .get("owner_generation")
            .and_then(serde_json::Value::as_str)
            .and_then(|text| text.parse::<u64>().ok())
            != Some(generation.get())
    {
        return Err(RuntimeError::ForeignAuthority);
    }
    for (key, expected) in [
        ("algorithm", world.algorithm.as_str()),
        ("domain", world.domain.as_str()),
        ("digest", world.digest.as_str()),
    ] {
        if target_world.get(key).and_then(serde_json::Value::as_str) != Some(expected) {
            return Err(RuntimeError::ForeignAuthority);
        }
    }
    let mut rows = activation.owners.iter().filter(|row| row.owner == *owner);
    let row = rows.next().ok_or(RuntimeError::ForeignAuthority)?;
    if rows.next().is_some() || row.incarnation != *incarnation || row.generation != generation {
        return Err(RuntimeError::ForeignAuthority);
    }
    Ok(())
}

#[cfg(test)]
mod target_data_tests {
    use super::*;
    use crate::node_contract::{ActivationRecord, OwnerIdentity};
    use crucible_node_format::{Id, Position, U64, canonical};
    use serde_json::json;

    #[test]
    fn target_activation_data_requires_actual_world_and_unique_full_owner_incarnation() {
        let world = canonical::hash("cnp.world-binding.v1", b"data").unwrap();
        let owner = Id::new("source").unwrap();
        let incarnation = Id::new("fresh-incarnation").unwrap();
        let generation = U64::new(3);
        let purpose = json!({"target":{
            "world":world,"owner":owner,"incarnation":incarnation,"owner_generation":generation,
        }});
        let activation = ActivationRecord {
            generation: U64::new(7),
            activation_id: Id::new("activation").unwrap(),
            world_binding_hash: world.clone(),
            owners: ["source", "other1", "other2", "host"]
                .into_iter()
                .map(|name| OwnerIdentity {
                    owner: Id::new(name).unwrap(),
                    incarnation: incarnation.clone(),
                    generation,
                })
                .collect(),
            boundary: Position::new(
                U64::new(0),
                U64::new(0),
                crucible_node_format::Phase::BoundaryControl,
            ),
        };
        authenticate_target_activation_data(
            &world,
            &owner,
            &incarnation,
            generation,
            &purpose,
            &activation,
        )
        .unwrap();
        for axis in 0..6 {
            let mut changed = activation.clone();
            match axis {
                0 => {
                    changed.world_binding_hash =
                        canonical::hash("cnp.world-binding.v1", b"foreign").unwrap()
                }
                1 => changed.owners[0].incarnation = Id::new("stale-incarnation").unwrap(),
                2 => changed.owners[0].generation = U64::new(4),
                3 => changed.owners[0].owner = Id::new("missing-source").unwrap(),
                4 => changed.owners[1] = changed.owners[0].clone(),
                _ => changed.owners.clear(),
            }
            assert!(
                authenticate_target_activation_data(
                    &world,
                    &owner,
                    &incarnation,
                    generation,
                    &purpose,
                    &changed
                )
                .is_err()
            );
        }
        for field in ["owner", "incarnation", "owner_generation", "world"] {
            let mut changed = purpose.clone();
            changed["target"].as_object_mut().unwrap().remove(field);
            assert!(
                authenticate_target_activation_data(
                    &world,
                    &owner,
                    &incarnation,
                    generation,
                    &changed,
                    &activation
                )
                .is_err()
            );
        }
    }
}

// Grammar DATA only: the invocation flag comes exclusively from the retained
// Core member at production callers. This helper cannot construct that member.
fn invocation_body_at_edition_data(
    invocation: bool,
    body: Option<&serde_json::Value>,
) -> Result<Option<&serde_json::Value>, RuntimeError> {
    match (invocation, body) {
        (false, None) => Ok(None),
        (true, Some(body))
            if body.as_object().is_some_and(|fields| fields.len() == 19)
                && body.get("schema").and_then(serde_json::Value::as_str)
                    == Some(PACKET_NATIVE_INVOCATION_SOURCE_BINDING_SCHEMA) =>
        {
            Ok(Some(body))
        }
        _ => Err(RuntimeError::ForeignAuthority),
    }
}

#[cfg(test)]
mod member_edition_data_tests {
    use super::*;

    #[test]
    fn member_edition_data_refuses_missing_invocation_body_and_legacy_reinterpretation() {
        let mut body = serde_json::Map::new();
        body.insert(
            "schema".into(),
            PACKET_NATIVE_INVOCATION_SOURCE_BINDING_SCHEMA.into(),
        );
        for field in 0..18 {
            body.insert(format!("field{field}"), serde_json::Value::Null);
        }
        let body = serde_json::Value::Object(body);
        assert!(
            invocation_body_at_edition_data(false, None)
                .unwrap()
                .is_none()
        );
        assert!(std::ptr::eq(
            invocation_body_at_edition_data(true, Some(&body))
                .unwrap()
                .unwrap(),
            &body
        ));
        assert!(invocation_body_at_edition_data(true, None).is_err());
        assert!(invocation_body_at_edition_data(false, Some(&body)).is_err());
        let mut changed = body.clone();
        changed["schema"] = PACKET_NATIVE_STARTUP_SOURCE_BINDING_SCHEMA.into();
        assert!(invocation_body_at_edition_data(true, Some(&changed)).is_err());
        changed = body.clone();
        changed.as_object_mut().unwrap().remove("field0");
        assert!(invocation_body_at_edition_data(true, Some(&changed)).is_err());
        assert_eq!(
            body["schema"],
            PACKET_NATIVE_INVOCATION_SOURCE_BINDING_SCHEMA
        );
    }
}

impl PacketCompleteSemanticSource {
    /// Checks only this live Source's completed genuine-original invocation.
    ///
    /// The caller precharges the defining getter before entry. Raw member and
    /// WeakPlan liveness checks invoke no authority callback under the birth
    /// loan. Full installed rights, source/kernel currency, selected snapshot
    /// declaration and complete historical reconstruction remain conjuncts of
    /// the actual Capture caller; this predicate issues none of those rights.
    ///
    /// # Errors
    /// Refuses foreign origin, a busy/missing/unready/failed/unstarted birth,
    /// missing or legacy member, dead/foreign plan/source, incomplete Source15,
    /// malformed full purpose, or any restoration-target purpose.
    pub(in crate::node_adapters::cnp::semantic::packet_complete_source) fn authenticate_original_capture_invocation_data(
        &self,
    ) -> Result<(), RuntimeError> {
        self.storage_origin_with_error::<RuntimeError>()?;
        let slot = self
            .ack_peer_birth
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        let birth = slot.as_ref().ok_or(RuntimeError::OwnerUnavailable)?;
        birth.authenticate_original_initial_lifecycle_data()?;
        let state = birth
            .native_startup
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        state
            .member
            .authenticate_original_invocation_source_identity_data(self)?;
        if !state.member.requires_original_invocation_data()? {
            return Err(RuntimeError::ForeignAuthority);
        }
        if !state.complete || state.additions.is_some() || !state.replacement.is_empty() {
            return Err(RuntimeError::OwnerUnavailable);
        }
        let body = state.body.as_ref().ok_or(RuntimeError::OwnerUnavailable)?;
        original_capture_purpose_data(body)?;
        drop(slot);
        self.storage_origin_with_error::<RuntimeError>()
    }

    /// Names the raw original-invocation validator's fixed borrowed/parse views.
    ///
    /// No requested heap, compiler/recursive frame or Source action permission
    /// is inferred from this fixed DATA. The existing conservative full purpose
    /// decoder getter is added explicitly; no unrelated padding is credited.
    ///
    /// # Errors
    /// Returns `ResourceLimit` if checked layout arithmetic overflows.
    pub(in crate::node_adapters::cnp::semantic::packet_complete_source) fn original_capture_invocation_counter_scratch_data()
    -> Result<usize, RuntimeError> {
        [
            Self::original_fresh_query_invocation_counter_scratch_data()?,
            crucible_node_transport::reference_packet::service::native_startup::original_native_invocation_counter_scratch_data(),
            size_of::<&OriginalNativeStartupMember>(),
            size_of::<&crate::node_admission::WeakInstalledConformancePlan>(),
            size_of::<Result<PacketNativeInvocationPurposeData, RuntimeError>>(),
            size_of::<Result<PacketNativeInvocationPurposeData, crucible_node_transport::ProviderError>>(),
            size_of::<[&str; 19]>(),
            size_of::<std::slice::Iter<'_, &str>>(),
            size_of::<&serde_json::Map<String, serde_json::Value>>(),
        ].into_iter().try_fold(0usize, |sum, bytes| {
            sum.checked_add(bytes).ok_or(RuntimeError::ResourceLimit)
        })
    }
}

// This leaf validates immutable constructor-produced DATA only. Its caller has
// already authenticated the actual private member edition/Source and completion;
// no decoded field or public argument can bypass that original owner boundary.
fn original_capture_purpose_data(
    body: &serde_json::Value,
) -> Result<PacketNativeInvocationPurposeData, RuntimeError> {
    let source = body.as_object().ok_or(RuntimeError::ForeignAuthority)?;
    let keys = [
        "ack_emitter_selection",
        "capture_allocation_selection",
        "capture_profile",
        "codec_metadata_extent",
        "complete_restore_selection",
        "confirmation_selection",
        "coordinator",
        "fresh_restore_allocation_selection",
        "invocation",
        "limits",
        "native_codec_metadata_extent",
        "native_startup_allocation",
        "program",
        "protocol_metadata_limits",
        "report_startup_allocation",
        "restore_input_emitter_selection",
        "schema",
        "selection",
        "storage",
    ];
    if source.len() != keys.len()
        || keys.iter().any(|key| !source.contains_key(*key))
        || body.get("schema").and_then(serde_json::Value::as_str)
            != Some(PACKET_NATIVE_INVOCATION_SOURCE_BINDING_SCHEMA)
    {
        return Err(RuntimeError::ForeignAuthority);
    }
    let purpose = PacketNativeInvocationPurposeData::from_original_value_data(
        body.get("invocation")
            .ok_or(RuntimeError::ForeignAuthority)?,
    )
    .map_err(|_| RuntimeError::ForeignAuthority)?;
    if !purpose.is_original_execution_data() {
        return Err(RuntimeError::ForeignAuthority);
    }
    Ok(purpose)
}

#[cfg(test)]
mod original_capture_purpose_data_tests {
    use super::*;
    use serde_json::{Value, json};

    // A pure parser bank with intentionally uninterpreted other Source fields;
    // it is not a native birth, Source member, installed action or permission.
    fn source_data() -> Value {
        let mut source = serde_json::Map::new();
        for key in [
            "ack_emitter_selection",
            "capture_allocation_selection",
            "capture_profile",
            "codec_metadata_extent",
            "complete_restore_selection",
            "confirmation_selection",
            "coordinator",
            "fresh_restore_allocation_selection",
            "invocation",
            "limits",
            "native_codec_metadata_extent",
            "native_startup_allocation",
            "program",
            "protocol_metadata_limits",
            "report_startup_allocation",
            "restore_input_emitter_selection",
            "schema",
            "selection",
            "storage",
        ] {
            source.insert(key.into(), Value::Null);
        }
        source.insert(
            "schema".into(),
            PACKET_NATIVE_INVOCATION_SOURCE_BINDING_SCHEMA.into(),
        );
        source.insert(
            "invocation".into(),
            json!({
                "schema":"source-owned.packet-native-invocation-purpose/1",
                "purpose":"original_execution", "source":null,
                "target":{
                    "world":canonical::hash("cnp.world-binding.v1", b"data").unwrap(),
                    "binding":canonical::hash("cnp.node-binding.v1", b"data").unwrap(),
                    "node":"node", "owner":"owner", "session":"session",
                    "incarnation":"incarnation", "owner_generation":"1",
                    "prepared_token":"prepared", "admission":"admission"
                }
            }),
        );
        Value::Object(source)
    }

    #[test]
    fn original_capture_purpose_data_refuses_target_legacy_and_incomplete_full_grammars() {
        let original = source_data();
        assert!(
            original_capture_purpose_data(&original)
                .unwrap()
                .is_original_execution_data()
        );
        let bytes = canonical::canonical_json(&original).unwrap();
        let reference = canonical::content_ref(b"archive data", "application/json").unwrap();
        let mut target = original.clone();
        target["invocation"]["purpose"] = "restoration_target".into();
        target["invocation"]["source"] = json!({
            "runtime":reference, "native_state":reference, "owner":"owner"
        });
        assert!(
            !PacketNativeInvocationPurposeData::from_original_value_data(&target["invocation"])
                .unwrap()
                .is_original_execution_data()
        );
        assert!(original_capture_purpose_data(&target).is_err());
        for axis in 0..7 {
            let mut changed = original.clone();
            match axis {
                0 => {
                    changed["schema"] = "source-owned.packet-canonical-ack-source-binding/14".into()
                }
                1 => {
                    changed
                        .as_object_mut()
                        .unwrap()
                        .remove("native_startup_allocation");
                }
                2 => changed["unknown"] = true.into(),
                3 => changed["invocation"]["source"] = json!({}),
                4 => changed["invocation"]["unknown"] = true.into(),
                5 => {
                    changed["invocation"]["target"]
                        .as_object_mut()
                        .unwrap()
                        .remove("incarnation");
                }
                _ => changed["invocation"]["target"]["world"]["domain"] = "cnp.foreign.v1".into(),
            }
            assert!(original_capture_purpose_data(&changed).is_err());
        }
        assert!(original_capture_purpose_data(&Value::Null).is_err());
        assert_eq!(canonical::canonical_json(&original).unwrap(), bytes);
    }
}
