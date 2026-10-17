//! Exact registry admission and declared browser-file identities.
//!
//! IndexedDB retains an immutable admission header and create-only append
//! records before dispatch. These records contain no bearer or provider grant.

use std::collections::BTreeSet;

use aos_proto_types::direct_upload::{
    encode_direct_control, valid_direct_digest, valid_direct_identity, valid_direct_path,
    DirectDependencyPhase, DirectUploadTarget, WireInteger, MAX_DIRECT_CONTROL_BYTES,
    MAX_DIRECT_OBJECT_BYTES,
};
use aos_proto_types::{
    AppendRegistryPublicationManifestRequest, BeginRegistryPublicationManifestRequest,
    RegistryPublication, RegistryPublicationManifestSession, RegistryPublicationObject,
    RegistryPublicationObjectInput, SealRegistryPublicationManifestRequest,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::direct_upload_model::CheckpointRecord;

/// Original admission metadata, before the first server mutation.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct AdmissionHead {
    /// Original server-proved deployment namespace.
    pub deployment: String,
    /// Original server-proved authenticated actor.
    pub principal: String,
    /// Complete original metadata declaration retained before Begin.
    pub begin: BeginRegistryPublicationManifestRequest,
    /// First positively observed server owner; later replies cannot replace it.
    pub publication_id: Option<String>,
}

impl CheckpointRecord for AdmissionHead {
    fn merge(mut self, previous: Option<Self>) -> Result<Self, String> {
        if let Some(old) = previous {
            if self.deployment != old.deployment
                || self.principal != old.principal
                || self.begin != old.begin
            {
                return Err("The retained publication admission changed".into());
            }
            if let Some(owner) = old.publication_id {
                if self
                    .publication_id
                    .as_ref()
                    .is_some_and(|new| new != &owner)
                {
                    return Err("The original publication owner changed".into());
                }
                self.publication_id = Some(owner);
            }
        }
        Ok(self)
    }
}

/// Exact bounded page, retained before its original Append request.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct AdmissionChunk {
    /// Original page and lease, retained before its exact dispatch.
    pub request: AppendRegistryPublicationManifestRequest,
}

impl CheckpointRecord for AdmissionChunk {
    fn merge(self, previous: Option<Self>) -> Result<Self, String> {
        if previous.as_ref().is_some_and(|old| old != &self) {
            return Err("The original manifest page or lease changed".into());
        }
        Ok(self)
    }
}

/// Exact Seal dispatch, retained before its first attempt or replay.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct AdmissionSeal {
    /// Original authenticated deployment and principal.
    pub actor: (String, String),
    /// Original owner and metadata lease; unknown acknowledgment changes neither.
    pub request: SealRegistryPublicationManifestRequest,
}

impl CheckpointRecord for AdmissionSeal {
    fn merge(self, previous: Option<Self>) -> Result<Self, String> {
        if previous.as_ref().is_some_and(|old| old != &self) {
            return Err("The original publication Seal or actor changed".into());
        }
        Ok(self)
    }
}

/// Owns a once-validated, sorted original inventory and its canonical digest.
///
/// No mutable entry access is exposed. Append pages borrow only this witness,
/// avoiding another full inventory scan for every bounded metadata dispatch.
pub(crate) struct ValidatedInventory {
    entries: Vec<RegistryPublicationObjectInput>,
    digest: String,
}

impl ValidatedInventory {
    /// Validates and takes ownership of every original manifest entry once.
    ///
    /// # Errors
    /// Refuses malformed, duplicate or excessive original source declarations.
    pub(crate) fn new(mut entries: Vec<RegistryPublicationObjectInput>) -> Result<Self, String> {
        let digest = inventory_digest(&entries)?;
        entries.sort_by(|left, right| left.path.cmp(&right.path));
        Ok(Self { entries, digest })
    }

    /// Returns the cached full canonical original digest.
    pub(crate) fn digest(&self) -> &str {
        &self.digest
    }

    /// Returns the number of validated original entries.
    pub(crate) fn len(&self) -> usize {
        self.entries.len()
    }
}

/// Computes the existing canonical sorted publication tuple digest.
///
/// # Errors
/// Refuses duplicate paths or malformed immutable object declarations.
pub(crate) fn inventory_digest(
    objects: &[RegistryPublicationObjectInput],
) -> Result<String, String> {
    if objects.is_empty() || objects.len() > 50_000 {
        return Err("The publication inventory size is invalid".into());
    }
    let mut paths = BTreeSet::new();
    let mut tuples = Vec::with_capacity(objects.len());
    for object in objects {
        if !valid_direct_path(&object.path)
            || !paths.insert(&object.path)
            || !valid_direct_digest(&object.sha256)
            || object.byte_size < 0
            || object.byte_size as u64 > MAX_DIRECT_OBJECT_BYTES
            || !matches!(object.kind.as_str(), "immutable" | "mutable_pointer")
            || object.media_type.len() > 255
        {
            return Err("The publication contains an invalid source declaration".into());
        }
        tuples.push((
            &object.path,
            &object.sha256,
            object.byte_size,
            &object.kind,
            &object.media_type,
        ));
    }
    tuples.sort();
    let bytes = serde_json::to_vec(&tuples).map_err(|_| "The publication inventory is invalid")?;
    Ok(hex::encode(Sha256::digest(bytes)))
}

impl AdmissionHead {
    /// Checks server progress against the retained complete original declaration.
    ///
    /// # Errors
    /// Refuses changed owner, malformed lease or impossible admitted progress.
    pub(crate) fn validate_session(
        &self,
        session: &RegistryPublicationManifestSession,
    ) -> Result<(), String> {
        if !valid_direct_identity(&session.publication_id)
            || !valid_direct_identity(&session.lease_token)
            || session.manifest_digest != self.begin.manifest_digest
            || session.object_count != self.begin.object_count
            || session.admitted_object_count > session.object_count
            || session.next_chunk_index > session.admitted_object_count
            || !matches!(session.state.as_str(), "accepting" | "sealed")
            || (session.state == "sealed" && session.admitted_object_count != session.object_count)
            || self
                .publication_id
                .as_ref()
                .is_some_and(|owner| owner != &session.publication_id)
        {
            return Err("The Hub changed the original publication admission".into());
        }
        Ok(())
    }

    /// Checks the complete sealed inventory before opening any provider session.
    ///
    /// # Errors
    /// Refuses changed original metadata, inventory tuples or object identities.
    pub(crate) fn validate_publication(&self, value: &RegistryPublication) -> Result<(), String> {
        let objects: Vec<_> = value
            .objects
            .iter()
            .map(|object| RegistryPublicationObjectInput {
                path: object.path.clone(),
                sha256: object.sha256.clone(),
                byte_size: object.byte_size,
                kind: object.kind.clone(),
                media_type: object.media_type.clone(),
            })
            .collect();
        if self.publication_id.as_deref() != Some(value.publication_id.as_str())
            || value.registry != self.begin.registry
            || value.generation != self.begin.generation
            || value.manifest_digest != self.begin.manifest_digest
            || value.refs_digest != self.begin.refs_digest
            || value.default_commit != self.begin.default_commit
            || value.parent_publication_id != self.begin.parent_publication_id
            || objects.len() != self.begin.object_count as usize
            || inventory_digest(&objects)? != self.begin.manifest_digest
            || value.objects.iter().any(|object| object.object_id <= 0)
            || value
                .objects
                .iter()
                .map(|object| object.object_id)
                .collect::<BTreeSet<_>>()
                .len()
                != value.objects.len()
        {
            return Err("The sealed publication differs from the original manifest".into());
        }
        Ok(())
    }
}

/// Constructs the next bounded exact append from authoritative admitted progress.
///
/// # Errors
/// Refuses invalid cursors, a changed full inventory or an oversized single entry.
pub(crate) fn next_chunk(
    head: &AdmissionHead,
    session: &RegistryPublicationManifestSession,
    inventory: &ValidatedInventory,
) -> Result<AdmissionChunk, String> {
    head.validate_session(session)?;
    if inventory.digest() != head.begin.manifest_digest
        || inventory.len() != head.begin.object_count as usize
    {
        return Err("The selected publication manifest changed".into());
    }
    let start = session.admitted_object_count as usize;
    let mut count = (inventory.len() - start).min(64);
    while count > 0 {
        let chunk = inventory.entries[start..start + count].to_vec();
        let value = AdmissionChunk {
            request: AppendRegistryPublicationManifestRequest {
                publication_id: session.publication_id.clone(),
                lease_token: session.lease_token.clone(),
                chunk_index: session.next_chunk_index,
                chunk_digest: inventory_digest(&chunk)?,
                objects: chunk,
            },
        };
        // Leave room for the IndexedDB key and record envelope as well as the RPC.
        if encode_direct_control(&value)
            .is_ok_and(|bytes| bytes.len() <= MAX_DIRECT_CONTROL_BYTES - 1024)
        {
            return Ok(value);
        }
        count /= 2;
    }
    Err("The next manifest page cannot fit the control bound".into())
}

/// Resolves an exact server-declared publication file and its dependency phase.
///
/// # Errors
/// Refuses wrong owner/object, changed declarations or premature pointer writes.
pub(crate) fn publication_target(
    value: &RegistryPublication,
    object: &RegistryPublicationObject,
) -> Result<(DirectUploadTarget, DirectDependencyPhase, (String, u64)), String> {
    if !value.objects.iter().any(|declared| declared == object)
        || object.object_id <= 0
        || !valid_direct_digest(&object.sha256)
        || object.byte_size < 0
        || !matches!(value.state.as_str(), "preparing" | "writing_pointers")
    {
        return Err("The selected publication object is not eligible".into());
    }
    let phase = match object.kind.as_str() {
        "immutable" if value.state == "preparing" => DirectDependencyPhase::Content,
        "mutable_pointer" if value.state == "writing_pointers" => DirectDependencyPhase::Visibility,
        _ => return Err("Publication dependencies are not verified for this upload".into()),
    };
    let target = DirectUploadTarget::PublicationObject {
        publication_id: value.publication_id.clone(),
        surface_object_id: WireInteger::new(object.object_id as u64),
        path: object.path.clone(),
    };
    target
        .validate()
        .map_err(|_| "The publication object target is invalid")?;
    Ok((
        target,
        phase,
        (object.sha256.clone(), object.byte_size as u64),
    ))
}

/// Checks refreshed progress without allowing another manifest or object owner.
///
/// # Errors
/// Refuses changed publication identity or inventory and incomplete selected bytes.
pub(crate) fn validate_progress(
    original: &RegistryPublication,
    next: &RegistryPublication,
    object_id: i64,
) -> Result<(), String> {
    let inventory = |value: &RegistryPublication| {
        let mut rows: Vec<_> = value
            .objects
            .iter()
            .map(|object| {
                (
                    object.object_id,
                    object.path.clone(),
                    object.sha256.clone(),
                    object.byte_size,
                    object.kind.clone(),
                    object.media_type.clone(),
                )
            })
            .collect();
        rows.sort();
        rows
    };
    let placements = |value: &RegistryPublication| {
        let mut rows: Vec<_> = value
            .placements
            .iter()
            .map(|placement| {
                (
                    placement.placement_id,
                    placement.name.clone(),
                    placement.required,
                )
            })
            .collect();
        rows.sort();
        rows
    };
    if placements(next) != placements(original)
        || next.publication_id != original.publication_id
        || next.registry != original.registry
        || next.generation != original.generation
        || next.manifest_digest != original.manifest_digest
        || next.refs_digest != original.refs_digest
        || next.default_commit != original.default_commit
        || next.parent_publication_id != original.parent_publication_id
        || inventory(original) != inventory(next)
        || !next
            .objects
            .iter()
            .any(|object| object.object_id == object_id && object.verified)
        || original.objects.iter().any(|old| {
            old.verified
                && next
                    .objects
                    .iter()
                    .any(|new| new.object_id == old.object_id && !new.verified)
        })
    {
        return Err("The publication readback changed or selected bytes remain unverified".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use aos_proto_types::direct_upload::DirectCapabilitiesTarget;
    use aos_proto_types::WhoAmIResponse;

    use super::*;
    use crate::direct_upload_model::{capability_target, InitialUploadPolicy};

    fn object(number: i64, kind: &str) -> RegistryPublicationObject {
        RegistryPublicationObject {
            object_id: number,
            path: format!("objects/{number}"),
            sha256: "a".repeat(64),
            byte_size: 9,
            kind: kind.into(),
            media_type: "application/octet-stream".into(),
            ..Default::default()
        }
    }

    fn input(number: usize) -> RegistryPublicationObjectInput {
        RegistryPublicationObjectInput {
            path: format!("objects/{number:05}"),
            sha256: "a".repeat(64),
            byte_size: 9,
            kind: "immutable".into(),
            media_type: "application/octet-stream".into(),
        }
    }

    fn head(objects: &[RegistryPublicationObjectInput]) -> AdmissionHead {
        AdmissionHead {
            deployment: "deployment".into(),
            principal: "b".repeat(64),
            begin: BeginRegistryPublicationManifestRequest {
                registry: "registry".into(),
                generation: "generation".into(),
                refs_digest: "c".repeat(64),
                manifest_digest: inventory_digest(objects).unwrap(),
                object_count: objects.len() as u32,
                ..Default::default()
            },
            publication_id: Some("publication".into()),
        }
    }

    fn session(head: &AdmissionHead) -> RegistryPublicationManifestSession {
        RegistryPublicationManifestSession {
            publication_id: "publication".into(),
            lease_token: "lease".into(),
            manifest_digest: head.begin.manifest_digest.clone(),
            object_count: head.begin.object_count,
            state: "accepting".into(),
            ..Default::default()
        }
    }

    #[test]
    fn publication_pages_are_bounded_exact_and_resume_from_acknowledged_progress() {
        let inputs: Vec<_> = (0..130).map(input).collect();
        let head = head(&inputs);
        let mut session = session(&head);
        let inventory = ValidatedInventory::new(inputs.clone()).unwrap();
        let first = next_chunk(&head, &session, &inventory).unwrap();
        assert_eq!(first.request.objects, inputs[..64]);
        assert_eq!(first.clone().merge(Some(first.clone())).unwrap(), first);
        let mut changed = first.clone();
        changed.request.objects[0].sha256 = "d".repeat(64);
        assert!(changed.merge(Some(first)).is_err());

        session.admitted_object_count = 64;
        session.next_chunk_index = 1;
        let second = next_chunk(&head, &session, &inventory).unwrap();
        assert_eq!(second.request.objects, inputs[64..128]);
        assert_eq!(second.request.chunk_index, 1);
        assert!(encode_direct_control(&second).unwrap().len() < MAX_DIRECT_CONTROL_BYTES - 1024);
        let mut wrong_source = inputs;
        wrong_source[129].sha256 = "d".repeat(64);
        let wrong_source = ValidatedInventory::new(wrong_source).unwrap();
        assert!(next_chunk(&head, &session, &wrong_source).is_err());
    }

    #[test]
    fn seal_replay_preserves_the_exact_owner_lease_and_actor_after_lost_acknowledgment() {
        let original = AdmissionSeal {
            actor: ("deployment".into(), "b".repeat(64)),
            request: SealRegistryPublicationManifestRequest {
                publication_id: "publication".into(),
                lease_token: "lease".into(),
            },
        };
        let retained = original.clone().merge(None).unwrap();
        assert_eq!(
            original.clone().merge(Some(retained.clone())).unwrap(),
            retained
        );

        let mut other = original.clone();
        other.request.publication_id = "replacement".into();
        assert!(other.merge(Some(retained.clone())).is_err());
        let mut other = original.clone();
        other.request.lease_token = "other-lease".into();
        assert!(other.merge(Some(retained.clone())).is_err());
        let mut other = original;
        other.actor.1 = "c".repeat(64);
        assert!(other.merge(Some(retained)).is_err());
    }

    #[test]
    fn inventory_witness_owns_sorted_originals_and_refuses_changed_resume_sources() {
        let inputs: Vec<_> = (0..130).map(input).collect();
        let original = head(&inputs);
        let session = session(&original);
        let mut selected = inputs.clone();
        selected.reverse();
        let inventory = ValidatedInventory::new(selected.clone()).unwrap();
        selected[0].sha256 = "d".repeat(64);
        assert_eq!(inventory.digest(), original.begin.manifest_digest);
        assert_eq!(
            next_chunk(&original, &session, &inventory)
                .unwrap()
                .request
                .objects,
            inputs[..64]
        );
        assert!(next_chunk(
            &original,
            &session,
            &ValidatedInventory::new(selected).unwrap()
        )
        .is_err());
        assert!(ValidatedInventory::new(vec![input(0), input(0)]).is_err());
    }

    #[test]
    fn admission_preserves_parent_actor_and_owner_across_lost_acknowledgment() {
        let original = head(&[input(0)]);
        let mut stale = original.clone();
        stale.publication_id = None;
        assert_eq!(
            stale.merge(Some(original.clone())).unwrap().publication_id,
            original.publication_id
        );
        let mut changed = original.clone();
        changed.begin.parent_publication_id = "other-parent".into();
        assert!(changed.merge(Some(original.clone())).is_err());
        let mut changed = original.clone();
        changed.principal = "d".repeat(64);
        assert!(changed.merge(Some(original.clone())).is_err());
        let mut reply = session(&original);
        reply.publication_id = "replacement".into();
        assert!(original.validate_session(&reply).is_err());
        reply = session(&original);
        reply.state = "sealed".into();
        assert!(original.validate_session(&reply).is_err());
    }

    #[test]
    fn visibility_and_refresh_keep_the_complete_original_publication_barrier() {
        let content = object(1, "immutable");
        let pointer = object(2, "mutable_pointer");
        let mut value = RegistryPublication {
            publication_id: "publication".into(),
            registry: "registry".into(),
            state: "preparing".into(),
            objects: vec![content.clone(), pointer.clone()],
            ..Default::default()
        };
        let (target, phase, declared) = publication_target(&value, &content).unwrap();
        assert_eq!(phase, DirectDependencyPhase::Content);
        assert_eq!(declared, ("a".repeat(64), 9));
        assert_eq!(
            capability_target(&target).unwrap(),
            DirectCapabilitiesTarget::Publication {
                publication_id: "publication".into()
            }
        );
        assert!(publication_target(&value, &pointer).is_err());
        let original = value.clone();
        value.objects[0].verified = true;
        value.state = "writing_pointers".into();
        validate_progress(&original, &value, 1).unwrap();
        assert_eq!(
            publication_target(&value, &pointer).unwrap().1,
            DirectDependencyPhase::Visibility
        );
        assert!(publication_target(&value, &content).is_err());
        let mut changed = value.clone();
        changed.objects[1].sha256 = "d".repeat(64);
        assert!(validate_progress(&value, &changed, 1).is_err());
        changed = value.clone();
        changed.publication_id = "replacement".into();
        assert!(validate_progress(&value, &changed, 1).is_err());
        assert!(validate_progress(&original, &original, 1).is_err());
        let mut foreign = pointer;
        foreign.object_id = 3;
        assert!(publication_target(&value, &foreign).is_err());
    }

    #[test]
    fn sealed_inventory_rechecks_every_tuple_not_just_server_digest() {
        let inputs = vec![input(0), input(1)];
        let head = head(&inputs);
        let mut value = RegistryPublication {
            publication_id: "publication".into(),
            registry: head.begin.registry.clone(),
            generation: head.begin.generation.clone(),
            refs_digest: head.begin.refs_digest.clone(),
            manifest_digest: head.begin.manifest_digest.clone(),
            objects: inputs
                .iter()
                .enumerate()
                .map(|(index, input)| RegistryPublicationObject {
                    object_id: index as i64 + 1,
                    path: input.path.clone(),
                    sha256: input.sha256.clone(),
                    byte_size: input.byte_size,
                    kind: input.kind.clone(),
                    media_type: input.media_type.clone(),
                    ..Default::default()
                })
                .collect(),
            ..Default::default()
        };
        head.validate_publication(&value).unwrap();
        value.objects[1].byte_size += 1;
        assert!(head.validate_publication(&value).is_err());
        assert!(inventory_digest(&[input(0), input(0)]).is_err());
    }

    #[test]
    fn selected_source_must_match_the_declared_whole_digest_and_size() {
        use crate::direct_upload_model::validate_declared_source;
        let source = ("a".repeat(64), 9);
        validate_declared_source(Some(&source), &source.0, 9).unwrap();
        assert!(validate_declared_source(Some(&source), &"b".repeat(64), 9).is_err());
        assert!(validate_declared_source(Some(&source), &source.0, 10).is_err());
        // Cache uploads still establish their own independently hashed source.
        validate_declared_source(None, &source.0, 9).unwrap();
    }

    #[test]
    fn pre_admission_policy_needs_no_fake_capability_and_blocks_legacy_bytes() {
        let identity = WhoAmIResponse {
            principal_kind: "user".into(),
            transfer_mode: "direct_required".into(),
            deployment_id: "deployment".into(),
            principal_id: "b".repeat(64),
            access_expires_at: 200,
            ..Default::default()
        };
        let policy =
            InitialUploadPolicy::from_authenticated("bearer", "https://hub.test", &identity, 100)
                .unwrap();
        assert_eq!(
            policy.actor(),
            Some(("deployment", identity.principal_id.as_str()))
        );
        let effects = std::cell::Cell::new(0);
        assert!(policy
            .dispatch_with("bearer", "https://hub.test", 100, true, |_| effects.set(1))
            .is_err());
        assert_eq!(effects.get(), 0);
        policy
            .dispatch_with("bearer", "https://hub.test", 100, false, |_| effects.set(1))
            .unwrap();
        assert_eq!(effects.get(), 1);
        assert!(policy
            .dispatch_with("refreshed", "https://hub.test", 100, false, |_| effects
                .set(2))
            .is_err());
        let mut unknown = identity;
        unknown.transfer_mode = "unsupported".into();
        assert!(InitialUploadPolicy::from_authenticated(
            "bearer",
            "https://hub.test",
            &unknown,
            100
        )
        .is_err());
    }
}
