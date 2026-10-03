//! Original scope, chronology and stable assertion joins for Source's suffix.

use super::{SourceNativeHeldCompletionRecordV1 as Record, corrupt, schema_error};
use crate::ledger::{
    LedgerFormatErrorV1, native_completion::NativeAcquireCompletionStateV2 as Outer,
};
use aos_sandbox_core::ObjectDigest;
use aos_sandbox_source_provider_protocol::native_held_completion::{
    NativeHeldControlKindV1 as Kind, NativeHeldOwnerV1 as Owner, NativeHeldScopeV1,
    NativeHeldSectionTagV1 as Tag,
    assertion::{
        NativeHeldDispositionV1 as Disposition, NativeHeldSettlementV1,
        ProviderNativeSettlementAssertionV1, RootNativeDispositionAssertionV1,
        StorageNativeSettlementAssertionV1,
    },
    frame::{NativeHeldSignerV1, PreparedNativeHeldControlV1, SignedNativeHeldControlV1},
    recovery::{
        NativeHeldRecoveryModeV1 as Mode, NativeHeldRecoveryQueryV1, ProviderNativeRecoveryStateV1,
        RootNativeRecoveryAssertionV1, StorageNativeRecoveryStateV1,
    },
};

pub(super) fn required(
    control: &PreparedNativeHeldControlV1,
    tag: Tag,
) -> Result<&[u8], LedgerFormatErrorV1> {
    control.section(tag).ok_or(corrupt("held required section"))
}

pub(super) fn query(
    control: &PreparedNativeHeldControlV1,
) -> Result<NativeHeldRecoveryQueryV1, LedgerFormatErrorV1> {
    NativeHeldRecoveryQueryV1::from_canonical_bytes(required(control, Tag::RecoveryQuery)?)
        .map_err(schema_error)
}

pub(super) fn full_scope(record: &Record) -> Result<NativeHeldScopeV1, LedgerFormatErrorV1> {
    let root = record
        .suffix
        .control(Kind::RootPrepared)
        .ok_or(corrupt("held original Root preparation"))?;
    Ok(NativeHeldScopeV1 {
        provider_attempt: record.original.attempt_digest,
        original_native_request: record.original.native_request_digest,
        ..*root.scope()
    })
}

pub(super) fn validate_record(record: &Record) -> Result<(), LedgerFormatErrorV1> {
    record.original.validate_canonical_artifacts()?;
    if record.original.original_clock.is_none() || record.suffix.owner() != Owner::Provider {
        return Err(corrupt("held clock/owner"));
    }
    let native = record
        .original
        .canonical_request
        .as_ref()
        .ok_or(corrupt("held original native request"))?;
    let root = record
        .suffix
        .control(Kind::RootPrepared)
        .ok_or(corrupt("held original Root preparation"))?;
    if root.scope().original_source_session != record.original.session_binding
        || root.scope().provider_acquisition != record.original.acquisition_id
        || root.scope().original_root_request != record.original.root_request_digest
        || root.prepared().signer()
            != &NativeHeldSignerV1::SourceProvider(
                native.request().signed_root_request().signer().clone(),
            )
        || root.scope().flight != record.suffix.flight()
    {
        return Err(corrupt("held original Root request/signer scope"));
    }
    let full = full_scope(record)?;
    full.validate_full().map_err(schema_error)?;
    let mut prefix: Vec<&SignedNativeHeldControlV1> = Vec::new();
    for control in record.suffix.controls() {
        if !control.scope().is_root_only() && control.scope() != &full {
            return Err(corrupt("held immutable full original scope"));
        }
        validate_signer_scope(record, control.prepared())?;
        validate_predecessor(control.prepared(), &prefix)?;
        if control.kind().is_recovery()
            && query(control.prepared())?.original_prepared != root.digest()
        {
            return Err(corrupt("held recovery original preparation"));
        }
        if control.kind() == Kind::RootRecoveryQuery
            && query(control.prepared())?.mode == Mode::Observe
        {
            return Err(corrupt(
                "held Source recovery requires recorded disposition",
            ));
        }
        if control.kind() == Kind::StorageHeld {
            let reply = record
                .original
                .accepted_reply
                .as_ref()
                .ok_or(corrupt("held Storage reply missing"))?;
            if required(control.prepared(), Tag::NativeReply)? != reply.to_canonical_bytes() {
                return Err(corrupt("held exact original Storage reply"));
            }
        }
        prefix.push(control);
    }
    if let Some(prepared) = record.suffix.prepared() {
        if prepared.scope() != &full {
            return Err(corrupt("held prepared original scope"));
        }
        validate_signer_scope(record, prepared)?;
        validate_predecessor(prepared, &prefix)?;
        if prepared.kind().is_recovery() && query(prepared)?.original_prepared != root.digest() {
            return Err(corrupt("held prepared recovery original preparation"));
        }
    }
    validate_phase(record)?;
    validate_assertions(record)
}

fn validate_signer_scope(
    record: &Record,
    control: &PreparedNativeHeldControlV1,
) -> Result<(), LedgerFormatErrorV1> {
    let native = record
        .original
        .canonical_request
        .as_ref()
        .ok_or(corrupt("held signer original request"))?;
    let expected = match control.kind().sender() {
        Owner::Root => NativeHeldSignerV1::SourceProvider(
            native.request().signed_root_request().signer().clone(),
        ),
        Owner::Provider => NativeHeldSignerV1::SourceProvider(native.signer().clone()),
        Owner::Storage => {
            let Some(reply) = record.original.accepted_reply.as_ref() else {
                // Cold12's current dedicated authority is authenticated by its
                // actual Storage owner. There is no invented earlier hot pin.
                return if control.kind() == Kind::StorageRecoveryState {
                    Ok(())
                } else {
                    Err(corrupt("held original Storage signer missing"))
                };
            };
            NativeHeldSignerV1::Storage(reply.acceptance().signer())
        }
    };
    let same_authority = match (control.signer(), &expected) {
        (
            NativeHeldSignerV1::SourceProvider(actual),
            NativeHeldSignerV1::SourceProvider(original),
        ) => actual.authority_id() == original.authority_id(),
        (NativeHeldSignerV1::Storage(actual), NativeHeldSignerV1::Storage(original)) => {
            actual.authority().0 == original.authority().0
        }
        _ => false,
    };
    if !same_authority || (!control.kind().is_recovery() && control.signer() != &expected) {
        return Err(corrupt("held original signer authority/role"));
    }
    Ok(())
}

fn retained<'a>(
    prefix: &[&'a SignedNativeHeldControlV1],
    kind: Kind,
) -> Result<&'a SignedNativeHeldControlV1, LedgerFormatErrorV1> {
    prefix
        .iter()
        .copied()
        .find(|control| control.kind() == kind)
        .ok_or(corrupt("held predecessor not yet retained"))
}

fn validate_predecessor(
    control: &PreparedNativeHeldControlV1,
    prefix: &[&SignedNativeHeldControlV1],
) -> Result<(), LedgerFormatErrorV1> {
    let kind = control.kind();
    let expected = match kind {
        Kind::RootPrepared | Kind::RootRecoveryQuery => return Ok(()),
        Kind::StorageHeld => {
            let root = retained(prefix, Kind::RootPrepared)?;
            if required(control, Tag::RootPrepared)? != root.to_canonical_bytes() {
                return Err(corrupt("held Storage exact original Root archive"));
            }
            root.digest()
        }
        Kind::ProviderHeld => {
            let storage = retained(prefix, Kind::StorageHeld)?;
            if required(control, Tag::StorageHeld)? != storage.to_canonical_bytes() {
                return Err(corrupt("held Provider exact original Storage archive"));
            }
            storage.digest()
        }
        Kind::RootAccepted => retained(prefix, Kind::ProviderHeld)?.digest(),
        Kind::RootClosed if control.scope().is_root_only() => {
            let root = retained(prefix, Kind::RootPrepared)?;
            if required(control, Tag::RootPrepared)? != root.to_canonical_bytes() {
                return Err(corrupt("held Closed exact original Root archive"));
            }
            root.digest()
        }
        Kind::RootClosed => retained(prefix, Kind::ProviderHeld)?.digest(),
        Kind::ProviderRelay => {
            let root = prefix
                .iter()
                .copied()
                .find(|value| matches!(value.kind(), Kind::RootAccepted | Kind::RootClosed))
                .ok_or(corrupt("held relay disposition missing"))?;
            if required(control, Tag::RootDispositionControl)? != root.to_canonical_bytes() {
                return Err(corrupt("held relay exact Root archive"));
            }
            root.digest()
        }
        Kind::StorageSettled => retained(prefix, Kind::ProviderRelay)?.digest(),
        Kind::ProviderSettled => retained(prefix, Kind::StorageSettled)?.digest(),
        Kind::RootTerminalRecorded => prefix
            .iter()
            .rev()
            .copied()
            .find(|control| {
                matches!(
                    control.kind(),
                    Kind::ProviderSettled | Kind::ProviderRecoveryState
                )
            })
            .ok_or(corrupt("held exact Source terminal predecessor"))?
            .digest(),
        Kind::ProviderStorageRecoveryQuery | Kind::ProviderRecoveryState => {
            let root = prefix
                .iter()
                .copied()
                .find(|value| {
                    value.kind() == Kind::RootRecoveryQuery
                        && query(value.prepared())
                            .is_ok_and(|q| q.mode == Mode::SettleRecordedDisposition)
                })
                .ok_or(corrupt("held first Root recovery query missing"))?;
            let q = query(control)?;
            let original = query(root.prepared())?;
            if q.recovery_session != original.recovery_session
                || q.mode != original.mode
                || (kind == Kind::ProviderRecoveryState && q != original)
                || (kind == Kind::ProviderStorageRecoveryQuery
                    && required(control, Tag::RootRecoveryControl)? != root.to_canonical_bytes())
            {
                return Err(corrupt("held current recovery query join"));
            }
            root.digest()
        }
        Kind::StorageRecoveryState => {
            let parent = retained(prefix, Kind::ProviderStorageRecoveryQuery)?;
            if query(control)? != query(parent.prepared())? {
                return Err(corrupt("held exact Storage child query"));
            }
            parent.digest()
        }
    };
    if control.predecessor() != expected {
        return Err(corrupt("held predecessor chronology"));
    }
    Ok(())
}

fn validate_phase(record: &Record) -> Result<(), LedgerFormatErrorV1> {
    let phase = record.suffix.phase();
    let r = root_disposition(record)?;
    if r.is_some() != (phase >= 7) {
        return Err(corrupt("held Root disposition phase"));
    }
    let closed = r
        .as_ref()
        .is_some_and(|r| r.disposition == Disposition::Closed);
    if !closed {
        let valid = match phase {
            0 | 1 => record.original.state == Outer::Requested,
            2 | 3 => record.original.state == Outer::Prepared,
            4..=10 => matches!(
                record.original.state,
                Outer::Active | Outer::CleanupRequired
            ),
            _ => false,
        };
        if !valid {
            return Err(corrupt("held original outer phase"));
        }
        for (earliest, kind) in [(2, Kind::StorageHeld), (6, Kind::ProviderHeld)] {
            if phase >= earliest && record.suffix.control(kind).is_none() {
                return Err(corrupt("held required normal prefix"));
            }
        }
    }
    if phase == 5
        && record
            .suffix
            .prepared()
            .is_none_or(|p| p.kind() != Kind::ProviderHeld)
    {
        return Err(corrupt("held phase5 preparation"));
    }
    if phase == 7
        && record.suffix.control(Kind::RootRecoveryQuery).is_none()
        && record.suffix.control(Kind::ProviderRelay).is_none()
        && record
            .suffix
            .prepared()
            .is_none_or(|control| control.kind() != Kind::ProviderRelay)
    {
        return Err(corrupt(
            "held disposition requires retained relay preparation",
        ));
    }
    if phase >= 8 && storage_assertion(record)?.is_none() {
        return Err(corrupt("held Storage settlement missing"));
    }
    if phase >= 9
        && record.suffix.control(Kind::ProviderSettled).is_none()
        && record.suffix.control(Kind::ProviderRecoveryState).is_none()
    {
        return Err(corrupt("held Provider terminal archive missing"));
    }
    Ok(())
}

pub(super) fn root_disposition(
    record: &Record,
) -> Result<Option<RootNativeDispositionAssertionV1>, LedgerFormatErrorV1> {
    let mut result = None;
    for control in record.suffix.controls() {
        let value = match control.kind() {
            Kind::RootAccepted | Kind::RootClosed => Some(
                RootNativeDispositionAssertionV1::from_canonical_bytes(required(
                    control.prepared(),
                    Tag::RootDispositionAssertion,
                )?)
                .map_err(schema_error)?,
            ),
            Kind::RootRecoveryQuery => {
                RootNativeRecoveryAssertionV1::from_canonical_bytes(required(
                    control.prepared(),
                    Tag::RootRecoveryAssertion,
                )?)
                .map_err(schema_error)?
                .disposition
            }
            _ => None,
        };
        if let Some(value) = value {
            if result.as_ref().is_some_and(|prior| prior != &value) {
                return Err(corrupt("held immutable Root disposition"));
            }
            result = Some(value);
        }
    }
    Ok(result)
}

pub(super) fn storage_assertion(
    record: &Record,
) -> Result<Option<StorageNativeSettlementAssertionV1>, LedgerFormatErrorV1> {
    let Some(root) = root_disposition(record)? else {
        return Ok(None);
    };
    let mut result = None;
    for control in record.suffix.controls() {
        let assertion = match control.kind() {
            Kind::StorageSettled => {
                let acceptance = record
                    .original
                    .accepted_reply
                    .as_ref()
                    .ok_or(corrupt("held original acceptance missing"))?
                    .acceptance()
                    .acceptance()
                    .clone();
                Some(StorageNativeSettlementAssertionV1 {
                    disposition: root.disposition,
                    scope: full_scope(record)?,
                    root_disposition: root.digest().map_err(schema_error)?,
                    acceptance,
                })
            }
            Kind::StorageRecoveryState => {
                let state = StorageNativeRecoveryStateV1::from_canonical_bytes(required(
                    control.prepared(),
                    Tag::StorageRecoveryState,
                )?)
                .map_err(schema_error)?;
                if state.fields.own_assertion.is_empty() {
                    None
                } else {
                    Some(
                        StorageNativeSettlementAssertionV1::from_canonical_bytes(
                            &state.fields.own_assertion,
                        )
                        .map_err(schema_error)?,
                    )
                }
            }
            _ => None,
        };
        if let Some(assertion) = assertion {
            if assertion.scope != full_scope(record)?
                || assertion.disposition != root.disposition
                || assertion.root_disposition != root.digest().map_err(schema_error)?
                || assertion.acceptance.request_digest() != record.original.native_request_digest
                || record
                    .original
                    .accepted_reply
                    .as_ref()
                    .is_some_and(|reply| reply.acceptance().acceptance() != &assertion.acceptance)
                || result.as_ref().is_some_and(|prior| prior != &assertion)
            {
                return Err(corrupt("held immutable Storage assertion"));
            }
            result = Some(assertion);
        }
    }
    Ok(result)
}

pub(super) fn artifact(record: &Record) -> Result<ObjectDigest, LedgerFormatErrorV1> {
    let mut result = None;
    for control in record
        .suffix
        .controls()
        .iter()
        .map(SignedNativeHeldControlV1::prepared)
        .chain(record.suffix.prepared())
    {
        let value = match control.kind() {
            Kind::ProviderHeld => Some(ObjectDigest::from_bytes(
                required(control, Tag::SourceArtifact)?
                    .try_into()
                    .map_err(|_| corrupt("held artifact width"))?,
            )),
            Kind::ProviderRecoveryState => {
                let state = ProviderNativeRecoveryStateV1::from_canonical_bytes(required(
                    control,
                    Tag::ProviderRecoveryState,
                )?)
                .map_err(schema_error)?;
                Some(
                    ProviderNativeSettlementAssertionV1::from_canonical_bytes(
                        &state.fields.own_assertion,
                    )
                    .map_err(schema_error)?
                    .source_artifact,
                )
            }
            _ => None,
        };
        if let Some(value) = value {
            if result.is_some_and(|prior| prior != value) {
                return Err(corrupt("held immutable Source artifact claims"));
            }
            result = Some(value);
        }
    }
    // A missing hot3 is not proof that Complete never happened. Intermediate
    // cold rows have no A field; terminal10 supplies its exact assertion and the
    // full graph independently joins A to the original completed response.
    Ok(result.unwrap_or(ObjectDigest::from_bytes([0; 32])))
}

pub(super) fn has_artifact_claim(record: &Record) -> bool {
    record
        .suffix
        .controls()
        .iter()
        .map(SignedNativeHeldControlV1::prepared)
        .chain(record.suffix.prepared())
        .any(|control| {
            matches!(
                control.kind(),
                Kind::ProviderHeld | Kind::ProviderRecoveryState
            )
        })
}

pub(super) fn acceptance(record: &Record) -> Result<ObjectDigest, LedgerFormatErrorV1> {
    if record.original.acceptance_payload_digest.as_bytes() != &[0; 32] {
        return Ok(record.original.acceptance_payload_digest);
    }
    // A cold signed12 can retain original acceptance metadata without the
    // missing positive reply, FD or outer Prepared/Active transition.
    Ok(storage_assertion(record)?
        .map(|assertion| assertion.acceptance.digest())
        .unwrap_or(ObjectDigest::from_bytes([0; 32])))
}

pub(super) fn settlement(
    record: &Record,
) -> Result<Option<NativeHeldSettlementV1>, LedgerFormatErrorV1> {
    let (Some(root), Some(storage)) = (root_disposition(record)?, storage_assertion(record)?)
    else {
        return Ok(None);
    };
    let provider = ProviderNativeSettlementAssertionV1 {
        disposition: root.disposition,
        scope: full_scope(record)?,
        root_disposition: root.digest().map_err(schema_error)?,
        storage_settlement: storage.digest().map_err(schema_error)?,
        source_artifact: artifact(record)?,
    };
    Ok(Some(NativeHeldSettlementV1 {
        disposition: root.disposition,
        root_disposition: provider.root_disposition,
        storage_settlement: provider.storage_settlement,
        provider_settlement: provider.digest().map_err(schema_error)?,
    }))
}

fn validate_assertions(record: &Record) -> Result<(), LedgerFormatErrorV1> {
    if let Some(root) = root_disposition(record)? {
        if root.scope.is_root_only() {
            full_scope(record)?
                .require_root_prefix(&root.scope)
                .map_err(schema_error)?;
        } else if root.scope != full_scope(record)? {
            return Err(corrupt("held Root assertion scope"));
        }
        if !root.scope.is_root_only() && root.source_artifact != artifact(record)? {
            return Err(corrupt("held Root artifact changed"));
        }
        if root.disposition == Disposition::Accepted
            && root.descriptor_commitment != record.original.descriptor_commitment
        {
            return Err(corrupt("held Root original descriptor"));
        }
    }
    let expected = settlement(record)?;
    for control in record
        .suffix
        .controls()
        .iter()
        .map(SignedNativeHeldControlV1::prepared)
        .chain(record.suffix.prepared())
    {
        if let Some(bytes) = control.section(Tag::Settlement) {
            let actual =
                NativeHeldSettlementV1::from_canonical_bytes(bytes).map_err(schema_error)?;
            let mut wanted =
                expected.ok_or(corrupt("held terminal without original assertions"))?;
            if control.kind() == Kind::StorageSettled {
                wanted.provider_settlement = ObjectDigest::from_bytes([0; 32]);
            }
            if actual != wanted {
                return Err(corrupt("held stable settlement IDs"));
            }
        }
        if control.kind() == Kind::ProviderRecoveryState {
            let state = ProviderNativeRecoveryStateV1::from_canonical_bytes(required(
                control,
                Tag::ProviderRecoveryState,
            )?)
            .map_err(schema_error)?;
            let wanted = expected.ok_or(corrupt("held recovery terminal without assertions"))?;
            if state.fields.native_request != record.original.native_request_digest
                || state.fields.acceptance != acceptance(record)?
                || state.fields.root_disposition != wanted.root_disposition
                || state.fields.storage_settlement != wanted.storage_settlement
                || state.fields.provider_settlement != wanted.provider_settlement
                || state.fields.disposition != root_disposition(record)?
            {
                return Err(corrupt("held Provider recovery row claims"));
            }
            let assertion = ProviderNativeSettlementAssertionV1::from_canonical_bytes(
                &state.fields.own_assertion,
            )
            .map_err(schema_error)?;
            if assertion.digest().map_err(schema_error)? != wanted.provider_settlement
                || assertion.scope != full_scope(record)?
                || assertion.source_artifact != artifact(record)?
            {
                return Err(corrupt("held Provider recovery own assertion"));
            }
        }
        if control.kind() == Kind::RootRecoveryQuery
            && query(control)?.mode == Mode::RecordRootTerminal
        {
            let state = RootNativeRecoveryAssertionV1::from_canonical_bytes(required(
                control,
                Tag::RootRecoveryAssertion,
            )?)
            .map_err(schema_error)?;
            if state.settlement != expected {
                return Err(corrupt("held actual Root terminal proof"));
            }
        }
    }
    Ok(())
}
