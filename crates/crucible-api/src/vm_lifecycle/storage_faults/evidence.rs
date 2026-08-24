//! Storage transaction accounting and canonical evidence helpers.

use super::*;
pub(super) fn absorb_intake(
    aggregate: &mut QemuLiveBlockIoServiceStep,
    intake: QemuLiveBlockIoIntakeStep,
) -> Result<(), QemuAsyncDriverRuntimeError> {
    aggregate.processed = aggregate
        .processed
        .checked_add(intake.processed)
        .ok_or_else(|| {
            storage_error(
                "account coordinated block service",
                "request count overflow",
            )
        })?;
    aggregate.write_frames_processed = aggregate
        .write_frames_processed
        .checked_add(intake.write_frames_processed)
        .ok_or_else(|| {
            storage_error("account coordinated block service", "write count overflow")
        })?;
    aggregate.first_request_icount = aggregate
        .first_request_icount
        .or(intake.first_request_icount);
    aggregate.computed_completion_icount = aggregate
        .computed_completion_icount
        .or(intake.computed_completion_icount);
    aggregate.next_completion_icount = intake.next_completion_icount;
    Ok(())
}

pub(super) fn bind_recovery_subscription_sequence(
    directive: &mut crucible_device::block::ResolvedBlockFaultDirective,
    same_coordinate_sequence: u64,
) {
    if directive.retention_recovery_event.is_some() {
        directive.retention_recovery_after_sequence = Some(same_coordinate_sequence);
    }
}

pub(super) fn absorb_delivery(
    aggregate: &mut QemuLiveBlockIoServiceStep,
    delivery: QemuLiveBlockIoDeliveryStep,
) -> Result<(), QemuAsyncDriverRuntimeError> {
    aggregate.delivered = aggregate
        .delivered
        .checked_add(delivery.delivered)
        .ok_or_else(|| {
            storage_error(
                "account coordinated block service",
                "delivery count overflow",
            )
        })?;
    aggregate.next_completion_icount = delivery.next_completion_icount;
    Ok(())
}

pub(super) fn block_targets_same_device(
    left: &ResolvedFaultTarget,
    right: &ResolvedFaultTarget,
) -> bool {
    let device = |target: &ResolvedFaultTarget| match target {
        ResolvedFaultTarget::BlockDevice { device }
        | ResolvedFaultTarget::BlockRange { device, .. } => Some(*device),
        _ => None,
    };
    device(left)
        .zip(device(right))
        .is_some_and(|(left, right)| left == right)
}

pub(super) fn storage_array_target_attaches_device(
    world: &World,
    candidate: &ResolvedFaultTarget,
    attached: &ResolvedFaultTarget,
) -> bool {
    let ResolvedFaultTarget::StorageArray { array, .. } = candidate else {
        return false;
    };
    let attached = match attached {
        ResolvedFaultTarget::BlockDevice { device }
        | ResolvedFaultTarget::BlockRange { device, .. } => *device,
        _ => return false,
    };
    world
        .fault_topology()
        .storage_arrays
        .iter()
        .find(|candidate| candidate.id.as_str() == array.as_str())
        .is_some_and(|array| storage_array_attaches_hash(world, array, attached))
}

pub(super) fn storage_array_attaches_device(
    world: &World,
    array: &crucible::model::WorldStorageArray,
    attached: &ResolvedFaultTarget,
) -> bool {
    match attached {
        ResolvedFaultTarget::BlockDevice { device }
        | ResolvedFaultTarget::BlockRange { device, .. } => {
            storage_array_attaches_hash(world, array, *device)
        }
        _ => false,
    }
}

pub(super) fn storage_array_attaches_hash(
    world: &World,
    array: &crucible::model::WorldStorageArray,
    attached: ContentHash,
) -> bool {
    world
        .io_nodes()
        .any(|node| node.id.name == array.device.as_str() && node.fault_target_hash() == attached)
}

pub(super) fn block_target_intersects_request(
    target: &ResolvedFaultTarget,
    request: &BlockRequest,
) -> bool {
    match request.op {
        BlockOp::Read | BlockOp::Write | BlockOp::Discard => {
            block_target_intersects_range(target, request.offset, u64::from(request.count))
        }
        BlockOp::Flush | BlockOp::GetLength => matches!(
            target,
            ResolvedFaultTarget::BlockDevice { .. } | ResolvedFaultTarget::BlockRange { .. }
        ),
    }
}

pub(super) fn block_target_intersects_range(
    target: &ResolvedFaultTarget,
    offset: u64,
    length: u64,
) -> bool {
    match target {
        ResolvedFaultTarget::BlockDevice { .. } => true,
        ResolvedFaultTarget::BlockRange {
            start_byte,
            length_bytes,
            ..
        } => offset
            .checked_add(length)
            .zip(start_byte.checked_add(*length_bytes))
            .is_some_and(|(end, target_end)| offset < target_end && *start_byte < end),
        _ => false,
    }
}

pub(super) fn retained_release_evidence(
    identity: crucible_device::block::BlockRequestIdentity,
    release: BlockRetainedRelease,
    release_nanos: u64,
    cause: Option<ContentHash>,
) -> ContentHash {
    let release = match release {
        BlockRetainedRelease::Recovery { .. } => "recovery",
        BlockRetainedRelease::Timeout => "timeout",
    };
    ContentHash::from_canonical_material(
        "crucible.storage-retained-release-evidence.v1",
        &format!(
            "epoch={}\nrequest_id={}\nrelease={release}\nrelease_nanos={release_nanos}\ncause={}",
            identity.epoch,
            identity.request_id,
            cause.map_or_else(|| String::from("none"), |value| value.to_hex()),
        ),
    )
}

pub(super) fn ninep_object_evidence(object: &NinepObjectVersion) -> String {
    format!(
        "path={}\nversion={}\nmode={}\ndeleted={}\ndata_len={}\ndata_digest={}",
        object.path,
        object.version,
        object.mode,
        object.deleted,
        object.data.len(),
        ContentHash {
            bytes: *blake3::hash(&object.data).as_bytes(),
        }
        .to_hex(),
    )
}

pub(super) fn ninep_result_evidence(
    action: &ResolvedBindingAction,
    request: &NinepRequestOpportunity,
    selected: &NinepResultDirective,
    response: LiveNinepResponseEvidence,
) -> ContentHash {
    let result = match selected {
        NinepResultDirective::Normal => String::from("kind=normal"),
        NinepResultDirective::Errno(errno) => format!("kind=errno\nerrno={errno}"),
        NinepResultDirective::Stale(object) => {
            format!("kind=stale\n{}", ninep_object_evidence(object))
        }
        NinepResultDirective::Misdirected(object) => {
            format!("kind=misdirected\n{}", ninep_object_evidence(object))
        }
    };
    let status = match response.status {
        crucible_device::ResponseStatus::Ok => "ok",
        crucible_device::ResponseStatus::Error => "error",
    };
    ContentHash::from_canonical_material(
        "crucible.ninep-result-evidence.v1",
        &format!(
            "action={}\nrequest_icount={}\ntransport_sequence={}\ntag={}\nrequest_digest={}\noperation={:?}\n{result}\ncompletion_icount={}\nresponse_transport_sequence={}\nresponse_status={status}\nresponse_len={}\nresponse_digest={}",
            action.committed_state_id().to_hex(),
            request.identity.request_icount,
            request.identity.transport_sequence,
            request.identity.tag,
            ContentHash {
                bytes: request.identity.digest,
            }
            .to_hex(),
            request.operation,
            response.completion_icount,
            response.transport_sequence,
            response.payload_len,
            ContentHash {
                bytes: response.payload_digest,
            }
            .to_hex(),
        ),
    )
}

// crucible-lint: allow rust-allow -- visibility evidence commits every independent action, version, policy, and release field.
#[allow(clippy::too_many_arguments)]
pub(super) fn ninep_visibility_evidence(
    action: &ResolvedBindingAction,
    update_id: ContentHash,
    sequence: u64,
    object: &NinepObjectVersion,
    policy: NinepVisibilityPolicy,
    release: NinepVisibilityRelease,
    data_lag_nanos: u64,
    writer_session: u64,
    state: &NinepVisibilityState,
) -> ContentHash {
    let scope = match policy.scope {
        NinepVisibilityScope::Global => "global",
        NinepVisibilityScope::PerSession => "per_session",
        NinepVisibilityScope::WriterImmediate => "writer_immediate",
    };
    let release = match release {
        NinepVisibilityRelease::AtNanos(nanos) => format!("at_nanos:{nanos}"),
        NinepVisibilityRelease::OnEvent(event) => {
            format!("on_event:{}", ContentHash { bytes: event }.to_hex(),)
        }
    };
    let frontiers = state
        .session_frontiers()
        .into_iter()
        .map(|(session, metadata, data)| format!("{session}:{metadata}:{data}"))
        .collect::<Vec<_>>()
        .join(",");
    let lookup =
        ninep_visibility_lookup_evidence(state.lookup_object(writer_session, object.path.as_str()));
    ContentHash::from_canonical_material(
        "crucible.ninep-visibility-evidence.v1",
        &format!(
            "action={}\nupdate_id={}\nsequence={sequence}\n{}\nscope={scope}\natomic_metadata_and_data={}\nretain_deleted_objects={}\nrelease={release}\ndata_lag_nanos={data_lag_nanos}\nwriter_session={writer_session}\ncommitted_frontier={}\nsession_frontiers={frontiers}\nlookup={lookup}",
            action.committed_state_id().to_hex(),
            update_id.to_hex(),
            ninep_object_evidence(object),
            policy.atomic_metadata_and_data,
            policy.retain_deleted_objects,
            state.committed_frontier(),
        ),
    )
}

pub(super) fn ninep_visibility_lookup_evidence(lookup: NinepVisibilityLookup) -> String {
    match lookup {
        NinepVisibilityLookup::Base => String::from("base"),
        NinepVisibilityLookup::Deleted => String::from("deleted"),
        NinepVisibilityLookup::Object(object) => {
            format!(
                "object:{}",
                ninep_object_evidence(&object).replace('\n', ";")
            )
        }
    }
}

pub(super) fn ninep_visibility_advance_evidence(
    session: u64,
    before: (u64, u64),
    after: (u64, u64),
    observed_nanos: u64,
    events: &BTreeMap<[u8; 32], u64>,
    updates: &[NinepVisibilityUpdate],
    state: &NinepVisibilityState,
) -> ContentHash {
    let updates = updates
        .iter()
        .map(|update| {
            let release = match update.release {
                NinepVisibilityRelease::AtNanos(deadline) => {
                    format!("deadline:{deadline}:satisfied_at:{deadline}")
                }
                NinepVisibilityRelease::OnEvent(event) => format!(
                    "event:{}:observed_at:{}",
                    ContentHash { bytes: event }.to_hex(),
                    events
                        .get(&event)
                        .map_or_else(|| String::from("absent"), u64::to_string),
                ),
            };
            format!(
                "sequence={};writer_session={};release={release};lookup={}",
                update.sequence,
                update.writer_session,
                ninep_visibility_lookup_evidence(
                    state.lookup_object(session, update.object.path.as_str())
                ),
            )
        })
        .collect::<Vec<_>>()
        .join("|");
    ContentHash::from_canonical_material(
        "crucible.ninep-visibility-advance-evidence.v1",
        &format!(
            "session={session}\nobserved_nanos={observed_nanos}\nmetadata_before={}\nmetadata_after={}\ndata_before={}\ndata_after={}\nupdates={updates}",
            before.0, after.0, before.1, after.1,
        ),
    )
}

pub(super) fn volatile_cache_loss_evidence(resolved: &ResolvedVolatileCacheLoss) -> ContentHash {
    let list = |values: &[u64]| {
        values
            .iter()
            .map(u64::to_string)
            .collect::<Vec<_>>()
            .join(",")
    };
    ContentHash::from_canonical_material(
        "crucible.storage-volatile-cache-loss-evidence.v1",
        &format!(
            "entry_set_digest={}\neligible={}\nprotected={}\nselected={}\ndurable_frontier_before={}\ndurable_frontier_after={}",
            ContentHash {
                bytes: resolved.entry_set_digest
            }
            .to_hex(),
            list(&resolved.eligible_sequences),
            list(&resolved.protected_sequences),
            list(&resolved.selected_sequences),
            resolved.durable_frontier_before,
            resolved.durable_frontier_after,
        ),
    )
}

pub(super) fn controller_transition_evidence(
    transition: &crucible_device::block::ResolvedBlockControllerTransition,
) -> ContentHash {
    ContentHash::from_canonical_material(
        "crucible.storage-controller-transition-evidence.v1",
        &format!(
            "failure_result={:?}\nunadmitted={:?}\nqueued={:?}\nexecuting={:?}\nresolved={:?}\ncompleted_undelivered={:?}\ncontroller_buffer={:?}\nvolatile_cache={:?}\nrequest_ids={:?}\nduplicate_history={:?}\ntopology={:?}\nrecovery_nanos={}",
            transition.failure_result,
            transition.unadmitted,
            transition.queued,
            transition.executing,
            transition.resolved,
            transition.completed_undelivered,
            transition.controller_buffer,
            transition.volatile_cache,
            transition.request_ids,
            transition.duplicate_history,
            transition.topology,
            transition.recovery_nanos,
        ),
    )
}

pub(super) fn persistence_media_evidence(outcome: &BlockPersistenceMediaOutcome) -> ContentHash {
    let spans = outcome
        .applied_spans
        .iter()
        .map(|span| format!("{}:{}", span.start, span.length))
        .collect::<Vec<_>>()
        .join(",");
    ContentHash::from_canonical_material(
        "crucible.storage-persistence-media-evidence.v1",
        &format!(
            "sequence={}\nrequest_id={}\noperation_sequence={}\noperation={}\nrequest_digest={}\noffset={}\ncount={}\nintended_digest={}\nready_nanos={}\nexecuted_nanos={}\napplied_spans={}\nmedia_failed={}\napplied_digest={}",
            outcome.opportunity.sequence,
            outcome.opportunity.request_id,
            outcome.opportunity.operation_sequence,
            outcome.opportunity.operation.to_wire(),
            ContentHash {
                bytes: outcome.opportunity.request_digest
            }
            .to_hex(),
            outcome.opportunity.offset,
            outcome.opportunity.count,
            ContentHash {
                bytes: outcome.opportunity.intended_digest
            }
            .to_hex(),
            outcome.opportunity.ready_nanos,
            outcome.executed_nanos,
            spans,
            outcome.media_failed,
            ContentHash {
                bytes: outcome.applied_digest
            }
            .to_hex(),
        ),
    )
}

pub(super) fn storage_service_evidence(outcome: &BlockServiceCompletion) -> ContentHash {
    ContentHash::from_canonical_material(
        "crucible.storage-service-evidence.v1",
        &format!(
            "contributor={}\nsequence={}\nstarted_nanos={}\nfinished_nanos={}\nbusy_epoch_bytes={}\nbusy_epoch_operations={}",
            ContentHash {
                bytes: outcome.contributor
            }
            .to_hex(),
            outcome.sequence,
            outcome.started_nanos,
            outcome.finished_nanos,
            outcome.busy_epoch_bytes,
            outcome.busy_epoch_operations,
        ),
    )
}

pub(super) fn storage_error(
    operation: &'static str,
    error: impl std::fmt::Display,
) -> QemuAsyncDriverRuntimeError {
    QemuAsyncDriverRuntimeError::new(operation, error.to_string())
}
