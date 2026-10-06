//! Frozen world capture, authenticated RAM publication, and native commit.
//!
//! This module owns the exact checkpoint transaction after the scheduler has
//! reserved its cut. It preserves native capture generations and source leases
//! through durable publication, commit, and uncertain-outcome reconciliation.

use super::super::checkpoint_store::{
    PersistExactCheckpointError, hash_exact_checkpoint_open_file_sha256_with_boundary,
    prepare_exact_checkpoint_set_with_boundary,
    stage_open_checkpoint_artifact_chunks_with_boundary,
    stage_sparse_checkpoint_artifact_chunks_with_boundary,
};
use super::*;

impl ProductionVmLifecycleLoop {
    /// Captures and publishes one scheduler-reserved exact world boundary.
    ///
    /// # Errors
    ///
    /// Preserves unpublished capture cleanup or indeterminate native commit
    /// ownership when capture, authentication, publication, or supervision fails.
    pub(super) fn capture_reserved_exact_checkpoint_set(
        &mut self,
        configuration: &Configuration,
        terminal_nodes: &BTreeSet<NodeId>,
        boundary: &mut dyn FnMut() -> Result<(), SchedulerError>,
    ) -> Result<ContentHash, ExactCheckpointTransactionError> {
        self.require_published_host_continuation()?;
        boundary()?;
        if !self.continuation_branches.is_empty() {
            return Err(SchedulerError::BoundaryViolation {
                message: String::from(
                    "exact checkpoint cannot retain unapplied cold-replay branch generations",
                ),
            }
            .into());
        }
        let checkpoint_virtual_time = self.inner.loop_impl().frontier();
        let network_committed_frontier = self.inner.committed_frontier();
        let fault_checkpoint = {
            let (scheduler, backend, interceptor, pending_outputs) =
                self.inner.network_transaction_parts_mut();
            interceptor
                .checkpoint(
                    scheduler,
                    network_committed_frontier,
                    pending_outputs,
                    backend,
                )
                .map_err(|error| SchedulerError::BoundaryViolation {
                    message: format!(
                        "capture signal, network, and device continuation at exact checkpoint boundary: {error}"
                    ),
                })?
        };
        boundary()?;
        let mut node_icounts = BTreeMap::new();
        let mut boundaries = Vec::new();
        for vm in self.source.world().vm_nodes() {
            boundary()?;
            if self.node_service_states.get(&vm.id)
                == Some(&ProductionNodeServiceState::PermanentlyFailed)
            {
                node_icounts.insert(vm.id.clone(), self.checkpoint_node_icount(&vm.id)?);
                continue;
            }
            let physical = self
                .inner
                .backend()
                .node_now(&vm.id)
                .map_err(SchedulerError::from)?;
            node_icounts.insert(
                vm.id.clone(),
                crucible::Icount {
                    retired: physical.ticks,
                },
            );
            let service_state = self
                .node_service_states
                .get(&vm.id)
                .copied()
                .ok_or_else(|| SchedulerError::BoundaryViolation {
                    message: format!("exact checkpoint has no service state for `{}`", vm.id.name),
                })?;
            boundaries.push((vm.id.clone(), physical.ticks, service_state));
        }

        // Own every scheduler/controller input before the first QMP save can
        // pause a running node. Immutable object and manifest preparation is
        // fallible but remains rollback-safe under the capture owners below.
        let event_log_objects = Arc::new(
            self.inner
                .loop_impl()
                .event_log_dependency_objects()
                .map_err(|error| SchedulerError::BoundaryViolation {
                    message: format!("capture exact event-log closure: {error}"),
                })?
                .into_iter()
                .collect(),
        );
        let scheduler = self.inner.loop_impl().checkpoint().map_err(|error| {
            SchedulerError::BoundaryViolation {
                message: format!("capture exact scheduler continuation: {error}"),
            }
        })?;
        let signal_artifact_objects = self.signal_artifact_objects.clone();
        let trigger_state = self.trigger_state.clone();
        let assertion_state = self
            .assertion_evaluator
            .checkpoint()
            .map_err(SchedulerError::from)?;
        let terminal_verdict = self.terminal_verdict.clone();
        let terminal_cause = self.checkpoint_terminal_cause.clone();
        let branch = self.branch.clone();
        let recorded_controls = self.recorded_controls.clone();
        let node_generations = self.node_generations.clone();
        let node_service_states = self.node_service_states.clone();
        let resource_limits = self.source.plan().fault_signals().resource_limits();
        let fault_manifest_identity =
            exact_checkpoint_fault_object_identity(&fault_checkpoint, resource_limits).map_err(
                |error| SchedulerError::BoundaryViolation {
                    message: error.to_string(),
                },
            )?;

        boundary()?;
        let checkpoint_parent = self._run_directory.path().join("exact-checkpoints");
        fs::create_dir_all(&checkpoint_parent).map_err(|error| {
            SchedulerError::BoundaryViolation {
                message: format!(
                    "create exact checkpoint parent directory {}: {error}",
                    checkpoint_parent.display()
                ),
            }
        })?;
        let staging = tempfile::Builder::new()
            .prefix(".exact-checkpoint-")
            .tempdir_in(&checkpoint_parent)
            .map_err(|error| SchedulerError::BoundaryViolation {
                message: format!(
                    "create exact checkpoint staging directory in {}: {error}",
                    checkpoint_parent.display()
                ),
            })?;

        let prepared_targets = prepare_exact_checkpoint_targets(
            configuration,
            checkpoint_virtual_time,
            &node_icounts,
            boundaries,
            &self.node_indexes,
            &self.node_run_directories,
            staging.path(),
        )?;
        boundary()?;
        let mut captured = Vec::new();
        captured
            .try_reserve_exact(prepared_targets.len())
            .map_err(|error| SchedulerError::BoundaryViolation {
                message: format!("reserve exact checkpoint capture owners: {error}"),
            })?;
        let mut artifact_bytes = 0_u64;
        let capture_result = (|| -> Result<(), SchedulerError> {
            for prepared in prepared_targets {
                boundary()?;
                let PreparedExactCheckpointTarget {
                    node,
                    counter,
                    scheduler_time,
                    service_state,
                    checkpoint,
                    source_overlay,
                    staged_overlay_chunks,
                    page_capture_output,
                    device_output,
                    staged_device_chunks,
                } = prepared;
                let immutable_root_image = self
                    .launch_configs
                    .get(&node)
                    .and_then(QemuLiveNodeStepGateConfig::root_image)
                    .ok_or_else(|| SchedulerError::BoundaryViolation {
                        message: format!(
                            "exact checkpoint has no immutable root image for `{}`",
                            node.name
                        ),
                    })?;
                let epoch = self
                    .inner
                    .backend_mut()
                    .query_exact_checkpoint_epoch(&node)?;
                if epoch.candidate().is_some() {
                    return Err(SchedulerError::BoundaryViolation {
                        message: format!(
                            "exact checkpoint capture for `{}` found an unresolved QEMU candidate",
                            node.name
                        ),
                    });
                }
                let committed = epoch.committed();
                let committed_capture_generation = epoch.committed_capture_generation();
                let (_parent_closure, parent_checkpoint) = retained_exact_ram_parent_for_committed(
                    &self.exact_ram_parents,
                    self.repository_exact_ram_rebase.as_ref(),
                    &node,
                    committed,
                )?;
                let capture_boundary = || crucible_qemu::QemuExactCheckpointCaptureBoundary {
                    configuration,
                    immutable_root_image,
                    node: &node,
                    counter,
                    scheduler_time,
                    checkpoint: &checkpoint,
                    fault: &fault_checkpoint,
                    scheduler: &scheduler,
                };
                let capture_outputs = || crucible_qemu::QemuExactCheckpointCaptureOutputs {
                    maximum_ram_bytes: resource_limits.fat_checkpoint_bytes,
                    maximum_device_bytes: resource_limits.fat_checkpoint_bytes,
                    ram: &page_capture_output,
                    device: &device_output,
                };
                let catalog = if let Some(parent) = &parent_checkpoint {
                    parent.catalog.clone()
                } else {
                    checkpoint_store::paged::PagedRamCatalog::open(
                        &self.config.run_state_root,
                        self.scenario.id(),
                        resource_limits,
                        self.config.ram_catalog_provider(),
                    )?
                };
                let publication_catalog = catalog.clone();
                let admission = QemuExactCheckpointCaptureAdmission::admit_paged(
                    capture_boundary(),
                    committed,
                    capture_outputs(),
                    parent_checkpoint.is_none(),
                )
                .map_err(|error| SchedulerError::BoundaryViolation {
                    message: format!("admit exact checkpoint capture outputs: {error}"),
                })?
                .with_ram_publication_preflight(move |record| {
                    publication_catalog
                        .store()
                        .admit_ram_publication(record.topology(), crucible_ram::Scope::Exact)
                        .map_err(std::io::Error::other)
                });
                let terminal_capture = terminal_nodes.contains(&node);
                let mut exact_capture = match service_state {
                    ProductionNodeServiceState::Running if terminal_capture => self
                        .inner
                        .backend_mut()
                        .capture_exact_checkpoint_terminal_guarded(&node, checkpoint, admission)?,
                    ProductionNodeServiceState::Running => self
                        .inner
                        .backend_mut()
                        .capture_exact_checkpoint_for_publication_guarded(
                            &node, checkpoint, admission,
                        )?,
                    ProductionNodeServiceState::PoweredOff => self
                        .inner
                        .backend_mut()
                        .capture_exact_checkpoint_paused_guarded(&node, checkpoint, admission)?,
                    ProductionNodeServiceState::PermanentlyFailed => {
                        return Err(SchedulerError::BoundaryViolation {
                            message: format!(
                                "permanently failed node `{}` unexpectedly reached snapshot capture",
                                node.name
                            ),
                        });
                    }
                };
                let overlay_file = self
                    .node_leases
                    .get(&node)
                    .ok_or_else(|| SchedulerError::BoundaryViolation {
                        message: format!(
                            "exact checkpoint has no generation lease for `{}`",
                            node.name
                        ),
                    })?
                    .open_checkpoint_root_overlay()
                    .map_err(|error| SchedulerError::BoundaryViolation {
                        message: format!(
                            "open pinned exact-checkpoint overlay for `{}`: {error}",
                            node.name
                        ),
                    })?;
                captured.push(PendingExactCapture {
                    node,
                    counter,
                    scheduler_time,
                    snapshot: exact_capture.snapshot().clone(),
                    overlay_artifact: None,
                    exact_ram: None,
                    exact_checkpoint: Some(PendingExactCheckpointCandidate {
                        identity: exact_capture.identity(),
                        capture_generation: exact_capture.capture_generation(),
                        parent: committed,
                        parent_capture_generation: committed_capture_generation,
                    }),
                    snapshot_cleanup_pending: false,
                    resume_pending: service_state == ProductionNodeServiceState::Running
                        && !terminal_capture,
                });
                let capture =
                    captured
                        .last_mut()
                        .ok_or_else(|| SchedulerError::BoundaryViolation {
                            message: String::from(
                                "exact checkpoint capture owner disappeared after insertion",
                            ),
                        })?;
                let overlay_artifact = stage_sparse_checkpoint_artifact_chunks_with_boundary(
                    &overlay_file,
                    &source_overlay,
                    &staged_overlay_chunks,
                    "root overlay",
                    artifact_bytes,
                    resource_limits,
                    boundary,
                )?;
                artifact_bytes = artifact_bytes
                    .checked_add(overlay_artifact.length)
                    .ok_or_else(|| SchedulerError::BoundaryViolation {
                        message: String::from("exact-checkpoint artifact byte accounting overflow"),
                    })?;
                capture.overlay_artifact = Some(overlay_artifact);

                let expected_device_bytes = exact_capture.device_bytes();
                let device_file = exact_capture.device_output_mut();
                let device_length = device_file
                    .metadata()
                    .map_err(|error| SchedulerError::BoundaryViolation {
                        message: format!("inspect captured device VMState: {error}"),
                    })?
                    .len();
                if device_length != expected_device_bytes {
                    return Err(SchedulerError::BoundaryViolation {
                        message: String::from("device VMState length differs from frozen capture"),
                    });
                }
                let device_content_sha256 = hash_exact_checkpoint_open_file_sha256_with_boundary(
                    device_file,
                    &device_output,
                    boundary,
                )?;
                let device_artifact = stage_open_checkpoint_artifact_chunks_with_boundary(
                    device_file,
                    &device_output,
                    &staged_device_chunks,
                    "exact device VMState",
                    artifact_bytes,
                    resource_limits,
                    boundary,
                )?;
                artifact_bytes = artifact_bytes
                    .checked_add(device_artifact.length)
                    .ok_or_else(|| SchedulerError::BoundaryViolation {
                        message: String::from("exact checkpoint artifact byte accounting overflow"),
                    })?;

                let expected_record = exact_capture.paged_record().clone();
                if expected_record.scope() != crucible_ram::Scope::Exact {
                    return Err(SchedulerError::BoundaryViolation {
                        message: String::from("QEMU capture has the wrong RAM coverage scope"),
                    });
                }
                resource_limits
                    .reserve(
                        "fat_checkpoint_bytes",
                        artifact_bytes,
                        expected_record.topology().total_logical_bytes(),
                    )
                    .map_err(|error| SchedulerError::BoundaryViolation {
                        message: format!("admit complete logical RAM capture: {error}"),
                    })?;
                let ram_boundary_failure = std::cell::RefCell::new(None);
                let mut ram_boundary = || {
                    boundary().map_err(|error| {
                        let description = error.to_string();
                        *ram_boundary_failure.borrow_mut() = Some(error);
                        crucible_cas::ram::RamStoreError::Retention(description)
                    })
                };
                let ram = if exact_capture.initial_capture() {
                    let mut read_page =
                        |region: &crucible_ram::RegionDescriptor, index, output: &mut [u8]| {
                            let page = exact_capture
                                .read_next_page()
                                .map_err(|error| {
                                    crucible_cas::ram::RamStoreError::Logical(error.to_string())
                                })?
                                .ok_or(crucible_cas::ram::RamStoreError::Invalid(
                                    "truncated initial RAM capture",
                                ))?;
                            if page.region_id != region.id()
                                || page.page_index != index
                                || page.bytes.len() != output.len()
                                || page.version == 0
                            {
                                return Err(crucible_cas::ram::RamStoreError::Invalid(
                                    "initial RAM capture page coordinate",
                                ));
                            }
                            output.copy_from_slice(&page.bytes);
                            Ok(())
                        };
                    let ram = catalog
                        .capture(
                            expected_record.topology().clone(),
                            &mut read_page,
                            &mut ram_boundary,
                        )
                        .map_err(|error| {
                            ram_boundary_failure.borrow_mut().take().unwrap_or_else(|| {
                                SchedulerError::BoundaryViolation {
                                    message: format!("persist initial paged RAM capture: {error}"),
                                }
                            })
                        })?;
                    if exact_capture
                        .read_next_page()
                        .map_err(|error| SchedulerError::BoundaryViolation {
                            message: format!("validate end of initial RAM capture: {error}"),
                        })?
                        .is_some()
                    {
                        return Err(SchedulerError::BoundaryViolation {
                            message: String::from("initial RAM capture has trailing pages"),
                        });
                    }
                    ram
                } else {
                    let parent = parent_checkpoint.as_ref().ok_or_else(|| {
                        SchedulerError::BoundaryViolation {
                            message: String::from(
                                "incremental RAM capture has no leased complete image",
                            ),
                        }
                    })?;
                    if parent.ram.record().topology() != expected_record.topology() {
                        return Err(SchedulerError::BoundaryViolation {
                            message: String::from("incremental RAM capture changed topology"),
                        });
                    }
                    let mut next = || {
                        exact_capture
                            .read_next_page()
                            .map_err(|error| {
                                crucible_cas::ram::RamStoreError::Logical(error.to_string())
                            })?
                            .map(|page| {
                                if page.version == 0 {
                                    return Err(crucible_cas::ram::RamStoreError::Invalid(
                                        "zero RAM capture page version",
                                    ));
                                }
                                Ok(crucible_cas::ram::RamPageChange {
                                    region_id: page.region_id,
                                    page_index: page.page_index,
                                    bytes: page.bytes,
                                })
                            })
                            .transpose()
                    };
                    catalog
                        .store()
                        .update_with_reader(
                            &parent.ram,
                            &mut next,
                            catalog
                                .retention()
                                .map_err(|error| SchedulerError::BoundaryViolation {
                                    message: format!("admit incremental RAM root: {error}"),
                                })?
                                .as_ref(),
                            &mut ram_boundary,
                        )
                        .map_err(|error| {
                            ram_boundary_failure.borrow_mut().take().unwrap_or_else(|| {
                                SchedulerError::BoundaryViolation {
                                    message: format!(
                                        "persist incremental paged RAM capture: {error}"
                                    ),
                                }
                            })
                        })?
                };
                if ram.record() != &expected_record {
                    return Err(SchedulerError::BoundaryViolation {
                        message: String::from(
                            "persisted RAM image differs from QEMU's frozen root",
                        ),
                    });
                }
                artifact_bytes = artifact_bytes
                    .checked_add(expected_record.topology().total_logical_bytes())
                    .ok_or_else(|| SchedulerError::BoundaryViolation {
                        message: String::from("complete RAM checkpoint byte accounting overflow"),
                    })?;
                let exact_ram = ProductionExactRamCheckpoint::from_paged_capture(
                    exact_capture.identity().into(),
                    device_content_sha256,
                    device_artifact,
                    catalog,
                    ram,
                )?;
                capture.exact_ram = Some(exact_ram);
                boundary()?;
            }
            Ok(())
        })();
        if let Err(error) = capture_result {
            let cleanup =
                self.release_exact_captures(&mut captured, ExactCaptureDisposition::Unpublished);
            return combine_exact_checkpoint_transaction(
                Err(ExactCheckpointTransactionError::Unpublished(error)),
                cleanup,
                captured,
            );
        }

        let preparation = (|| -> Result<_, ExactCheckpointTransactionError> {
            let mut targets = BTreeMap::new();
            for capture in &captured {
                boundary()?;
                let overlay_artifact = capture.overlay_artifact.clone().ok_or_else(|| {
                    SchedulerError::BoundaryViolation {
                        message: format!(
                            "exact checkpoint root overlay for `{}` is not staged",
                            capture.node.name
                        ),
                    }
                })?;
                let exact_ram =
                    capture
                        .exact_ram
                        .clone()
                        .ok_or_else(|| SchedulerError::BoundaryViolation {
                            message: format!(
                                "exact checkpoint RAM closure for `{}` is not staged",
                                capture.node.name
                            ),
                        })?;
                let immutable_backing = self
                    .immutable_root_images
                    .get(&capture.node)
                    .copied()
                    .ok_or_else(|| SchedulerError::BoundaryViolation {
                        message: format!(
                            "exact checkpoint has no immutable root-image identity for `{}`",
                            capture.node.name
                        ),
                    })?;
                let manifest_basis = ExactCheckpointTargetManifestBasis {
                    configuration: configuration.id(),
                    immutable_backing,
                    node: &capture.node,
                    counter: capture.counter,
                    scheduler_time: capture.scheduler_time,
                    snapshot: exact_checkpoint_snapshot_object_identity(
                        &capture.snapshot,
                        resource_limits,
                    )
                    .map_err(|error| SchedulerError::BoundaryViolation {
                        message: error.to_string(),
                    })?,
                    fault_identity: fault_manifest_identity,
                    overlay: overlay_artifact.identity,
                    device_state: exact_ram.device_artifact.identity,
                };
                let manifest_identity =
                    exact_ram_checkpoint_target_manifest_identity(manifest_basis, &exact_ram);
                targets.insert(
                    capture.node.clone(),
                    ProductionVmExactCheckpointTarget {
                        configuration: Arc::new(configuration.clone()),
                        immutable_backing,
                        counter: capture.counter,
                        scheduler_time: capture.scheduler_time,
                        snapshot: capture.snapshot.clone(),
                        materialization: ProductionVmExactCheckpointMaterialization::Native {
                            overlay_artifact,
                            exact_ram: Box::new(exact_ram),
                            manifest_identity,
                        },
                    },
                );
            }

            validate_failed_host_io_topology(
                &self.source,
                &node_service_states,
                &self.failed_host_io,
            )
            .map_err(|error| SchedulerError::BoundaryViolation {
                message: format!("validate failed-node host I/O: {error}"),
            })?;
            let mut checkpoint_set = ProductionVmExactCheckpointSet {
                identity: ContentHash::default(),
                configuration: configuration.clone(),
                scheduler: Arc::new(scheduler),
                event_log_objects,
                signal_artifact_objects,
                trigger_state,
                assertion_state,
                terminal_verdict,
                terminal_cause,
                initial_lifecycle_observations_pending: self.initial_lifecycle_observations_pending,
                branch,
                recorded_controls,
                selectable_catalog_plans: self.inner.backend_mut().selectable_catalog_plans(),
                fault_checkpoint: Some(fault_checkpoint),
                targets,
                failed_host_io: self.failed_host_io.clone(),
                node_generations,
                node_service_states,
                repository_restore: None,
            };
            let prepared = prepare_exact_checkpoint_set_with_boundary(
                &self.config.run_state_root,
                self.scenario.id(),
                resource_limits,
                &mut checkpoint_set,
                boundary,
            )
            .map_err(|error| match error {
                PersistExactCheckpointError::Unpublished(source) => {
                    ExactCheckpointTransactionError::Unpublished(source)
                }
                PersistExactCheckpointError::Indeterminate { identity, source } => {
                    ExactCheckpointTransactionError::Indeterminate {
                        identity: Some(identity),
                        captures: Vec::new(),
                        source,
                    }
                }
            })?;
            let mut retained_targets = BTreeMap::new();
            for (node, target) in &checkpoint_set.targets {
                let exact_ram = target.native_exact_ram().ok_or_else(|| {
                    ExactCheckpointTransactionError::Unpublished(
                        SchedulerError::BoundaryViolation {
                            message: String::from(
                                "captured checkpoint target lost native RAM state",
                            ),
                        },
                    )
                })?;
                retained_targets.insert(node.clone(), exact_ram.clone());
            }
            let parent = ProductionExactRamPublishedParent {
                closure: prepared.identity(),
                targets: retained_targets,
            };
            Ok((prepared, parent))
        })();
        let (prepared, retained_parent) = match preparation {
            Ok(prepared) => prepared,
            Err(error @ ExactCheckpointTransactionError::Unpublished(_)) => {
                let cleanup = self
                    .release_exact_captures(&mut captured, ExactCaptureDisposition::Unpublished);
                return combine_exact_checkpoint_transaction(Err(error), cleanup, captured);
            }
            Err(ExactCheckpointTransactionError::Indeterminate {
                identity, source, ..
            }) => {
                return Err(ExactCheckpointTransactionError::Indeterminate {
                    identity,
                    captures: captured,
                    source,
                });
            }
        };
        let identity = prepared.identity();
        self.exact_ram_parents
            .insert(configuration.id(), retained_parent);
        match prepared.publish() {
            Ok(()) => {
                if let Err(source) =
                    self.release_exact_captures(&mut captured, ExactCaptureDisposition::Published)
                {
                    return Err(ExactCheckpointTransactionError::Indeterminate {
                        identity: Some(identity),
                        captures: captured,
                        source,
                    });
                }
                self.exact_ram_parents
                    .retain(|candidate, _| *candidate == configuration.id());
                self.repository_exact_ram_rebase = None;
                Ok(identity)
            }
            Err(PersistExactCheckpointError::Unpublished(source)) => {
                self.exact_ram_parents.remove(&configuration.id());
                let cleanup = self
                    .release_exact_captures(&mut captured, ExactCaptureDisposition::Unpublished);
                combine_exact_checkpoint_transaction(
                    Err(ExactCheckpointTransactionError::Unpublished(source)),
                    cleanup,
                    captured,
                )
            }
            Err(PersistExactCheckpointError::Indeterminate { identity, source }) => {
                Err(ExactCheckpointTransactionError::Indeterminate {
                    identity: Some(identity),
                    captures: captured,
                    source,
                })
            }
        }
    }
}
