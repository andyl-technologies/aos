//! Launches only finite host-authorized cohorts beneath seven prior reservations.
//!
//! Private launch tokens are neither hashed into content nor written to reports.
//! The returned original guard owns them and actual Child after spawn. Ordinary
//! class acceptance and finite conformance fixture authority remain distinct.

use super::super::{NodeObservedError, refused};
use super::{
    InstalledTypedReaderCatalog, InstalledTypedReaderConfiguration,
    InstalledTypedReaderOwningPolicy, InstalledTypedReaderPreparedParts, TypedReaderCustodyPair,
    TypedReaderCustodySupervisor,
};
use crucible::node_adapters::cnp::{
    LineageControlledReference, LineagePreparationFailure, LineageRuntimeCustodySlot,
};
use crucible::node_contract::{ActivationRecord, RuntimeCustodySlot, RuntimeLimits};
use crucible_node_contract::{Extensions, Id, Validate, canonical};
use crucible_node_provider::{
    ProviderError,
    bodies::{DiscoverRequest, MethodResult, RealizeRequest},
    client::{DeadlineStream, ExchangeDeadline, ReferenceController},
    envelope::Method,
    handshake::ExtensionHandshake,
    reference_lineage::{
        LineageSourceCustodySlot, LineageSourceExtensionFailure, LineageSourceGuard,
        LineageSourceLaunchFailure,
    },
    reference_service::ReferenceNegotiatedLineageReaderLaunchBootstrap,
};
use std::{
    collections::VecDeque,
    os::{
        fd::OwnedFd,
        unix::{fs::DirBuilderExt, net::UnixStream},
    },
    path::PathBuf,
    process::{Command, Stdio},
    rc::Rc,
};

pub(super) struct Pending {
    pub(super) parts: Box<InstalledTypedReaderPreparedParts>,
    slots: TypedReaderCustodyPair,
}

/// Owns a fixed two-producer/one-consumer launch before the first native Child.
///
/// The owning event loop retains and polls [`Self::supervisor`] on every failure.
/// Neither this object nor the target reservation grants a complete activation.
pub struct PreparedTypedReaderCohort {
    pub(super) policy: Rc<InstalledTypedReaderOwningPolicy>,
    pub(super) target: ActivationRecord,
    supervisor: TypedReaderCustodySupervisor,
    world: Option<Box<dyn RuntimeCustodySlot>>,
    pub(super) pending: VecDeque<Pending>,
}

/// Owns the actual launched provider and original reader preparation unchanged.
pub struct LaunchedTypedReaderProvider {
    /// Retains actual Child, private bootstrap, raw journals and prior source slot.
    pub guard: LineageSourceGuard,
    /// Retains the same package/profile/installed source policy.
    pub preparation: Box<InstalledTypedReaderPreparedParts>,
    /// Retains the prior complete reader reservation for original adoption.
    pub runtime: Box<dyn LineageRuntimeCustodySlot>,
    realization: RealizeRequest,
}

/// Preserves native custody and unused reservations after an actual launch refusal.
pub struct TypedReaderLaunchFailure {
    /// Reports the original failure without inferring rollback or no prior effects.
    pub error: NodeObservedError,
    /// Retains a successfully spawned original Child when one exists.
    pub guard: Option<LineageSourceGuard>,
    /// Retains the same source metadata and independently installed policy.
    pub preparation: Box<InstalledTypedReaderPreparedParts>,
    /// Retains the unused source obligation only when no Child was returned.
    pub unstarted_source: Option<Box<dyn LineageSourceCustodySlot>>,
    /// Retains the complete reader obligation, independent of source-group custody.
    pub runtime: Box<dyn LineageRuntimeCustodySlot>,
}

/// Distinguishes an exhausted reservation from a retained actual launch attempt.
pub enum TypedReaderLaunchError {
    /// Reports exhaustion without consuming or inventing an owning capsule.
    NoRemainingReservation(NodeObservedError),
    /// Retains all original resources of the single attempted launch.
    Original(Box<TypedReaderLaunchFailure>),
}

/// Returns every supplied original attachment handle when adoption refuses.
pub enum TypedReaderAdoptionFailure {
    /// Retains the same attached owner after original discovery/realization refusal.
    Original {
        /// Reports the original control refusal without replacement or rollback.
        error: NodeObservedError,
        /// Retains both actual process groups, journals, policy and reader slot.
        provider: Box<LaunchedTypedReaderProvider>,
    },
    /// Retains original guard/controller/registrar together with policy and slot.
    Attachment {
        /// Retains all handles returned by the actual consuming attachment.
        original: Box<LineageSourceExtensionFailure>,
        /// Retains original measured metadata and source policy.
        preparation: Box<InstalledTypedReaderPreparedParts>,
        /// Retains the original complete reader reservation.
        runtime: Box<dyn LineageRuntimeCustodySlot>,
    },
    /// Retains the actual already-attached native capsule and installed policy.
    Preparation(Box<LineagePreparationFailure>),
}

impl PreparedTypedReaderCohort {
    /// Checks all source prerequisites and reserves all seven obligations first.
    ///
    /// Configurations are ordered producer/producer/consumer, with two distinct
    /// closed ingresses. No unsupported class certificate or fixture authority
    /// can reach native launch. Every original source policy is prepared before
    /// the whole-world/source/reader reservation is exposed to the launcher.
    ///
    /// # Errors
    /// Refuses missing current authority, changed role/owner geometry, metadata,
    /// finite credits or source policy. No native Child exists on this path.
    pub fn prepare(
        policy: Rc<InstalledTypedReaderOwningPolicy>,
        descriptor: PathBuf,
        configurations: [InstalledTypedReaderConfiguration; 3],
        target: ActivationRecord,
        limits: RuntimeLimits,
    ) -> Result<Self, NodeObservedError> {
        if !configurations[0].closed_ingress
            || !configurations[1].closed_ingress
            || configurations[2].closed_ingress
            || configurations.iter().enumerate().any(|(index, current)| {
                configurations[..index].iter().any(|previous| {
                    previous.node == current.node || previous.owner == current.owner
                })
            })
            || configurations.iter().any(|configuration| {
                target
                    .owners
                    .iter()
                    .filter(|owner| owner.owner == configuration.owner)
                    .count()
                    != 1
            })
        {
            return Err(refused("typed cohort original role/owner geometry differs"));
        }
        let original = policy.expected_package.clone();
        let catalog = InstalledTypedReaderCatalog::new(
            descriptor,
            original,
            Rc::clone(&policy.registry),
            Some(Rc::clone(&policy) as Rc<dyn super::InstalledTypedReaderCatalogPolicy>),
        )?;
        let mut preparations = Vec::new();
        preparations
            .try_reserve_exact(3)
            .map_err(|_| refused("typed cohort preparation credit"))?;
        for configuration in configurations {
            preparations.push(catalog.prepare(configuration)?.into_parts());
        }
        let mut pending = VecDeque::new();
        pending
            .try_reserve_exact(3)
            .map_err(|_| refused("typed cohort launch credit"))?;
        let (supervisor, reservation) = TypedReaderCustodySupervisor::reserve(&target, limits)?;
        for (parts, slots) in preparations.into_iter().zip(reservation.readers) {
            pending.push_back(Pending {
                parts: Box::new(parts),
                slots,
            });
        }
        Ok(Self {
            policy,
            target,
            supervisor,
            world: Some(reservation.world),
            pending,
        })
    }

    /// Borrows the actual owning cleanup actor across success, refusal and unwind.
    pub fn supervisor(&self) -> &TypedReaderCustodySupervisor {
        &self.supervisor
    }

    /// Transfers the original whole-world slot once for actual runtime construction.
    ///
    /// # Errors
    /// Refuses a second transfer. This transfers storage, not activation authority.
    pub fn take_world_slot(&mut self) -> Result<Box<dyn RuntimeCustodySlot>, NodeObservedError> {
        self.world
            .take()
            .ok_or_else(|| refused("typed whole-world slot already transferred"))
    }

    /// Launches one original provider only after rechecking its private host scope.
    ///
    /// All bootstrap/body counting and executable/argument preparation precede
    /// Child. The source primitive allocates its complete owning holder first.
    /// The returned guard receives bootstrap before any public transport call.
    /// Serialization temporaries are bounded by the declared private body budget;
    /// this API does not claim zero-copy serialization of secret launch bytes.
    ///
    /// # Errors
    /// Returns the same policy/reservations and actual Child on refusal, never a
    /// replacement process. The actor services authentic cleanup through the
    /// retained supervisor; failed or absent custody never proves reclamation.
    pub fn launch_next(
        &mut self,
        directory: PathBuf,
        launch: &ReferenceNegotiatedLineageReaderLaunchBootstrap,
    ) -> Result<LaunchedTypedReaderProvider, TypedReaderLaunchError> {
        self.launch_next_transport(directory, launch, None)
    }

    pub(super) fn launch_next_transport(
        &mut self,
        directory: PathBuf,
        launch: &ReferenceNegotiatedLineageReaderLaunchBootstrap,
        transport: Option<(UnixStream, UnixStream, ExchangeDeadline)>,
    ) -> Result<LaunchedTypedReaderProvider, TypedReaderLaunchError> {
        // The closed fixed cohort cannot allocate a fourth provider obligation.
        let Some(pending) = self.pending.pop_front() else {
            // No owning resource was consumed. Callers inspect remaining count
            // before scheduling; an exhausted cohort is not an admission retry.
            return Err(TypedReaderLaunchError::NoRemainingReservation(refused(
                "typed cohort source reservations exhausted",
            )));
        };
        let Pending { parts, slots } = pending;
        let checked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            launch.validate()?;
            if let Some((_, _, deadline)) = &transport {
                deadline.remaining().map_err(|error| native(error.into()))?;
            }
            if !directory.is_absolute()
                || directory.as_os_str().len() > 4096
                || launch.bootstrap.node_id != parts.profile.descriptor.id
                || launch.bootstrap.owner_id != parts.profile.owner.id
                || launch.bootstrap.world_binding_hash != self.target.world_binding_hash
                || launch.bootstrap.activation_id != self.target.activation_id
                || launch.bootstrap.world_generation != self.target.generation
                || !self.target.owners.iter().any(|owner| {
                    owner.owner == launch.bootstrap.owner_id
                        && owner.incarnation == launch.bootstrap.authority.incarnation_id
                        && owner.generation == launch.bootstrap.authority.owner_generation
                })
            {
                return Err(refused("typed original private launch target differs"));
            }
            let bytes = launch
                .bootstrap
                .installed_content
                .iter()
                .try_fold(0usize, |total, body| {
                    total
                        .checked_add(body.bytes.as_slice().len())
                        .filter(|total| *total <= 16 * 1024 * 1024)
                })
                .ok_or_else(|| refused("typed private launch original body credit"))?;
            let _ = bytes;
            super::owning::count_launch(launch, 16 * 1024 * 1024).map_err(native)?;
            self.policy.authenticate_launch(&parts, launch)?;
            let bytes = canonical::canonical_json(
                &serde_json::to_value(launch)
                    .map_err(crucible_node_contract::ContractError::from)?,
            )?;
            std::fs::DirBuilder::new()
                .mode(0o700)
                .create(&directory)
                .map_err(|error| NodeObservedError::Native(error.to_string()))?;
            Ok(bytes)
        }))
        .unwrap_or_else(|_| Err(refused("typed original launch authority unwound")));
        let bytes = match checked {
            Ok(bytes) => bytes,
            Err(error) => {
                return Err(TypedReaderLaunchError::Original(Box::new(
                    TypedReaderLaunchFailure {
                        error,
                        guard: None,
                        preparation: parts,
                        unstarted_source: Some(slots.source),
                        runtime: slots.runtime,
                    },
                )));
            }
        };
        let provider = parts
            .package
            .executable("provider")
            .map(std::path::Path::to_path_buf);
        let device = parts
            .package
            .executable("device")
            .map(std::path::Path::to_path_buf);
        let (provider, device) = match (provider, device) {
            (Ok(provider), Ok(device)) => (provider, device),
            (Err(error), _) | (_, Err(error)) => {
                return Err(TypedReaderLaunchError::Original(Box::new(
                    TypedReaderLaunchFailure {
                        error,
                        guard: None,
                        preparation: parts,
                        unstarted_source: Some(slots.source),
                        runtime: slots.runtime,
                    },
                )));
            }
        };
        let provider_ref = match parts.package.artifact_content("provider") {
            Ok(reference) => reference.clone(),
            Err(error) => {
                return Err(TypedReaderLaunchError::Original(Box::new(
                    TypedReaderLaunchFailure {
                        error,
                        guard: None,
                        preparation: parts,
                        unstarted_source: Some(slots.source),
                        runtime: slots.runtime,
                    },
                )));
            }
        };
        let device_ref = match parts.package.artifact_content("device") {
            Ok(reference) => reference.clone(),
            Err(error) => {
                return Err(TypedReaderLaunchError::Original(Box::new(
                    TypedReaderLaunchFailure {
                        error,
                        guard: None,
                        preparation: parts,
                        unstarted_source: Some(slots.source),
                        runtime: slots.runtime,
                    },
                )));
            }
        };
        let realization = RealizeRequest {
            realization_id: launch.bootstrap.authority.realization_id.clone(),
            configuration: parts.profile.configuration_ref.clone(),
            requested_node_ids: vec![parts.profile.descriptor.id.clone()],
            resource_limits: launch.bootstrap.resource_limits.clone(),
            extensions: Extensions::new(),
        };
        let (stdin, bootstrap_writer) = match transport {
            Some((reader, writer, deadline)) => {
                (Stdio::from(OwnedFd::from(reader)), Some((writer, deadline)))
            }
            None => (Stdio::piped(), None),
        };
        let mut command = Command::new(provider);
        command
            .arg(directory.join("control.sock"))
            .arg(device)
            .env_clear()
            .env("LC_ALL", "C")
            .stdin(stdin)
            .stdout(Stdio::null())
            .stderr(Stdio::inherit());
        let mut guard = match LineageSourceGuard::spawn_reserved(
            &mut command,
            directory,
            provider_ref,
            device_ref,
            slots.source,
        ) {
            Ok(guard) => guard,
            Err(failure) => {
                let (error, guard, source) = match *failure {
                    LineageSourceLaunchFailure::BeforeSpawn { error, slot } => {
                        (error, None, Some(slot))
                    }
                    LineageSourceLaunchFailure::AfterSpawn(original) => {
                        (original.error, Some(original.guard), None)
                    }
                };
                return Err(TypedReaderLaunchError::Original(Box::new(
                    TypedReaderLaunchFailure {
                        error: native(error),
                        guard,
                        preparation: parts,
                        unstarted_source: source,
                        runtime: slots.runtime,
                    },
                )));
            }
        };
        let written = match bootstrap_writer {
            Some((writer, deadline)) => DeadlineStream::with_deadline(writer, deadline)
                .map_err(ProviderError::from)
                .and_then(|stream| guard.write_private_bootstrap_stream(bytes, stream)),
            None => guard.write_private_bootstrap(bytes),
        };
        if let Err(error) = written {
            return Err(TypedReaderLaunchError::Original(Box::new(
                TypedReaderLaunchFailure {
                    error: native(error),
                    guard: Some(guard),
                    preparation: parts,
                    unstarted_source: None,
                    runtime: slots.runtime,
                },
            )));
        }
        Ok(LaunchedTypedReaderProvider {
            guard,
            preparation: parts,
            runtime: slots.runtime,
            realization,
        })
    }
}

impl TypedReaderAdoptionFailure {
    /// Transfers rejected attachment journals into the original source supervisor.
    ///
    /// This discards no owner: the original policy and unused reader slot remain
    /// live until the complete rejected tuple has entered its source capsule.
    /// Preparation failures already own an attached reader and use its existing
    /// consuming Drop supervision. No native progression or cleanup is asserted.
    ///
    /// # Errors
    /// Returns the same complete failed attachment when its capsule cannot retain
    /// the original controller and registrar; the caller must preserve that owner.
    pub fn retain_for_cleanup(self) -> Result<(), Box<Self>> {
        match self {
            Self::Original { provider, .. } => {
                drop(provider);
                Ok(())
            }
            Self::Attachment {
                original,
                preparation,
                runtime,
            } => match original.into_containment() {
                Ok(guard) => {
                    drop(guard);
                    drop(preparation);
                    drop(runtime);
                    Ok(())
                }
                Err(original) => Err(Box::new(Self::Attachment {
                    original,
                    preparation,
                    runtime,
                })),
            },
            Self::Preparation(original) => {
                drop(original);
                Ok(())
            }
        }
    }
}

impl LaunchedTypedReaderProvider {
    /// Drives original typed discovery and realization beneath actual source custody.
    ///
    /// The caller supplies the genuinely authenticated original controller and
    /// surviving registrar. This method attaches them before any discovery or
    /// realization call and uses only the source/target request fixed before
    /// Child. It consumes the actual cached realization through the same
    /// negotiated source constructor; it issues neither activation nor Ready.
    ///
    /// # Errors
    /// Returns the same owner/policy/slot and complete journals on transport,
    /// discovery, realization or constructor refusal. An uncertain original
    /// request is retained and never redispatched under a new identity.
    pub fn realize_original(
        mut self,
        controller: Box<ReferenceController>,
        registrar: Box<ExtensionHandshake>,
        discovery: Id,
        realization: Id,
    ) -> Result<LineageControlledReference, Box<TypedReaderAdoptionFailure>> {
        if discovery == realization {
            return Err(Box::new(TypedReaderAdoptionFailure::Original {
                error: refused("typed original discovery/realization identities overlap"),
                provider: Box::new(self),
            }));
        }
        self.guard = match self.guard.attach_extensions(controller, registrar) {
            Ok(guard) => guard,
            Err(original) => {
                return Err(Box::new(TypedReaderAdoptionFailure::Attachment {
                    original: Box::new(original),
                    preparation: self.preparation,
                    runtime: self.runtime,
                }));
            }
        };
        let checked = (|| {
            let discovered = self.guard.call(
                discovery,
                None,
                Method::Discover,
                false,
                DiscoverRequest {
                    profile_ids: vec![self.preparation.profile.node_manifest.profile_id.clone()],
                    cursor: None,
                    extensions: Extensions::new(),
                },
            )?;
            let Some(MethodResult::Discover(discovered)) = discovered.result else {
                return Err(ProviderError::Correlation(
                    "typed original discovery refused",
                ));
            };
            if discovered.provider_manifest != self.preparation.profile.provider_manifest
                || discovered.profiles.as_slice()
                    != std::slice::from_ref(&self.preparation.profile.node_manifest)
                || !discovered.complete
                || discovered.next_cursor.0.is_some()
            {
                return Err(ProviderError::Correlation(
                    "typed original complete discovery differs",
                ));
            }
            let realized = self.guard.call(
                realization.clone(),
                None,
                Method::Realize,
                false,
                &self.realization,
            )?;
            if !matches!(realized.result, Some(MethodResult::Realize(_))) {
                return Err(ProviderError::Correlation(
                    "typed original realization refused",
                ));
            }
            Ok(())
        })();
        if let Err(error) = checked {
            return Err(Box::new(TypedReaderAdoptionFailure::Original {
                error: native(error),
                provider: Box::new(self),
            }));
        }
        LineageControlledReference::from_negotiated_original(
            self.guard,
            realization,
            self.preparation.qualification,
            self.runtime,
            self.preparation.maximum_operations,
        )
        .map_err(|failure| Box::new(TypedReaderAdoptionFailure::Preparation(failure)))
    }

    /// Attaches the actual typed session and consumes the original reader constructor.
    ///
    /// This route invokes the same installed source policy under original kernel,
    /// registrar and realization checks. It grants no graph or common Ready.
    ///
    /// # Errors
    /// Returns complete same ownership on attachment or source/realization refusal.
    pub fn adopt(
        self,
        controller: Box<ReferenceController>,
        registrar: Box<ExtensionHandshake>,
        realization: Id,
    ) -> Result<LineageControlledReference, Box<TypedReaderAdoptionFailure>> {
        let Self {
            guard,
            preparation,
            runtime,
            realization: _,
        } = self;
        let guard = match guard.attach_extensions(controller, registrar) {
            Ok(guard) => guard,
            Err(original) => {
                return Err(Box::new(TypedReaderAdoptionFailure::Attachment {
                    original: Box::new(original),
                    preparation,
                    runtime,
                }));
            }
        };
        LineageControlledReference::from_negotiated_original(
            guard,
            realization,
            preparation.qualification,
            runtime,
            preparation.maximum_operations,
        )
        .map_err(|failure| Box::new(TypedReaderAdoptionFailure::Preparation(failure)))
    }
}

fn native(error: ProviderError) -> NodeObservedError {
    NodeObservedError::Native(error.to_string())
}
