//! Trusted live capabilities for native provider assignments.
//!
//! A provider assignment names both a logical provider and a process
//! incarnation. The durable readiness output supplies the former, but it does
//! not preserve a process-local transport. This module reacquires the transport
//! from an environment-scoped capability inventory and rechecks its current
//! incarnation before the assignment can enter current admission authority.

use std::collections::BTreeMap;
use std::sync::Arc;

use anyhow::{Context as _, Result, ensure};
use aos_ability_model::{
    AbilityValue, Binding, EnvironmentId, ExecutionStage, InstanceId, InterfaceKey, LocalKey,
    ProviderAssignment, ProviderImplementationReference, ResourceId,
};
use aos_ability_runtime::adapter::RuntimeControl;
use aos_systemd::SystemdManagerConnection;

use super::kubernetes_ability::{DeferredKubernetesApiCapability, KubernetesApiCapability};

/// Retains caller-supplied systemd transports under exact environment identities.
pub(crate) struct SystemdManagerCapabilities {
    control_managers: BTreeMap<EnvironmentId, ScopedSystemdManagerCapability>,
    planned_managers: BTreeMap<SystemdManagerHandoffKey, Arc<SystemdManagerConnection>>,
}

struct ScopedSystemdManagerCapability {
    environment: EnvironmentId,
    connection: Arc<SystemdManagerConnection>,
}

impl ScopedSystemdManagerCapability {
    fn host(environment: EnvironmentId, connection: Arc<SystemdManagerConnection>) -> Result<Self> {
        require_host_environment(&environment)?;
        Ok(Self {
            environment,
            connection,
        })
    }

    #[cfg(test)]
    fn delegated_system_container_for_test(
        environment: EnvironmentId,
        connection: Arc<SystemdManagerConnection>,
    ) -> Result<Self> {
        ensure!(
            environment.stage == ExecutionStage::SystemContainer,
            "delegated systemd capability was registered for another execution stage"
        );
        Ok(Self {
            environment,
            connection,
        })
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct SystemdManagerHandoffKey {
    bootstrap_resource: ResourceId,
    target_provider: InstanceId,
}

/// Defers one typed planned-manager output until the bootstrap observation succeeds.
#[derive(Clone)]
pub(crate) struct SystemdManagerReadinessOutput {
    output: LocalKey,
    source: SystemdManagerReadinessSource,
}

#[derive(Clone)]
enum SystemdManagerReadinessSource {
    Live {
        subject: ProviderAssignment,
        target: Arc<SystemdManagerConnection>,
        control: Arc<SystemdManagerConnection>,
    },
    #[cfg(test)]
    Fixed(AbilityValue),
}

/// Defers one typed provider assignment until its live capability is observed.
#[derive(Clone)]
pub(crate) enum NativeProviderReadinessOutput {
    /// Observes a separately scoped systemd manager endpoint.
    Systemd(SystemdManagerReadinessOutput),
    /// Observes one exact Kubernetes API cluster.
    Kubernetes(KubernetesClusterReadinessOutput),
}

/// Defers a Kubernetes provider assignment until the cluster UID is observed.
#[derive(Clone)]
pub(crate) struct KubernetesClusterReadinessOutput {
    output: LocalKey,
    subject: ProviderAssignment,
    capability: DeferredKubernetesApiCapability,
}

impl NativeProviderReadinessOutput {
    /// Observes the provider's current incarnation and encodes its assignment.
    ///
    /// # Errors
    ///
    /// Returns an error when the scoped capability cannot be observed or its
    /// assignment cannot be represented as a bounded ability value.
    pub(crate) fn observe(&self, control: &dyn RuntimeControl) -> Result<(LocalKey, AbilityValue)> {
        match self {
            Self::Systemd(output) => output.observe(),
            Self::Kubernetes(output) => output.observe(control),
        }
    }
}

impl KubernetesClusterReadinessOutput {
    /// Constructs a deferred Kubernetes assignment from an exact checked binding.
    ///
    /// # Errors
    ///
    /// Returns an error when the binding is not the built-in Kubernetes contract.
    pub(crate) fn new(
        output: LocalKey,
        binding: &Binding,
        capability: DeferredKubernetesApiCapability,
    ) -> Result<Self> {
        ensure!(
            binding.interface.name.as_str()
                == aos_ability_model::builtin::KUBERNETES_OBJECT_INTERFACE_NAME,
            "planned provider readiness target is not Kubernetes object effects"
        );
        let subject = ProviderAssignment {
            provider: binding.provider.clone(),
            interface: binding.interface.clone(),
            implementation: binding.implementation.clone(),
            incarnation: aos_ability_model::IncarnationId::new("unobserved")?,
        };
        Ok(Self {
            output,
            subject,
            capability,
        })
    }

    fn observe(&self, control: &dyn RuntimeControl) -> Result<(LocalKey, AbilityValue)> {
        let capability = self
            .capability
            .acquire()
            .context("acquiring Kubernetes capability after producer readiness")?;
        let incarnation = capability
            .observe_incarnation(control)
            .context("observing Kubernetes provider readiness")?;
        let value = assignment_value(&self.subject, incarnation)?;
        Ok((self.output.clone(), value))
    }
}

impl SystemdManagerReadinessOutput {
    /// Pins the target manager and encodes its exact live assignment.
    ///
    /// # Errors
    ///
    /// Returns an error when the supplied target-manager capability cannot be
    /// pinned or its assignment cannot be represented as a bounded value.
    pub(crate) fn observe(&self) -> Result<(LocalKey, AbilityValue)> {
        let (subject, target, control) = match &self.source {
            SystemdManagerReadinessSource::Live {
                subject,
                target,
                control,
            } => (subject, target, control),
            #[cfg(test)]
            SystemdManagerReadinessSource::Fixed(value) => {
                return Ok((self.output.clone(), value.clone()));
            }
        };
        let incarnation = super::systemd_ability::current_systemd_incarnation(target)
            .context("observing planned systemd manager readiness")?;
        let control_incarnation = super::systemd_ability::current_systemd_incarnation(control)
            .context("rechecking bootstrap systemd manager")?;
        require_distinct_manager_incarnations(&incarnation, &control_incarnation)?;
        let value = assignment_value(subject, incarnation)?;
        Ok((self.output.clone(), value))
    }

    #[cfg(test)]
    pub(crate) fn fixed_for_test(output: LocalKey, value: AbilityValue) -> Self {
        Self {
            output,
            source: SystemdManagerReadinessSource::Fixed(value),
        }
    }
}

fn assignment_value(
    subject: &ProviderAssignment,
    incarnation: aos_ability_model::IncarnationId,
) -> Result<AbilityValue> {
    let mut assignment = subject.clone();
    assignment.incarnation = incarnation;
    AbilityValue::new(
        serde_json::to_value(assignment).context("encoding planned systemd manager assignment")?,
    )
    .context("bounding planned systemd manager assignment")
}

impl SystemdManagerCapabilities {
    /// Constructs an inventory for a native plan with no systemd routes.
    pub(crate) fn empty() -> Self {
        Self {
            control_managers: BTreeMap::new(),
            planned_managers: BTreeMap::new(),
        }
    }

    /// Constructs the current production inventory for one host environment.
    ///
    /// The connection is already scoped by its transport. The separately
    /// authenticated environment identity prevents a planned assignment for a
    /// user, initrd, or container manager from falling back to this host bus.
    ///
    /// # Errors
    ///
    /// Returns an error when `environment` does not name the host stage.
    pub(crate) fn single_host(
        environment: EnvironmentId,
        connection: Arc<SystemdManagerConnection>,
    ) -> Result<Self> {
        Self::from_scoped(
            [ScopedSystemdManagerCapability::host(
                environment,
                connection,
            )?],
            [],
        )
    }

    /// Constructs an inventory from caller-authenticated scoped transports.
    ///
    /// A control connection remains associated with the exact environment
    /// identity supplied by its broker. A planned manager connection is keyed
    /// by the exact bootstrap resource and target provider that supply the
    /// handoff. This constructor never opens a default bus or translates one
    /// scope into another.
    ///
    /// # Errors
    ///
    /// Returns an error when the caller supplies duplicate control environments
    /// or duplicate planned handoff identities.
    fn from_scoped(
        control_managers: impl IntoIterator<Item = ScopedSystemdManagerCapability>,
        planned_managers: impl IntoIterator<
            Item = (ResourceId, InstanceId, Arc<SystemdManagerConnection>),
        >,
    ) -> Result<Self> {
        let mut controls = BTreeMap::new();
        for capability in control_managers {
            ensure!(
                controls
                    .insert(capability.environment.clone(), capability)
                    .is_none(),
                "duplicate systemd manager capability environment"
            );
        }

        let mut planned = BTreeMap::new();
        for (bootstrap_resource, target_provider, connection) in planned_managers {
            let handoff = SystemdManagerHandoffKey {
                bootstrap_resource,
                target_provider,
            };
            ensure!(
                planned.insert(handoff, connection).is_none(),
                "duplicate planned systemd manager handoff capability"
            );
        }
        Ok(Self {
            control_managers: controls,
            planned_managers: planned,
        })
    }

    /// Builds a deferred readiness output for an exact planned manager binding.
    ///
    /// # Errors
    ///
    /// Returns an error when the planned binding is not the built-in systemd
    /// manager contract or its scoped transport is unavailable.
    pub(crate) fn readiness_output(
        &self,
        output: LocalKey,
        binding: &Binding,
        bootstrap_resource: &ResourceId,
    ) -> Result<SystemdManagerReadinessOutput> {
        ensure!(
            binding.interface.name.as_str()
                == aos_ability_model::builtin::SYSTEMD_MANAGER_INTERFACE_NAME,
            "planned provider readiness target is not a systemd manager"
        );
        let handoff = SystemdManagerHandoffKey {
            bootstrap_resource: bootstrap_resource.clone(),
            target_provider: binding.provider.clone(),
        };
        let target = self
            .planned_managers
            .get(&handoff)
            .cloned()
            .context("planned systemd manager endpoint was not supplied by its provider")?;
        let control = self.control_connection(&bootstrap_resource.provider.environment)?;
        let subject = ProviderAssignment {
            provider: binding.provider.clone(),
            interface: binding.interface.clone(),
            implementation: binding.implementation.clone(),
            incarnation: aos_ability_model::IncarnationId::new("unobserved")
                .context("constructing deferred manager assignment")?,
        };
        Ok(SystemdManagerReadinessOutput {
            output,
            source: SystemdManagerReadinessSource::Live {
                subject,
                target,
                control,
            },
        })
    }

    /// Observes a fresh assignment through the exact environment capability.
    ///
    /// # Errors
    ///
    /// Returns an error when no transport was supplied for the provider's
    /// environment or the live manager cannot be pinned and identified.
    pub(crate) fn observe_assignment(
        &self,
        provider: &InstanceId,
        interface: &InterfaceKey,
        implementation: &ProviderImplementationReference,
    ) -> Result<ProviderAssignment> {
        let connection = self.control_connection(&provider.environment)?;
        let incarnation = super::systemd_ability::current_systemd_incarnation(&connection)
            .context("observing systemd manager capability incarnation")?;
        Ok(ProviderAssignment {
            provider: provider.clone(),
            interface: interface.clone(),
            implementation: implementation.clone(),
            incarnation,
        })
    }

    /// Reacquires an available provider through its environment control manager.
    ///
    /// The caller receives a connection only after its current unique manager
    /// incarnation exactly matches the assignment admitted for this operation.
    ///
    /// # Errors
    ///
    /// Returns an error when the environment transport is unavailable, the
    /// manager cannot be observed, or its incarnation changed.
    pub(crate) fn reacquire_assignment(
        &self,
        expected: &ProviderAssignment,
    ) -> Result<Arc<SystemdManagerConnection>> {
        let connection = self.control_connection(&expected.provider.environment)?;
        let observed = super::systemd_ability::current_systemd_incarnation(&connection)
            .context("reacquiring systemd manager capability incarnation")?;
        require_same_incarnation(expected, &observed)?;
        Ok(connection)
    }

    /// Reacquires the exact endpoint emitted by planned-manager readiness.
    ///
    /// # Errors
    ///
    /// Returns an error when the planned provider did not supply an endpoint,
    /// the endpoint cannot be pinned, or its incarnation changed.
    pub(crate) fn reacquire_planned_assignment(
        &self,
        expected: &ProviderAssignment,
        bootstrap_resource: &ResourceId,
    ) -> Result<Arc<SystemdManagerConnection>> {
        let handoff = SystemdManagerHandoffKey {
            bootstrap_resource: bootstrap_resource.clone(),
            target_provider: expected.provider.clone(),
        };
        let connection = self
            .planned_managers
            .get(&handoff)
            .cloned()
            .context("planned systemd manager endpoint is unavailable")?;
        let observed = super::systemd_ability::current_systemd_incarnation(&connection)
            .context("reacquiring planned systemd manager incarnation")?;
        require_same_incarnation(expected, &observed)?;
        Ok(connection)
    }

    fn control_connection(
        &self,
        environment: &EnvironmentId,
    ) -> Result<Arc<SystemdManagerConnection>> {
        self.control_managers
            .get(environment)
            .map(|capability| Arc::clone(&capability.connection))
            .context("no trusted control manager exists for the provider environment")
    }
}

/// Requires a Kubernetes capability to match an admitted provider assignment.
///
/// # Errors
///
/// Returns an error when the cluster cannot be observed or its UID changed.
pub(crate) fn reacquire_kubernetes_assignment(
    capability: &KubernetesApiCapability,
    expected: &ProviderAssignment,
) -> Result<()> {
    let observed = capability
        .observe_incarnation_bounded(30_000)
        .context("reacquiring Kubernetes cluster incarnation")?;
    require_same_incarnation(expected, &observed)
}

fn require_host_environment(environment: &EnvironmentId) -> Result<()> {
    ensure!(
        environment.stage == ExecutionStage::Host,
        "host systemd capability was registered for another execution stage"
    );
    Ok(())
}

fn require_same_incarnation(
    expected: &ProviderAssignment,
    observed: &aos_ability_model::IncarnationId,
) -> Result<()> {
    ensure!(
        &expected.incarnation == observed,
        "planned systemd manager incarnation changed before capability reacquisition"
    );
    Ok(())
}

fn require_distinct_manager_incarnations(
    target: &aos_ability_model::IncarnationId,
    control: &aos_ability_model::IncarnationId,
) -> Result<()> {
    ensure!(
        target != control,
        "planned systemd manager resolved to the bootstrap control manager"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroU32;

    use aos_ability_model::{
        ArtifactReference, IncarnationId, InterfaceName, LocalKey, ProviderImplementationReference,
    };
    use aos_contract::Sha256Digest;

    use super::*;

    #[test]
    fn stale_manager_incarnation_never_falls_back_to_the_environment_transport() {
        let assignment = assignment("manager-a");

        require_same_incarnation(&assignment, &IncarnationId::new("manager-a").unwrap()).unwrap();
        let error = require_same_incarnation(
            &assignment,
            &IncarnationId::new("replacement-manager").unwrap(),
        )
        .unwrap_err();

        assert!(error.to_string().contains("incarnation changed"));
    }

    #[test]
    fn host_transport_cannot_claim_an_initrd_environment() {
        let mut environment = assignment("manager-a").provider.environment;
        environment.stage = ExecutionStage::Initrd;

        let error = require_host_environment(&environment).unwrap_err();

        assert!(error.to_string().contains("another execution stage"));
    }

    #[tokio::test]
    async fn scoped_container_lookup_never_falls_back_to_the_host_transport() {
        let (host_connection, _host_peer) = connection_pair().await;
        let (container_connection, _container_peer) = connection_pair().await;
        let host_environment = assignment("host-manager").provider.environment;
        let mut container_environment = host_environment.clone();
        container_environment.key = LocalKey::new("container").unwrap();
        container_environment.stage = ExecutionStage::SystemContainer;
        let capabilities = SystemdManagerCapabilities::from_scoped(
            [
                ScopedSystemdManagerCapability::host(
                    host_environment.clone(),
                    Arc::clone(&host_connection),
                )
                .unwrap(),
                ScopedSystemdManagerCapability::delegated_system_container_for_test(
                    container_environment.clone(),
                    Arc::clone(&container_connection),
                )
                .unwrap(),
            ],
            [],
        )
        .unwrap();

        let selected = capabilities
            .control_connection(&container_environment)
            .unwrap();
        assert!(Arc::ptr_eq(&selected, &container_connection));
        assert!(!Arc::ptr_eq(&selected, &host_connection));

        let mut foreign_environment = container_environment;
        foreign_environment.key = LocalKey::new("foreign-container").unwrap();
        let error = capabilities
            .control_connection(&foreign_environment)
            .err()
            .expect("an absent container scope must not use the host connection");
        assert!(error.to_string().contains("no trusted control manager"));
    }

    #[test]
    fn readiness_value_preserves_the_planned_subject_and_live_incarnation() {
        let subject = assignment("unobserved");
        let live = IncarnationId::new("bus:live;owner::1.42").unwrap();

        let value = assignment_value(&subject, live.clone()).unwrap();
        let observed: ProviderAssignment = serde_json::from_value(value.as_json().clone()).unwrap();

        assert_eq!(observed.provider, subject.provider);
        assert_eq!(observed.interface, subject.interface);
        assert_eq!(observed.implementation, subject.implementation);
        assert_eq!(observed.incarnation, live);
    }

    #[test]
    fn handoff_identity_binds_bootstrap_resource_and_target_provider_independently() {
        let target = assignment("manager-a").provider;
        let mut other_target = target.clone();
        other_target.key = LocalKey::new("other-target").unwrap();
        let bootstrap = ResourceId {
            provider: target.clone(),
            key: LocalKey::new("bootstrap").unwrap(),
        };
        let mut other_bootstrap = bootstrap.clone();
        other_bootstrap.key = LocalKey::new("other-bootstrap").unwrap();

        let expected = SystemdManagerHandoffKey {
            bootstrap_resource: bootstrap.clone(),
            target_provider: target.clone(),
        };

        assert_ne!(
            expected,
            SystemdManagerHandoffKey {
                bootstrap_resource: other_bootstrap,
                target_provider: target,
            }
        );
        assert_ne!(
            expected,
            SystemdManagerHandoffKey {
                bootstrap_resource: bootstrap,
                target_provider: other_target,
            }
        );
    }

    #[test]
    fn readiness_rejects_the_existing_control_manager() {
        let incarnation = IncarnationId::new("bus:host;owner::1.1").unwrap();

        let error = require_distinct_manager_incarnations(&incarnation, &incarnation).unwrap_err();

        assert!(error.to_string().contains("bootstrap control manager"));
    }

    async fn connection_pair() -> (Arc<SystemdManagerConnection>, zbus::Connection) {
        let guid = zbus::Guid::generate();
        let (server_socket, client_socket) = tokio::net::UnixStream::pair().unwrap();
        let server = zbus::connection::Builder::unix_stream(server_socket)
            .server(guid)
            .unwrap()
            .p2p()
            .build();
        let client = zbus::connection::Builder::unix_stream(client_socket)
            .p2p()
            .build();
        let (server, client) = tokio::join!(server, client);

        (
            Arc::new(SystemdManagerConnection::from_connection(client.unwrap())),
            server.unwrap(),
        )
    }

    fn assignment(incarnation: &str) -> ProviderAssignment {
        let digest = Sha256Digest::parse(&format!("sha256:{}", "1".repeat(64))).unwrap();
        ProviderAssignment {
            provider: InstanceId {
                environment: EnvironmentId {
                    authority: LocalKey::new("test").unwrap(),
                    key: LocalKey::new("host").unwrap(),
                    stage: ExecutionStage::Host,
                },
                key: LocalKey::new("systemd").unwrap(),
            },
            interface: InterfaceKey {
                name: InterfaceName::new("aos.test.systemd").unwrap(),
                abi: NonZeroU32::new(1).unwrap(),
                descriptor: digest,
            },
            implementation: ProviderImplementationReference {
                descriptor: digest,
                artifact: ArtifactReference {
                    content: digest,
                    store_path: "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-systemd".to_string(),
                    nar_hash: digest,
                    closure: digest,
                },
                handler: Some(LocalKey::new("systemd").unwrap()),
            },
            incarnation: IncarnationId::new(incarnation).unwrap(),
        }
    }
}
