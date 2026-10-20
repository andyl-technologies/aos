//! Owns the one Network mutation recipe and its concrete helper destinations.
//!
//! Namespace transitions, plan validation and typed effect ordering are shared.
//! The ordinary destination preserves immediate disposal; the paid Source
//! destination retains the exact helper and independently owed posts.

use super::*;

pub(super) struct LifecycleRecipeInputs<'a> {
    pub(super) plan: &'a crate::NetworkKernelPlanV1,
    pub(super) target: crate::NetworkNamespaceIdentityV1,
    pub(super) step: NetworkLifecycleExecutionStepV1,
    pub(super) desired: crate::NetworkNamespaceObservedStateV1,
    pub(super) action: crate::NetworkNamespaceLifecycleActionV1,
}

pub(super) trait HelperPort {
    fn current_artifact(
        &mut self,
        artifact: &PinnedArtifact,
        current_executable: bool,
    ) -> Result<(), NetworkKernelMutationError>;

    fn publish_namespace(
        &mut self,
        handle: [u8; 32],
        namespace: &NamespaceFd,
    ) -> Result<(), NetworkKernelMutationError>;

    fn status(
        &mut self,
        artifact: &PinnedArtifact,
        arguments: &[OsString],
        stdin: Option<BorrowedFd<'_>>,
        inherited: &[BorrowedFd<'_>],
    ) -> Result<(), NetworkKernelMutationError>;

    fn link_inventory(
        &mut self,
        artifact: &PinnedArtifact,
        arguments: &[OsString],
    ) -> Result<Vec<u8>, NetworkKernelMutationError>;

    fn complete_link_inventory(
        &mut self,
        result: Result<bool, NetworkKernelMutationError>,
    ) -> Result<bool, NetworkKernelMutationError>;

    fn nft_batch(
        &mut self,
        artifact: &PinnedArtifact,
        bytes: &[u8],
    ) -> Result<(), NetworkKernelMutationError>;
}

struct LocalHelperPort;

enum Helpers<'held> {
    Local(LocalHelperPort),
    Retained(&'held mut dyn HelperPort),
}

impl HelperPort for Helpers<'_> {
    fn current_artifact(
        &mut self,
        artifact: &PinnedArtifact,
        current_executable: bool,
    ) -> Result<(), NetworkKernelMutationError> {
        match self {
            Self::Local(port) => port.current_artifact(artifact, current_executable),
            Self::Retained(port) => port.current_artifact(artifact, current_executable),
        }
    }

    fn publish_namespace(
        &mut self,
        handle: [u8; 32],
        namespace: &NamespaceFd,
    ) -> Result<(), NetworkKernelMutationError> {
        match self {
            Self::Local(port) => port.publish_namespace(handle, namespace),
            Self::Retained(port) => port.publish_namespace(handle, namespace),
        }
    }

    fn status(
        &mut self,
        artifact: &PinnedArtifact,
        arguments: &[OsString],
        stdin: Option<BorrowedFd<'_>>,
        inherited: &[BorrowedFd<'_>],
    ) -> Result<(), NetworkKernelMutationError> {
        match self {
            Self::Local(port) => port.status(artifact, arguments, stdin, inherited),
            Self::Retained(port) => port.status(artifact, arguments, stdin, inherited),
        }
    }

    fn link_inventory(
        &mut self,
        artifact: &PinnedArtifact,
        arguments: &[OsString],
    ) -> Result<Vec<u8>, NetworkKernelMutationError> {
        match self {
            Self::Local(port) => port.link_inventory(artifact, arguments),
            Self::Retained(port) => port.link_inventory(artifact, arguments),
        }
    }

    fn nft_batch(
        &mut self,
        artifact: &PinnedArtifact,
        bytes: &[u8],
    ) -> Result<(), NetworkKernelMutationError> {
        match self {
            Self::Local(port) => port.nft_batch(artifact, bytes),
            Self::Retained(port) => port.nft_batch(artifact, bytes),
        }
    }

    fn complete_link_inventory(
        &mut self,
        result: Result<bool, NetworkKernelMutationError>,
    ) -> Result<bool, NetworkKernelMutationError> {
        match self {
            Self::Local(port) => port.complete_link_inventory(result),
            Self::Retained(port) => port.complete_link_inventory(result),
        }
    }
}

impl HelperPort for LocalHelperPort {
    fn current_artifact(
        &mut self,
        artifact: &PinnedArtifact,
        current_executable: bool,
    ) -> Result<(), NetworkKernelMutationError> {
        if current_executable {
            artifact.validate_current_executable()?;
        } else {
            artifact.validate_current()?;
        }
        Ok(())
    }

    fn publish_namespace(
        &mut self,
        handle: [u8; 32],
        namespace: &NamespaceFd,
    ) -> Result<(), NetworkKernelMutationError> {
        publish_namespace_pin(handle, namespace).map_err(Into::into)
    }

    fn complete_link_inventory(
        &mut self,
        result: Result<bool, NetworkKernelMutationError>,
    ) -> Result<bool, NetworkKernelMutationError> {
        result
    }

    fn status(
        &mut self,
        artifact: &PinnedArtifact,
        arguments: &[OsString],
        stdin: Option<BorrowedFd<'_>>,
        inherited: &[BorrowedFd<'_>],
    ) -> Result<(), NetworkKernelMutationError> {
        run_fixed_status(artifact, arguments, stdin, inherited)
    }

    fn link_inventory(
        &mut self,
        artifact: &PinnedArtifact,
        arguments: &[OsString],
    ) -> Result<Vec<u8>, NetworkKernelMutationError> {
        let output = artifact.run(arguments, MAXIMUM_LINK_INVENTORY_BYTES)?;
        Ok(successful_helper_stdout(output)?)
    }

    fn nft_batch(
        &mut self,
        artifact: &PinnedArtifact,
        bytes: &[u8],
    ) -> Result<(), NetworkKernelMutationError> {
        let descriptor =
            rustix::fs::memfd_create("aos-network-nft-batch", rustix::fs::MemfdFlags::CLOEXEC)
                .map_err(linux_syscall("create nftables batch"))?;
        let mut input = File::from(descriptor);
        input
            .write_all(bytes)
            .map_err(|_| NetworkKernelMutationError::Nftables)?;
        input
            .rewind()
            .map_err(|_| NetworkKernelMutationError::Nftables)?;
        self.status(
            artifact,
            &["--json".into(), "--file".into(), "-".into()],
            Some(input.as_fd()),
            &[],
        )
    }
}

pub(crate) struct Recipe<'held> {
    mutator: &'held FixedNetworkKernelMutator,
    helpers: Helpers<'held>,
}

impl<'held> Recipe<'held> {
    pub(super) fn local(mutator: &'held FixedNetworkKernelMutator) -> Self {
        Self {
            mutator,
            helpers: Helpers::Local(LocalHelperPort),
        }
    }

    pub(super) fn retained(
        mutator: &'held FixedNetworkKernelMutator,
        helpers: &'held mut dyn HelperPort,
    ) -> Self {
        Self {
            mutator,
            helpers: Helpers::Retained(helpers),
        }
    }

    /// Creates the table and both default-drop base chains as the first effect.
    ///
    /// The caller must already have retained the target namespace in durable
    /// custody and persisted the request at the Ambiguous boundary. The
    /// authenticated authorization proves that precondition to this effect
    /// layer; the retained namespace must also be the worker's current one.
    ///
    /// # Errors
    ///
    /// Returns [`NetworkKernelMutationError`] for namespace substitution,
    /// artifact mismatch, an unsupported plan, oversized policy, or any failed
    /// nftables transaction. Exclusive `create` operations reject every
    /// preexisting table or chain; existing objects are never changed.
    pub(crate) fn install_default_drop(
        &mut self,
        authorization: &NetworkMutationAuthorizationV1,
        target_namespace: &NamespaceFd,
    ) -> Result<PreparedDefaultDropV1, NetworkKernelMutationError> {
        target_namespace.validate_current_network()?;
        let plan = authorization.kernel_plan();
        let expectation = plan.observation_expectation();
        self.validate_artifacts(expectation)?;

        let batch = encode_nftables_base(expectation)?;
        self.run_nft_batch(&batch)?;
        target_namespace.validate_current_network()?;
        self.validate_artifacts(expectation)?;

        Ok(PreparedDefaultDropV1 {
            plan_digest: plan.digest(),
            namespace: target_namespace.identity(),
        })
    }

    /// Creates and configures the optional veth and disarmed TCX lease gate.
    ///
    /// This requires the fresh activation token obtained after default-drop
    /// installation. Veth creation fails on every preexisting name or pin
    /// conflict; this path does not delete or reuse prior kernel objects. Both
    /// ends remain down, and the worker is restored to the target namespace
    /// before success is returned.
    ///
    /// # Errors
    ///
    /// Returns [`NetworkKernelMutationError`] for a mismatched preparation or
    /// activation, namespace substitution, fixed-helper failure, or any failed
    /// link, address, route, or BPF operation. Failure to restore the target
    /// namespace aborts the one-shot worker process.
    pub(crate) fn realize_prepared(
        &mut self,
        prepared: PreparedDefaultDropV1,
        activation: &NetworkActivationAuthorizationV1<'_>,
        target_namespace: &NamespaceFd,
        host_namespace: &NamespaceFd,
        worker: &SingleThreadedProcess,
    ) -> Result<(), NetworkKernelMutationError> {
        let plan = activation.kernel_plan();
        let expectation = plan.observation_expectation();
        if prepared.plan_digest != plan.digest()
            || prepared.namespace != target_namespace.identity()
            || target_namespace.identity() == host_namespace.identity()
        {
            return Err(NetworkKernelMutationError::UnsupportedPlan);
        }
        target_namespace.validate_current_network()?;
        self.validate_artifacts(expectation)?;

        match expectation.kind() {
            NetworkKind::Isolated => {
                if expectation.veth().is_some()
                    || expectation.lease_gate_artifact_digest().is_some()
                    || !expectation.address_pairs().is_empty()
                    || !expectation.routes().is_empty()
                {
                    return Err(NetworkKernelMutationError::UnsupportedPlan);
                }
            }
            NetworkKind::Project | NetworkKind::Outbound | NetworkKind::Published => {
                self.realize_veth(expectation, target_namespace, host_namespace, worker)?;
            }
            NetworkKind::Host => return Err(NetworkKernelMutationError::UnsupportedPlan),
        }

        self.run_ip(&["link", "set", "dev", "lo", "up"])?;
        target_namespace.validate_current_network()?;
        self.validate_artifacts(expectation)
    }

    /// Publishes the realized target through its fixed handle-derived pin.
    ///
    /// This must run in the initial host mount namespace after all planned
    /// kernel objects exist and before the worker acknowledges success.
    ///
    /// # Errors
    ///
    /// Returns an error for changed plan artifacts, namespace substitution,
    /// an existing pin, failed bind publication, or identity mismatch.
    pub(crate) fn publish_prepared_namespace(
        &mut self,
        authorization: &NetworkMutationAuthorizationV1,
        target_namespace: &NamespaceFd,
    ) -> Result<(), NetworkKernelMutationError> {
        target_namespace.validate_current_network()?;
        let expectation = authorization.kernel_plan().observation_expectation();
        self.validate_artifacts(expectation)?;
        self.helpers
            .publish_namespace(*expectation.network_handle(), target_namespace)?;
        self.validate_artifacts(expectation)
    }

    /// Executes one already freshness-gated existing-resource lifecycle step.
    ///
    /// The caller must acknowledge the step token only after this method
    /// succeeds. Every namespace transition returns to the worker's private
    /// bootstrap namespace; failure to restore that namespace aborts the
    /// one-shot process because later authority checks would be ambiguous.
    ///
    /// # Errors
    ///
    /// Returns an error for namespace substitution, an unsupported plan/step
    /// combination, changed fixed artifacts, or any failed kernel mutation.
    pub(crate) fn execute_lifecycle_step(
        &mut self,
        authorization: &NetworkLifecycleAuthorizedStepV1<'_>,
        target_namespace: &NamespaceFd,
        host_namespace: &NamespaceFd,
        bootstrap_namespace: &NamespaceFd,
        worker: &SingleThreadedProcess,
    ) -> Result<(), NetworkKernelMutationError> {

        self.execute_lifecycle_inputs(LifecycleRecipeInputs {
            plan: authorization.kernel_plan(), target: authorization.target_namespace(),
            step: authorization.step(), desired: authorization.desired_state(),
            action: authorization.action(),
        }, target_namespace, host_namespace, bootstrap_namespace, worker)
    }

    pub(super) fn execute_lifecycle_inputs(
        &mut self,
        input: LifecycleRecipeInputs<'_>,
        target_namespace: &NamespaceFd,
        host_namespace: &NamespaceFd,
        bootstrap_namespace: &NamespaceFd,
        worker: &SingleThreadedProcess,
    ) -> Result<(), NetworkKernelMutationError> {
        let expectation = input.plan.observation_expectation();
        if target_namespace.identity().device != input.target.namespace_device()
            || target_namespace.identity().inode
                != input.target.namespace_inode()
            || target_namespace.identity() == host_namespace.identity()
            || bootstrap_namespace.identity() == target_namespace.identity()
            || bootstrap_namespace.identity() == host_namespace.identity()
        {
            return Err(NetworkKernelMutationError::UnsupportedPlan);
        }
        bootstrap_namespace.validate_current_network()?;
        self.validate_artifacts(expectation)?;

        match input.step {
            NetworkLifecycleExecutionStepV1::EnsureLinksDown => self.set_link_pair_state(
                expectation,
                target_namespace,
                host_namespace,
                bootstrap_namespace,
                worker,
                false,
                false,
            )?,
            NetworkLifecycleExecutionStepV1::ArmLeaseGate
            | NetworkLifecycleExecutionStepV1::ReplaceLeaseGateAtomically => {
                self.set_lease_gate(expectation, input.desired)?
            }
            NetworkLifecycleExecutionStepV1::ConfigureExactAddressPairs => self
                .replace_address_pairs(
                    expectation,
                    target_namespace,
                    host_namespace,
                    bootstrap_namespace,
                    worker,
                )?,
            NetworkLifecycleExecutionStepV1::ConfigureExactRoutes => {
                self.replace_routes(expectation, target_namespace, bootstrap_namespace, worker)?
            }
            NetworkLifecycleExecutionStepV1::ConfigureExactPermanentNeighbors => self
                .replace_neighbors(
                    expectation,
                    target_namespace,
                    host_namespace,
                    bootstrap_namespace,
                    worker,
                )?,
            NetworkLifecycleExecutionStepV1::VerifyExactPlanConfiguration => {
                self.validate_artifacts(expectation)?
            }
            NetworkLifecycleExecutionStepV1::RaiseLinks => self.set_link_pair_state(
                expectation,
                target_namespace,
                host_namespace,
                bootstrap_namespace,
                worker,
                true,
                false,
            )?,
            NetworkLifecycleExecutionStepV1::LowerLinks => self.set_link_pair_state(
                expectation,
                target_namespace,
                host_namespace,
                bootstrap_namespace,
                worker,
                false,
                input.action == crate::NetworkNamespaceLifecycleActionV1::Destroy,
            )?,
            NetworkLifecycleExecutionStepV1::DisarmLeaseGate => {
                self.set_default_drop_gate(expectation)?
            }
            NetworkLifecycleExecutionStepV1::RemoveOwnedNetworkObjects => self
                .remove_owned_network_objects(
                    expectation,
                    target_namespace,
                    host_namespace,
                    bootstrap_namespace,
                    worker,
                )?,
            NetworkLifecycleExecutionStepV1::VerifyKernelOwnedObjectsAbsent => {
                self.validate_artifacts(expectation)?
            }
        }

        bootstrap_namespace.validate_current_network()?;
        self.validate_artifacts(expectation)
    }

    fn set_link_pair_state(
        &mut self,
        expectation: &NetworkKernelExpectationV1,
        target_namespace: &NamespaceFd,
        host_namespace: &NamespaceFd,
        bootstrap_namespace: &NamespaceFd,
        worker: &SingleThreadedProcess,
        raised: bool,
        absent_is_success: bool,
    ) -> Result<(), NetworkKernelMutationError> {
        let Some(veth) = expectation.veth() else {
            return Ok(());
        };
        let state = if raised { "up" } else { "down" };
        Self::in_namespace(target_namespace, bootstrap_namespace, worker, || {
            if absent_is_success && !self.link_name_present(&veth.sandbox_name)? {
                return Ok(());
            }
            self.run_ip(&["link", "set", "dev", &veth.sandbox_name, state])
        })?;
        Self::in_namespace(host_namespace, bootstrap_namespace, worker, || {
            if absent_is_success && !self.link_name_present(&veth.host_name)? {
                return Ok(());
            }
            self.run_ip(&["link", "set", "dev", &veth.host_name, state])
        })
    }

    fn set_lease_gate(
        &mut self,
        expectation: &NetworkKernelExpectationV1,
        desired_state: crate::NetworkNamespaceObservedStateV1,
    ) -> Result<(), NetworkKernelMutationError> {
        let (lease_digest, generation, deadline) = desired_state
            .lease()
            .ok_or(NetworkKernelMutationError::UnsupportedPlan)?;
        self.run_lease_gate(&[
            "set-lease".into(),
            encode_hex(expectation.network_handle()).into(),
            expectation.assignment().epoch().get().to_string().into(),
            encode_hex(expectation.assignment().digest().as_bytes()).into(),
            generation.to_string().into(),
            deadline.to_string().into(),
            encode_hex(lease_digest.as_bytes()).into(),
        ])
    }

    fn set_default_drop_gate(
        &mut self,
        expectation: &NetworkKernelExpectationV1,
    ) -> Result<(), NetworkKernelMutationError> {
        self.run_lease_gate(&[
            "set-default-drop".into(),
            encode_hex(expectation.network_handle()).into(),
            expectation.assignment().epoch().get().to_string().into(),
            encode_hex(expectation.assignment().digest().as_bytes()).into(),
        ])
    }

    fn replace_address_pairs(
        &mut self,
        expectation: &NetworkKernelExpectationV1,
        target_namespace: &NamespaceFd,
        host_namespace: &NamespaceFd,
        bootstrap_namespace: &NamespaceFd,
        worker: &SingleThreadedProcess,
    ) -> Result<(), NetworkKernelMutationError> {
        let veth = expectation
            .veth()
            .ok_or(NetworkKernelMutationError::UnsupportedPlan)?;
        Self::in_namespace(target_namespace, bootstrap_namespace, worker, || {
            for pair in expectation.address_pairs() {
                self.replace_address(&veth.sandbox_name, pair.sandbox, pair.prefix_length)?;
            }
            Ok(())
        })?;
        Self::in_namespace(host_namespace, bootstrap_namespace, worker, || {
            for pair in expectation.address_pairs() {
                self.replace_address(&veth.host_name, pair.host, pair.prefix_length)?;
            }
            Ok(())
        })
    }

    fn replace_routes(
        &mut self,
        expectation: &NetworkKernelExpectationV1,
        target_namespace: &NamespaceFd,
        bootstrap_namespace: &NamespaceFd,
        worker: &SingleThreadedProcess,
    ) -> Result<(), NetworkKernelMutationError> {
        let veth = expectation
            .veth()
            .ok_or(NetworkKernelMutationError::UnsupportedPlan)?;
        Self::in_namespace(target_namespace, bootstrap_namespace, worker, || {
            for route in expectation.routes() {
                self.replace_route(&veth.sandbox_name, route.destination, route.gateway)?;
            }
            Ok(())
        })
    }

    fn replace_neighbors(
        &mut self,
        expectation: &NetworkKernelExpectationV1,
        target_namespace: &NamespaceFd,
        host_namespace: &NamespaceFd,
        bootstrap_namespace: &NamespaceFd,
        worker: &SingleThreadedProcess,
    ) -> Result<(), NetworkKernelMutationError> {
        let veth = expectation
            .veth()
            .ok_or(NetworkKernelMutationError::UnsupportedPlan)?;
        Self::in_namespace(target_namespace, bootstrap_namespace, worker, || {
            for pair in expectation.address_pairs() {
                if matches!(pair.sandbox, ObservedIpAddressV1::Ipv6(_)) {
                    self.replace_ipv6_neighbor(&veth.sandbox_name, pair.host, veth.host_mac)?;
                }
            }
            Ok(())
        })?;
        Self::in_namespace(host_namespace, bootstrap_namespace, worker, || {
            for pair in expectation.address_pairs() {
                if matches!(pair.host, ObservedIpAddressV1::Ipv6(_)) {
                    self.replace_ipv6_neighbor(&veth.host_name, pair.sandbox, veth.sandbox_mac)?;
                }
            }
            Ok(())
        })
    }

    fn remove_owned_network_objects(
        &mut self,
        expectation: &NetworkKernelExpectationV1,
        target_namespace: &NamespaceFd,
        host_namespace: &NamespaceFd,
        bootstrap_namespace: &NamespaceFd,
        worker: &SingleThreadedProcess,
    ) -> Result<(), NetworkKernelMutationError> {
        Self::in_namespace(target_namespace, bootstrap_namespace, worker, || {
            self.run_nft_destroy_table()
        })?;
        let Some(veth) = expectation.veth() else {
            return Ok(());
        };
        Self::in_namespace(host_namespace, bootstrap_namespace, worker, || {
            self.run_lease_gate(&[
                "remove".into(),
                encode_hex(expectation.network_handle()).into(),
                expectation.assignment().epoch().get().to_string().into(),
                encode_hex(expectation.assignment().digest().as_bytes()).into(),
            ])?;
            if self.link_name_present(&veth.host_name)? {
                self.run_ip(&["link", "delete", "dev", &veth.host_name])?;
            }
            Ok(())
        })
    }

    fn link_name_present(
        &mut self,
        expected_name: &str,
    ) -> Result<bool, NetworkKernelMutationError> {
        let arguments = [
            OsString::from("-j"),
            OsString::from("link"),
            OsString::from("show"),
        ];
        let stdout = self.helpers.link_inventory(&self.mutator.ip, &arguments)?;
        let result = link_name_present_in_inventory(&stdout, expected_name);
        self.helpers.complete_link_inventory(result)
    }

    fn in_namespace<T>(
        namespace: &NamespaceFd,
        bootstrap_namespace: &NamespaceFd,
        worker: &SingleThreadedProcess,
        operation: impl FnOnce() -> Result<T, NetworkKernelMutationError>,
    ) -> Result<T, NetworkKernelMutationError> {
        namespace.enter(worker)?;
        let result = operation();
        let restored = bootstrap_namespace
            .enter(worker)
            .and_then(|()| bootstrap_namespace.validate_current_network());
        if restored.is_err() {
            std::process::abort();
        }
        result
    }

    fn validate_artifacts(
        &mut self,
        expectation: &NetworkKernelExpectationV1,
    ) -> Result<(), NetworkKernelMutationError> {
        for artifact in [
            &self.mutator.ip,
            &self.mutator.nft,
            &self.mutator.lease_gate_loader,
            &self.mutator.lease_gate_object,
        ] {
            self.helpers.current_artifact(artifact, false)?;
        }
        self.helpers
            .current_artifact(&self.mutator.enforcement_artifact, true)?;
        if self.mutator.enforcement_artifact.digest() != expectation.enforcement_artifact_digest()
            || expectation.lease_gate_artifact_digest().is_some() != expectation.veth().is_some()
            || expectation
                .lease_gate_artifact_digest()
                .is_some_and(|digest| digest != self.mutator.lease_gate_object.digest())
        {
            return Err(NetworkKernelMutationError::Artifact);
        }
        Ok(())
    }

    fn realize_veth(
        &mut self,
        expectation: &NetworkKernelExpectationV1,
        target_namespace: &NamespaceFd,
        host_namespace: &NamespaceFd,
        worker: &SingleThreadedProcess,
    ) -> Result<(), NetworkKernelMutationError> {
        let veth = expectation
            .veth()
            .ok_or(NetworkKernelMutationError::UnsupportedPlan)?;
        self.helpers.status(
            &self.mutator.ip,
            &[
                "link".into(),
                "add".into(),
                "name".into(),
                veth.sandbox_name.clone().into(),
                "type".into(),
                "veth".into(),
                "peer".into(),
                "name".into(),
                veth.host_name.clone().into(),
                "netns".into(),
                inherited_fd_path(3),
            ],
            None,
            &[host_namespace.as_fd()],
        )?;

        self.configure_link(&veth.sandbox_name, veth.sandbox_mac, veth.mtu)?;
        for pair in expectation.address_pairs() {
            self.add_address(&veth.sandbox_name, pair.sandbox, pair.prefix_length)?;
            if matches!(pair.sandbox, ObservedIpAddressV1::Ipv6(_)) {
                self.add_ipv6_neighbor(&veth.sandbox_name, pair.host, veth.host_mac)?;
            }
        }
        for route in expectation.routes() {
            self.add_route(&veth.sandbox_name, route.destination, route.gateway)?;
        }
        self.run_nft_batch(&encode_nftables_rules(expectation)?)?;

        host_namespace.enter(worker)?;
        let host_result = (|| {
            host_namespace.validate_current_network()?;
            self.configure_link(&veth.host_name, veth.host_mac, veth.mtu)?;
            for pair in expectation.address_pairs() {
                self.add_address(&veth.host_name, pair.host, pair.prefix_length)?;
                if matches!(pair.host, ObservedIpAddressV1::Ipv6(_)) {
                    self.add_ipv6_neighbor(&veth.host_name, pair.sandbox, veth.sandbox_mac)?;
                }
            }
            self.install_disarmed_gate(expectation, target_namespace)?;
            Ok::<_, NetworkKernelMutationError>(())
        })();
        let restored = target_namespace
            .enter(worker)
            .and_then(|()| target_namespace.validate_current_network());
        if restored.is_err() {
            std::process::abort();
        }
        host_result
    }

    fn configure_link(
        &mut self,
        name: &str,
        mac: [u8; 6],
        mtu: u32,
    ) -> Result<(), NetworkKernelMutationError> {
        let mac = format_mac(mac);
        let mtu = mtu.to_string();
        self.run_ip_owned(&[
            "link".into(),
            "set".into(),
            "dev".into(),
            name.into(),
            "address".into(),
            mac.into(),
            "mtu".into(),
            mtu.into(),
            "addrgenmode".into(),
            "none".into(),
            "down".into(),
        ])
    }

    fn add_address(
        &mut self,
        interface: &str,
        address: ObservedIpAddressV1,
        prefix_length: u8,
    ) -> Result<(), NetworkKernelMutationError> {
        let ipv6 = matches!(address, ObservedIpAddressV1::Ipv6(_));
        let family = address_family_flag(address);
        let address = format!("{}/{}", format_address(address), prefix_length);
        let mut arguments = vec![
            family.into(),
            "address".into(),
            "add".into(),
            address.into(),
        ];
        if ipv6 {
            arguments.push("nodad".into());
        }
        arguments.extend(["dev".into(), interface.into()]);
        self.run_ip_owned(&arguments)
    }

    fn replace_address(
        &mut self,
        interface: &str,
        address: ObservedIpAddressV1,
        prefix_length: u8,
    ) -> Result<(), NetworkKernelMutationError> {
        let ipv6 = matches!(address, ObservedIpAddressV1::Ipv6(_));
        let family = address_family_flag(address);
        let address = format!("{}/{}", format_address(address), prefix_length);
        let mut arguments = vec![
            family.into(),
            "address".into(),
            "replace".into(),
            address.into(),
        ];
        if ipv6 {
            arguments.push("nodad".into());
        }
        arguments.extend(["dev".into(), interface.into()]);
        self.run_ip_owned(&arguments)
    }

    fn add_ipv6_neighbor(
        &mut self,
        interface: &str,
        address: ObservedIpAddressV1,
        mac: [u8; 6],
    ) -> Result<(), NetworkKernelMutationError> {
        let ObservedIpAddressV1::Ipv6(_) = address else {
            return Err(NetworkKernelMutationError::UnsupportedPlan);
        };
        let address = format_address(address);
        let mac = format_mac(mac);
        self.run_ip_owned(&[
            "-6".into(),
            "neighbor".into(),
            "add".into(),
            address.into(),
            "lladdr".into(),
            mac.into(),
            "nud".into(),
            "permanent".into(),
            "dev".into(),
            interface.into(),
        ])
    }

    fn replace_ipv6_neighbor(
        &mut self,
        interface: &str,
        address: ObservedIpAddressV1,
        mac: [u8; 6],
    ) -> Result<(), NetworkKernelMutationError> {
        let ObservedIpAddressV1::Ipv6(_) = address else {
            return Err(NetworkKernelMutationError::UnsupportedPlan);
        };
        self.run_ip_owned(&[
            "-6".into(),
            "neighbor".into(),
            "replace".into(),
            format_address(address).into(),
            "lladdr".into(),
            format_mac(mac).into(),
            "nud".into(),
            "permanent".into(),
            "dev".into(),
            interface.into(),
        ])
    }

    fn add_route(
        &mut self,
        interface: &str,
        destination: ObservedIpPrefixV1,
        gateway: ObservedIpAddressV1,
    ) -> Result<(), NetworkKernelMutationError> {
        let family = address_family_flag(destination.address);
        let destination = format!(
            "{}/{}",
            format_address(destination.address),
            destination.prefix_length
        );
        let gateway = format_address(gateway);
        self.run_ip_owned(&[
            family.into(),
            "route".into(),
            "add".into(),
            destination.into(),
            "via".into(),
            gateway.into(),
            "dev".into(),
            interface.into(),
        ])
    }

    fn replace_route(
        &mut self,
        interface: &str,
        destination: ObservedIpPrefixV1,
        gateway: ObservedIpAddressV1,
    ) -> Result<(), NetworkKernelMutationError> {
        let family = address_family_flag(destination.address);
        let destination = format!(
            "{}/{}",
            format_address(destination.address),
            destination.prefix_length
        );
        self.run_ip_owned(&[
            family.into(),
            "route".into(),
            "replace".into(),
            destination.into(),
            "via".into(),
            format_address(gateway).into(),
            "dev".into(),
            interface.into(),
        ])
    }

    fn install_disarmed_gate(
        &mut self,
        expectation: &NetworkKernelExpectationV1,
        target_namespace: &NamespaceFd,
    ) -> Result<(), NetworkKernelMutationError> {
        let veth = expectation
            .veth()
            .ok_or(NetworkKernelMutationError::UnsupportedPlan)?;
        let gate_digest = expectation
            .lease_gate_artifact_digest()
            .ok_or(NetworkKernelMutationError::UnsupportedPlan)?;
        let arguments = [
            OsString::from("install-disarmed"),
            veth.host_name.clone().into(),
            veth.sandbox_name.clone().into(),
            inherited_fd_path(3),
            expectation.assignment().epoch().get().to_string().into(),
            expectation.allocation_generation().to_string().into(),
            encode_hex(expectation.network_handle()).into(),
            encode_hex(expectation.assignment().digest().as_bytes()).into(),
            encode_hex(gate_digest.as_bytes()).into(),
            self.mutator.lease_gate_object.path().as_os_str().to_owned(),
        ];
        self.helpers.status(
            &self.mutator.lease_gate_loader,
            &arguments,
            None,
            &[target_namespace.as_fd()],
        )
    }

    fn run_nft_batch(&mut self, bytes: &[u8]) -> Result<(), NetworkKernelMutationError> {
        if bytes.is_empty() || bytes.len() > MAXIMUM_NFT_BATCH_BYTES || !bytes.ends_with(b"\n") {
            return Err(NetworkKernelMutationError::Nftables);
        }
        self.helpers.nft_batch(&self.mutator.nft, bytes)
    }

    fn run_nft_destroy_table(&mut self) -> Result<(), NetworkKernelMutationError> {
        self.helpers
            .status(&self.mutator.nft, &nftables_destroy_arguments(), None, &[])
    }

    fn run_ip(&mut self, arguments: &[&str]) -> Result<(), NetworkKernelMutationError> {
        let arguments = arguments.iter().map(OsString::from).collect::<Vec<_>>();
        self.run_ip_owned(&arguments)
    }

    fn run_ip_owned(&mut self, arguments: &[OsString]) -> Result<(), NetworkKernelMutationError> {
        self.helpers.status(&self.mutator.ip, arguments, None, &[])
    }

    fn run_lease_gate(&mut self, arguments: &[OsString]) -> Result<(), NetworkKernelMutationError> {
        self.helpers
            .status(&self.mutator.lease_gate_loader, arguments, None, &[])
    }
}
