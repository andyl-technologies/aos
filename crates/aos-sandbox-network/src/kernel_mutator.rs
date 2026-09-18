//! Typed, fail-closed realization of one prepared Network kernel plan.
//!
//! The mutator accepts only a non-clone authenticated mutation authorization.
//! It first creates the nftables table and both default-drop base chains in the
//! worker's already-custodied private namespace. A distinct fresh activation
//! token is then required before a veth can be created directly into the
//! retained host namespace, the plan's policy rules can be added, and the fixed
//! disarmed TCX lease gate can be installed. Both veth ends remain
//! administratively down.
//!
//! Fixed helpers are immutable Nix-store artifacts retained and remeasured by
//! descriptor. Every invocation uses a closed environment and exact typed
//! arguments; no shell, caller path, interface label, or command text crosses
//! this boundary.

use std::collections::BTreeSet;
use std::ffi::OsString;
use std::fs::File;
use std::io::{Seek as _, Write as _};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::os::fd::{AsFd as _, BorrowedFd};
use std::path::PathBuf;
use std::time::Duration;

use aos_sandbox_core::ObjectDigest;
use aos_sandbox_core::model::NetworkKind;
use aos_sandbox_linux::pidfd::{NamespaceFd, NamespaceIdentity, SingleThreadedProcess};
use aos_sandbox_linux::process::{
    FixedProcessDescriptorRequest, FixedProcessOutcome, FixedProcessRequest,
    run_fixed_process_with_descriptors,
};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::{Value, json};

use crate::kernel_observation::{
    NetworkKernelExpectationV1, ObservedIpAddressV1, ObservedIpPrefixV1,
};
use crate::kernel_reader::{NetworkKernelReaderError, PinnedArtifact, successful_helper_stdout};
use crate::namespace_pin::{NetworkNamespacePinMutationError, publish_namespace_pin};
use crate::policy::{
    NetworkFlowDirectionV1, NetworkFlowPolicyV1, NetworkIpPrefixV1, NetworkTransportProtocolV1,
};
use crate::{
    NetworkActivationAuthorizationV1, NetworkLifecycleAuthorizedStepV1,
    NetworkLifecycleExecutionStepV1, NetworkMutationAuthorizationV1,
};

const MAXIMUM_NFT_BATCH_BYTES: usize = 4 * 1024 * 1024;
const MAXIMUM_LINK_INVENTORY_BYTES: usize = 64 * 1024;
const MAXIMUM_ARGUMENTS: usize = 32;
const MAXIMUM_ARGUMENT_BYTES: usize = 16 * 1024;
const HELPER_TIMEOUT: Duration = Duration::from_secs(5);
const MAXIMUM_HELPER_OUTPUT_BYTES: usize = 16 * 1024;
const TABLE_FAMILY: &str = "inet";
const TABLE_NAME: &str = "aos_sandbox";
const TABLE_PROVENANCE_PREFIX: &str = "aos.net.v1:a=";
const TABLE_POLICY_SEPARATOR: &str = ":p=";
const ANTI_SPOOF_COMMENT: &str = "aos.sandbox.network.rule.v1 anti-spoof";
const FLOW_COMMENT_PREFIX: &str = "aos.sandbox.network.rule.v1 flow=";

/// Reports rejected artifacts, namespace substitution, or a failed kernel effect.
#[derive(Debug, thiserror::Error)]
pub enum NetworkKernelMutationError {
    /// A fixed immutable helper or object did not match the authorized plan.
    #[error("fixed Network mutator artifact was rejected")]
    Artifact,
    /// A namespace or single-thread transition was rejected by Linux.
    #[error("Network mutator namespace authority was rejected: {0}")]
    Linux(#[from] aos_sandbox_linux::Error),
    /// A retained fixed artifact could not be revalidated.
    #[error("Network mutator artifact validation failed: {0}")]
    Reader(#[from] NetworkKernelReaderError),
    /// A fixed helper failed, timed out, or could not be executed.
    #[error("fixed Network mutator process failed")]
    Helper,
    /// The plan cannot be represented by the fixed mutation profile.
    #[error("Network kernel plan is unsupported by the fixed mutator")]
    UnsupportedPlan,
    /// Atomic nftables input exceeded its closed bound or could not be encoded.
    #[error("Network nftables mutation batch is invalid")]
    Nftables,
    /// The canonical host-visible namespace pin could not be published.
    #[error(transparent)]
    NamespacePin(#[from] NetworkNamespacePinMutationError),
}

/// Retains all immutable production artifacts used for Network mutation.
#[derive(Debug)]
pub struct FixedNetworkKernelMutator {
    ip: PinnedArtifact,
    nft: PinnedArtifact,
    enforcement_artifact: PinnedArtifact,
    lease_gate_loader: PinnedArtifact,
    lease_gate_object: PinnedArtifact,
}

/// Proves the plan's table and both default-drop base chains were created.
#[derive(Debug, Eq, PartialEq)]
pub struct PreparedDefaultDropV1 {
    plan_digest: ObjectDigest,
    namespace: NamespaceIdentity,
}

impl FixedNetworkKernelMutator {
    /// Opens and retains the fixed mutation toolchain and policy artifacts.
    ///
    /// `enforcement_artifact` names the reviewed executable whose digest is
    /// recorded in nftables provenance. `lease_gate_loader` is the fixed
    /// libbpf installer; `lease_gate_object` is the exact object it installs.
    ///
    /// # Errors
    ///
    /// Returns [`NetworkKernelMutationError`] unless every path names an
    /// immutable root-owned Nix-store artifact of the required file type.
    pub fn new(
        ip: PathBuf,
        nft: PathBuf,
        enforcement_artifact: PathBuf,
        lease_gate_loader: PathBuf,
        lease_gate_object: PathBuf,
    ) -> Result<Self, NetworkKernelMutationError> {
        Ok(Self {
            ip: PinnedArtifact::open(ip, true)?,
            nft: PinnedArtifact::open(nft, true)?,
            enforcement_artifact: PinnedArtifact::open(enforcement_artifact, true)?,
            lease_gate_loader: PinnedArtifact::open(lease_gate_loader, true)?,
            lease_gate_object: PinnedArtifact::open(lease_gate_object, false)?,
        })
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
    pub fn install_default_drop(
        &self,
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
    pub fn realize_prepared(
        &self,
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
    pub fn publish_prepared_namespace(
        &self,
        authorization: &NetworkMutationAuthorizationV1,
        target_namespace: &NamespaceFd,
    ) -> Result<(), NetworkKernelMutationError> {
        target_namespace.validate_current_network()?;
        let expectation = authorization.kernel_plan().observation_expectation();
        self.validate_artifacts(expectation)?;
        publish_namespace_pin(*expectation.network_handle(), target_namespace)?;
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
    pub fn execute_lifecycle_step(
        &self,
        authorization: &NetworkLifecycleAuthorizedStepV1<'_>,
        target_namespace: &NamespaceFd,
        host_namespace: &NamespaceFd,
        bootstrap_namespace: &NamespaceFd,
        worker: &SingleThreadedProcess,
    ) -> Result<(), NetworkKernelMutationError> {
        let expectation = authorization.kernel_plan().observation_expectation();
        if target_namespace.identity().device != authorization.target_namespace().namespace_device()
            || target_namespace.identity().inode
                != authorization.target_namespace().namespace_inode()
            || target_namespace.identity() == host_namespace.identity()
            || bootstrap_namespace.identity() == target_namespace.identity()
            || bootstrap_namespace.identity() == host_namespace.identity()
        {
            return Err(NetworkKernelMutationError::UnsupportedPlan);
        }
        bootstrap_namespace.validate_current_network()?;
        self.validate_artifacts(expectation)?;

        match authorization.step() {
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
                self.set_lease_gate(expectation, authorization.desired_state())?
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
                authorization.action() == crate::NetworkNamespaceLifecycleActionV1::Destroy,
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
        &self,
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
        self.in_namespace(target_namespace, bootstrap_namespace, worker, || {
            if absent_is_success && !self.link_name_present(&veth.sandbox_name)? {
                return Ok(());
            }
            self.run_ip(&["link", "set", "dev", &veth.sandbox_name, state])
        })?;
        self.in_namespace(host_namespace, bootstrap_namespace, worker, || {
            if absent_is_success && !self.link_name_present(&veth.host_name)? {
                return Ok(());
            }
            self.run_ip(&["link", "set", "dev", &veth.host_name, state])
        })
    }

    fn set_lease_gate(
        &self,
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
        &self,
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
        &self,
        expectation: &NetworkKernelExpectationV1,
        target_namespace: &NamespaceFd,
        host_namespace: &NamespaceFd,
        bootstrap_namespace: &NamespaceFd,
        worker: &SingleThreadedProcess,
    ) -> Result<(), NetworkKernelMutationError> {
        let veth = expectation
            .veth()
            .ok_or(NetworkKernelMutationError::UnsupportedPlan)?;
        self.in_namespace(target_namespace, bootstrap_namespace, worker, || {
            for pair in expectation.address_pairs() {
                self.replace_address(&veth.sandbox_name, pair.sandbox, pair.prefix_length)?;
            }
            Ok(())
        })?;
        self.in_namespace(host_namespace, bootstrap_namespace, worker, || {
            for pair in expectation.address_pairs() {
                self.replace_address(&veth.host_name, pair.host, pair.prefix_length)?;
            }
            Ok(())
        })
    }

    fn replace_routes(
        &self,
        expectation: &NetworkKernelExpectationV1,
        target_namespace: &NamespaceFd,
        bootstrap_namespace: &NamespaceFd,
        worker: &SingleThreadedProcess,
    ) -> Result<(), NetworkKernelMutationError> {
        let veth = expectation
            .veth()
            .ok_or(NetworkKernelMutationError::UnsupportedPlan)?;
        self.in_namespace(target_namespace, bootstrap_namespace, worker, || {
            for route in expectation.routes() {
                self.replace_route(&veth.sandbox_name, route.destination, route.gateway)?;
            }
            Ok(())
        })
    }

    fn replace_neighbors(
        &self,
        expectation: &NetworkKernelExpectationV1,
        target_namespace: &NamespaceFd,
        host_namespace: &NamespaceFd,
        bootstrap_namespace: &NamespaceFd,
        worker: &SingleThreadedProcess,
    ) -> Result<(), NetworkKernelMutationError> {
        let veth = expectation
            .veth()
            .ok_or(NetworkKernelMutationError::UnsupportedPlan)?;
        self.in_namespace(target_namespace, bootstrap_namespace, worker, || {
            for pair in expectation.address_pairs() {
                if matches!(pair.sandbox, ObservedIpAddressV1::Ipv6(_)) {
                    self.replace_ipv6_neighbor(&veth.sandbox_name, pair.host, veth.host_mac)?;
                }
            }
            Ok(())
        })?;
        self.in_namespace(host_namespace, bootstrap_namespace, worker, || {
            for pair in expectation.address_pairs() {
                if matches!(pair.host, ObservedIpAddressV1::Ipv6(_)) {
                    self.replace_ipv6_neighbor(&veth.host_name, pair.sandbox, veth.sandbox_mac)?;
                }
            }
            Ok(())
        })
    }

    fn remove_owned_network_objects(
        &self,
        expectation: &NetworkKernelExpectationV1,
        target_namespace: &NamespaceFd,
        host_namespace: &NamespaceFd,
        bootstrap_namespace: &NamespaceFd,
        worker: &SingleThreadedProcess,
    ) -> Result<(), NetworkKernelMutationError> {
        self.in_namespace(target_namespace, bootstrap_namespace, worker, || {
            self.run_nft_destroy_table()
        })?;
        let Some(veth) = expectation.veth() else {
            return Ok(());
        };
        self.in_namespace(host_namespace, bootstrap_namespace, worker, || {
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

    fn link_name_present(&self, expected_name: &str) -> Result<bool, NetworkKernelMutationError> {
        let arguments = [
            OsString::from("-j"),
            OsString::from("link"),
            OsString::from("show"),
        ];
        let output = self.ip.run(&arguments, MAXIMUM_LINK_INVENTORY_BYTES)?;
        let stdout = successful_helper_stdout(output)?;
        link_name_present_in_inventory(&stdout, expected_name)
    }

    fn in_namespace<T>(
        &self,
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
        &self,
        expectation: &NetworkKernelExpectationV1,
    ) -> Result<(), NetworkKernelMutationError> {
        for artifact in [
            &self.ip,
            &self.nft,
            &self.lease_gate_loader,
            &self.lease_gate_object,
        ] {
            artifact.validate_current()?;
        }
        self.enforcement_artifact.validate_current_executable()?;
        if self.enforcement_artifact.digest() != expectation.enforcement_artifact_digest()
            || expectation.lease_gate_artifact_digest().is_some() != expectation.veth().is_some()
            || expectation
                .lease_gate_artifact_digest()
                .is_some_and(|digest| digest != self.lease_gate_object.digest())
        {
            return Err(NetworkKernelMutationError::Artifact);
        }
        Ok(())
    }

    fn realize_veth(
        &self,
        expectation: &NetworkKernelExpectationV1,
        target_namespace: &NamespaceFd,
        host_namespace: &NamespaceFd,
        worker: &SingleThreadedProcess,
    ) -> Result<(), NetworkKernelMutationError> {
        let veth = expectation
            .veth()
            .ok_or(NetworkKernelMutationError::UnsupportedPlan)?;
        run_fixed_status(
            &self.ip,
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
        &self,
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
        &self,
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
        &self,
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
        &self,
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
        &self,
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
        &self,
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
        &self,
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
        &self,
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
            self.lease_gate_object.path().as_os_str().to_owned(),
        ];
        run_fixed_status(
            &self.lease_gate_loader,
            &arguments,
            None,
            &[target_namespace.as_fd()],
        )
    }

    fn run_nft_batch(&self, bytes: &[u8]) -> Result<(), NetworkKernelMutationError> {
        if bytes.is_empty() || bytes.len() > MAXIMUM_NFT_BATCH_BYTES || !bytes.ends_with(b"\n") {
            return Err(NetworkKernelMutationError::Nftables);
        }
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
        run_fixed_status(
            &self.nft,
            &["--json".into(), "--file".into(), "-".into()],
            Some(input.as_fd()),
            &[],
        )
    }

    fn run_nft_destroy_table(&self) -> Result<(), NetworkKernelMutationError> {
        run_fixed_status(&self.nft, &nftables_destroy_arguments(), None, &[])
    }

    fn run_ip(&self, arguments: &[&str]) -> Result<(), NetworkKernelMutationError> {
        let arguments = arguments.iter().map(OsString::from).collect::<Vec<_>>();
        self.run_ip_owned(&arguments)
    }

    fn run_ip_owned(&self, arguments: &[OsString]) -> Result<(), NetworkKernelMutationError> {
        run_fixed_status(&self.ip, arguments, None, &[])
    }

    fn run_lease_gate(&self, arguments: &[OsString]) -> Result<(), NetworkKernelMutationError> {
        run_fixed_status(&self.lease_gate_loader, arguments, None, &[])
    }
}

fn link_name_present_in_inventory(
    bytes: &[u8],
    expected_name: &str,
) -> Result<bool, NetworkKernelMutationError> {
    if !bytes.ends_with(b"\n") {
        return Err(NetworkKernelMutationError::Helper);
    }
    let inventory =
        serde_json::from_slice::<Value>(bytes).map_err(|_| NetworkKernelMutationError::Helper)?;
    let records = inventory
        .as_array()
        .ok_or(NetworkKernelMutationError::Helper)?;
    let mut names = BTreeSet::new();
    for record in records {
        let name = record
            .as_object()
            .and_then(|object| object.get("ifname"))
            .and_then(Value::as_str)
            .ok_or(NetworkKernelMutationError::Helper)?;
        if name.is_empty() || name.len() > 15 || name.as_bytes().contains(&0) || !names.insert(name)
        {
            return Err(NetworkKernelMutationError::Helper);
        }
    }
    Ok(names.contains(expected_name))
}

fn run_fixed_status(
    artifact: &PinnedArtifact,
    arguments: &[OsString],
    stdin: Option<BorrowedFd<'_>>,
    inherited: &[BorrowedFd<'_>],
) -> Result<(), NetworkKernelMutationError> {
    let argument_bytes = arguments
        .iter()
        .try_fold(0_usize, |total, argument| total.checked_add(argument.len()))
        .ok_or(NetworkKernelMutationError::Helper)?;
    if arguments.len() > MAXIMUM_ARGUMENTS || argument_bytes > MAXIMUM_ARGUMENT_BYTES {
        return Err(NetworkKernelMutationError::Helper);
    }
    artifact.validate_current()?;
    let outcome = run_fixed_process_with_descriptors(FixedProcessDescriptorRequest {
        process: FixedProcessRequest {
            executable: artifact.path(),
            arguments,
            timeout: HELPER_TIMEOUT,
            maximum_stdout_bytes: MAXIMUM_HELPER_OUTPUT_BYTES,
            maximum_stderr_bytes: MAXIMUM_HELPER_OUTPUT_BYTES,
        },
        stdin,
        inherited,
    })?;
    artifact.validate_current()?;
    match outcome {
        FixedProcessOutcome::Completed(output)
            if output.exit_code == Some(0) && output.signal.is_none() =>
        {
            Ok(())
        }
        FixedProcessOutcome::Completed(_)
        | FixedProcessOutcome::TimedOut
        | FixedProcessOutcome::OutputLimitExceeded => Err(NetworkKernelMutationError::Helper),
    }
}

fn encode_nftables_base(
    expectation: &NetworkKernelExpectationV1,
) -> Result<Vec<u8>, NetworkKernelMutationError> {
    let provenance = format!(
        "{TABLE_PROVENANCE_PREFIX}{}{TABLE_POLICY_SEPARATOR}{}",
        URL_SAFE_NO_PAD.encode(expectation.enforcement_artifact_digest().as_bytes()),
        URL_SAFE_NO_PAD.encode(expectation.policy().digest().as_bytes())
    );
    encode_nftables_commands(vec![
        json!({"create":{"table":{"family":TABLE_FAMILY,"name":TABLE_NAME,"comment":provenance}}}),
        base_chain("ingress", "input"),
        base_chain("egress", "output"),
    ])
}

fn encode_nftables_rules(
    expectation: &NetworkKernelExpectationV1,
) -> Result<Vec<u8>, NetworkKernelMutationError> {
    let mut commands = Vec::new();

    if let Some(veth) = expectation.veth() {
        let mut ipv4 = Vec::new();
        let mut ipv6 = Vec::new();
        for pair in expectation.address_pairs() {
            match pair.sandbox {
                ObservedIpAddressV1::Ipv4(_) => ipv4.push(pair.sandbox),
                ObservedIpAddressV1::Ipv6(_) => ipv6.push(pair.sandbox),
            }
        }
        for addresses in [ipv4, ipv6]
            .into_iter()
            .filter(|addresses| !addresses.is_empty())
        {
            commands.push(anti_spoof_rule(
                NetworkFlowDirectionV1::Ingress,
                &veth.sandbox_name,
                &addresses,
            ));
            commands.push(anti_spoof_rule(
                NetworkFlowDirectionV1::Egress,
                &veth.sandbox_name,
                &addresses,
            ));
        }
    }
    for endpoint in expectation.policy().endpoints() {
        for flow in endpoint.flows() {
            commands.push(flow_rule(
                encode_hex(endpoint.endpoint_id().as_bytes()),
                *flow,
            )?);
        }
    }

    encode_nftables_commands(commands)
}

fn nftables_destroy_arguments() -> [OsString; 4] {
    // `destroy` is the idempotent form: it removes the exact table when
    // present and succeeds when a prior attempt already removed it.
    [
        "destroy".into(),
        "table".into(),
        TABLE_FAMILY.into(),
        TABLE_NAME.into(),
    ]
}

fn encode_nftables_commands(commands: Vec<Value>) -> Result<Vec<u8>, NetworkKernelMutationError> {
    let mut bytes = serde_json::to_vec(&json!({"nftables":commands}))
        .map_err(|_| NetworkKernelMutationError::Nftables)?;
    bytes.push(b'\n');
    if bytes.len() > MAXIMUM_NFT_BATCH_BYTES {
        return Err(NetworkKernelMutationError::Nftables);
    }
    Ok(bytes)
}

fn base_chain(name: &str, hook: &str) -> Value {
    json!({"create":{"chain":{
        "family":TABLE_FAMILY,"table":TABLE_NAME,"name":name,
        "type":"filter","hook":hook,"prio":0,"policy":"drop"
    }}})
}

fn anti_spoof_rule(
    direction: NetworkFlowDirectionV1,
    interface: &str,
    addresses: &[ObservedIpAddressV1],
) -> Value {
    let (chain, interface_key, address_field) = match direction {
        NetworkFlowDirectionV1::Ingress => ("ingress", "iif", "daddr"),
        NetworkFlowDirectionV1::Egress => ("egress", "oif", "saddr"),
    };
    let protocol = match addresses[0] {
        ObservedIpAddressV1::Ipv4(_) => "ip",
        ObservedIpAddressV1::Ipv6(_) => "ip6",
    };
    let values = addresses
        .iter()
        .copied()
        .map(format_address)
        .map(Value::String)
        .collect::<Vec<_>>();
    let address_value = match values.as_slice() {
        [one] => one.clone(),
        _ => json!({"set":values}),
    };
    json!({"add":{"rule":{
        "family":TABLE_FAMILY,"table":TABLE_NAME,"chain":chain,
        "comment":ANTI_SPOOF_COMMENT,
        "expr":[
            {"match":{"op":"==","left":{"meta":{"key":interface_key}},"right":interface}},
            {"match":{"op":"!=","left":{"payload":{"protocol":protocol,"field":address_field}},"right":address_value}},
            {"drop":null}
        ]
    }}})
}

fn flow_rule(
    endpoint: String,
    flow: NetworkFlowPolicyV1,
) -> Result<Value, NetworkKernelMutationError> {
    let (chain, address_field) = match flow.direction() {
        NetworkFlowDirectionV1::Ingress => ("ingress", "saddr"),
        NetworkFlowDirectionV1::Egress => ("egress", "daddr"),
    };
    let address_protocol = match flow.remote_prefix() {
        NetworkIpPrefixV1::Ipv4 { .. } => "ip",
        NetworkIpPrefixV1::Ipv6 { .. } => "ip6",
    };
    let transport = match flow.protocol() {
        NetworkTransportProtocolV1::Tcp => transport_match("tcp", flow)?,
        NetworkTransportProtocolV1::Udp => transport_match("udp", flow)?,
        NetworkTransportProtocolV1::IcmpV4 => {
            json!({"match":{"op":"==","left":{"meta":{"key":"l4proto"}},"right":1}})
        }
        NetworkTransportProtocolV1::IcmpV6 => {
            json!({"match":{"op":"==","left":{"meta":{"key":"l4proto"}},"right":58}})
        }
    };
    Ok(json!({"add":{"rule":{
        "family":TABLE_FAMILY,"table":TABLE_NAME,"chain":chain,
        "comment":format!("{FLOW_COMMENT_PREFIX}{endpoint}"),
        "expr":[
            {"match":{"op":"==","left":{"payload":{"protocol":address_protocol,"field":address_field}},"right":prefix_value(flow.remote_prefix())}},
            transport,
            {"accept":null}
        ]
    }}}))
}

fn transport_match(
    protocol: &str,
    flow: NetworkFlowPolicyV1,
) -> Result<Value, NetworkKernelMutationError> {
    let ports = flow
        .ports()
        .ok_or(NetworkKernelMutationError::UnsupportedPlan)?;
    let right = if ports.first() == ports.last() {
        json!(ports.first())
    } else {
        json!({"range":[ports.first(),ports.last()]})
    };
    Ok(json!({"match":{
        "op":"==",
        "left":{"payload":{"protocol":protocol,"field":"dport"}},
        "right":right
    }}))
}

fn prefix_value(prefix: NetworkIpPrefixV1) -> Value {
    match prefix {
        NetworkIpPrefixV1::Ipv4 {
            network,
            prefix_length,
        } => json!({"prefix":{"addr":Ipv4Addr::from(network).to_string(),"len":prefix_length}}),
        NetworkIpPrefixV1::Ipv6 {
            network,
            prefix_length,
        } => json!({"prefix":{"addr":Ipv6Addr::from(network).to_string(),"len":prefix_length}}),
    }
}

fn format_address(address: ObservedIpAddressV1) -> String {
    match address {
        ObservedIpAddressV1::Ipv4(octets) => Ipv4Addr::from(octets).to_string(),
        ObservedIpAddressV1::Ipv6(octets) => Ipv6Addr::from(octets).to_string(),
    }
}

const fn address_family_flag(address: ObservedIpAddressV1) -> &'static str {
    match address {
        ObservedIpAddressV1::Ipv4(_) => "-4",
        ObservedIpAddressV1::Ipv6(_) => "-6",
    }
}

fn format_mac(mac: [u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
}

fn inherited_fd_path(fd: i32) -> OsString {
    format!("/proc/self/fd/{fd}").into()
}

fn encode_hex(bytes: &[u8]) -> String {
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(encoded, "{byte:02x}");
    }
    encoded
}

fn linux_syscall(
    operation: &'static str,
) -> impl FnOnce(rustix::io::Errno) -> NetworkKernelMutationError {
    move |source| {
        NetworkKernelMutationError::Linux(aos_sandbox_linux::Error::Syscall {
            operation,
            source: std::io::Error::from_raw_os_error(source.raw_os_error()),
        })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use aos_sandbox_core::{
        AssignmentEpoch, BrokerAssignment, DesiredGeneration, IncarnationId, NetworkEndpointId,
        SandboxId,
    };

    use super::*;
    use crate::kernel_observation::{ExpectedAddressPairV1, ExpectedVethV1};
    use crate::policy::{NetworkEndpointPolicyV1, NetworkPolicyProgramV1, NetworkPortRangeV1};

    fn expectation() -> NetworkKernelExpectationV1 {
        let assignment = BrokerAssignment::new(
            SandboxId::from_bytes([0x11; 16]),
            IncarnationId::from_bytes([0x22; 16]),
            AssignmentEpoch::new(41),
            DesiredGeneration::new(7),
            ObjectDigest::from_bytes([0x33; 32]),
        )
        .unwrap();
        let flow = NetworkFlowPolicyV1::new(
            NetworkFlowDirectionV1::Ingress,
            NetworkTransportProtocolV1::Tcp,
            NetworkIpPrefixV1::ipv4([198, 51, 100, 0], 24).unwrap(),
            Some(NetworkPortRangeV1::new(443, 443).unwrap()),
        )
        .unwrap();
        let endpoint =
            NetworkEndpointPolicyV1::new(NetworkEndpointId::from_bytes([0x44; 16]), vec![flow])
                .unwrap();
        let policy = NetworkPolicyProgramV1::new(
            NetworkKind::Published,
            ObjectDigest::from_bytes([0x55; 32]),
            Some(ObjectDigest::from_bytes([0x66; 32])),
            vec![endpoint],
        )
        .unwrap();

        NetworkKernelExpectationV1::new(
            assignment,
            [0x77; 32],
            9,
            NetworkKind::Published,
            ObjectDigest::from_bytes([0x88; 32]),
            ObjectDigest::from_bytes([0x55; 32]),
            Some(ObjectDigest::from_bytes([0x66; 32])),
            Some(ExpectedVethV1 {
                mtu: 1_500,
                host_name: "aoh000000000009".to_owned(),
                sandbox_name: "aog000000000009".to_owned(),
                host_mac: [0x02, 0xaa, 0xbb, 0, 0, 1],
                sandbox_mac: [0x02, 0xaa, 0xbb, 0, 0, 2],
            }),
            vec![ExpectedAddressPairV1 {
                host: ObservedIpAddressV1::Ipv4([10, 80, 0, 0]),
                sandbox: ObservedIpAddressV1::Ipv4([10, 80, 0, 1]),
                prefix_length: 31,
            }],
            Vec::new(),
            policy,
        )
    }

    #[test]
    fn first_batch_exclusively_creates_only_default_drop_objects() {
        let document: Value =
            serde_json::from_slice(&encode_nftables_base(&expectation()).unwrap()).unwrap();
        let commands = document["nftables"].as_array().unwrap();

        assert_eq!(commands.len(), 3);
        assert!(
            commands
                .iter()
                .all(|command| command.get("create").is_some())
        );
        assert!(commands.iter().all(|command| command.get("add").is_none()));
        assert_eq!(
            commands[0]["create"]["table"]["name"],
            Value::String(TABLE_NAME.to_owned())
        );
        for command in &commands[1..] {
            assert_eq!(command["create"]["chain"]["policy"], "drop");
        }
    }

    #[test]
    fn second_batch_contains_only_plan_derived_rules() {
        let document: Value =
            serde_json::from_slice(&encode_nftables_rules(&expectation()).unwrap()).unwrap();
        let commands = document["nftables"].as_array().unwrap();

        assert_eq!(commands.len(), 3);
        assert!(commands.iter().all(|command| command.get("add").is_some()));
        assert!(
            commands
                .iter()
                .all(|command| command.get("create").is_none())
        );
        assert_eq!(commands[0]["add"]["rule"]["comment"], ANTI_SPOOF_COMMENT);
        assert_eq!(commands[1]["add"]["rule"]["comment"], ANTI_SPOOF_COMMENT);
        assert_eq!(
            commands[2]["add"]["rule"]["comment"],
            format!("{FLOW_COMMENT_PREFIX}{}", "44".repeat(16))
        );
    }

    #[test]
    fn destroy_command_is_an_exact_idempotent_table_removal() {
        assert_eq!(
            nftables_destroy_arguments(),
            ["destroy", "table", TABLE_FAMILY, TABLE_NAME].map(OsString::from)
        );
    }

    #[test]
    fn complete_link_inventory_proves_presence_or_absence_without_filtering() {
        let inventory = br#"[{"ifname":"lo"},{"ifname":"aoh000000000009"}]
"#;

        assert_eq!(
            link_name_present_in_inventory(inventory, "aoh000000000009").unwrap(),
            true
        );
        assert_eq!(
            link_name_present_in_inventory(inventory, "aoh000000000010").unwrap(),
            false
        );
        assert!(
            link_name_present_in_inventory(
                br#"[{"ifname":"lo"},{"ifname":"lo"}]
"#,
                "lo"
            )
            .is_err()
        );
        assert!(
            link_name_present_in_inventory(
                br#"[{"ifindex":1}]
"#,
                "lo"
            )
            .is_err()
        );
    }

    #[test]
    fn formatting_helpers_are_canonical_and_descriptor_only() {
        assert_eq!(
            format_address(ObservedIpAddressV1::Ipv4([192, 0, 2, 1])),
            "192.0.2.1"
        );
        assert_eq!(
            format_address(ObservedIpAddressV1::Ipv6([
                0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
            ])),
            "2001:db8::1"
        );
        assert_eq!(format_mac([2, 0xaa, 0xbb, 0, 1, 2]), "02:aa:bb:00:01:02");
        assert_eq!(inherited_fd_path(71), "/proc/self/fd/71");
    }
}
