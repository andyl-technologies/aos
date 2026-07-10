//! Plugin-side inertness assertions for sim-off QEMU launches.
//!
//! RFC-0010 PLUG-49 splits `gate:qemu-inert` across the host launch boundary
//! and the plugin boundary. The full real-QEMU corpus proves patched QEMU is
//! behaviorally identical to upstream with simulation disabled. This module
//! records the plugin half: if simulation mode is off, the plugin must have no
//! launch argument, no install call, no control or shared-memory setup, no
//! callback registrations, and no calls into patched QEMU capabilities.

use thiserror::Error;

use crate::OWNED_DEVICE_CALLBACK_KINDS;

/// QEMU simulation activation state as seen by plugin inertness checks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PluginSimulationMode {
    /// Simulation mode is disabled and the plugin must be absent.
    Off,
    /// Simulation mode is enabled and plugin registration may have effects.
    On,
}

/// Counts calls the plugin made into patched QEMU capabilities.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PluginPatchCapabilityCalls {
    /// Requests for QEMU plugin ownership of virtual time.
    pub time_control_requests: u32,
    /// Queries of QEMU plugin virtual-time ownership state.
    pub time_control_status_queries: u32,
    /// Updates to QEMU's virtual clock.
    pub virtual_clock_updates: u32,
    /// Reads through the exact virtual-clock deadline capability.
    pub exact_deadline_reads: u32,
    /// Queued virtual-time advances through the idle advance capability.
    pub direct_virtual_time_advances: u32,
    /// Commanded vCPU-switch or interrupt preemption injections.
    pub preemption_injections: u32,
    /// Per-vCPU register-file reads through the fingerprint introspection API.
    pub vcpu_register_reads: u32,
    /// Round-robin cursor reads through the fingerprint introspection API.
    pub rr_cursor_reads: u32,
    /// Lossless guest network receive capacity queries.
    pub network_receive_capacity_queries: u32,
    /// Lossless guest network receive queue operations.
    pub network_receive_queues: u32,
    /// Lossless guest network receive flush operations.
    pub network_receive_flushes: u32,
    /// TCG-exec coverage callback registrations.
    pub coverage_callback_registrations: u32,
    /// TCG-exec coverage callback invocations.
    pub coverage_exec_callbacks: u32,
    /// White-box guest doorbell trap registrations.
    pub whitebox_trap_registrations: u32,
    /// Guest-memory reads through the QEMU plugin API.
    pub guest_memory_reads: u32,
    /// Guest-memory writes through the QEMU plugin API.
    pub guest_memory_writes: u32,
}

impl PluginPatchCapabilityCalls {
    /// Returns the zero-call patch capability observation.
    #[must_use]
    pub const fn none() -> Self {
        Self {
            time_control_requests: 0,
            time_control_status_queries: 0,
            virtual_clock_updates: 0,
            exact_deadline_reads: 0,
            direct_virtual_time_advances: 0,
            preemption_injections: 0,
            vcpu_register_reads: 0,
            rr_cursor_reads: 0,
            network_receive_capacity_queries: 0,
            network_receive_queues: 0,
            network_receive_flushes: 0,
            coverage_callback_registrations: 0,
            coverage_exec_callbacks: 0,
            whitebox_trap_registrations: 0,
            guest_memory_reads: 0,
            guest_memory_writes: 0,
        }
    }

    /// Returns the total number of patched-capability calls.
    #[must_use]
    pub const fn total(self) -> usize {
        self.time_control_requests as usize
            + self.time_control_status_queries as usize
            + self.virtual_clock_updates as usize
            + self.exact_deadline_reads as usize
            + self.direct_virtual_time_advances as usize
            + self.preemption_injections as usize
            + self.vcpu_register_reads as usize
            + self.rr_cursor_reads as usize
            + self.network_receive_capacity_queries as usize
            + self.network_receive_queues as usize
            + self.network_receive_flushes as usize
            + self.coverage_callback_registrations as usize
            + self.coverage_exec_callbacks as usize
            + self.whitebox_trap_registrations as usize
            + self.guest_memory_reads as usize
            + self.guest_memory_writes as usize
    }
}

/// Observed plugin-side load and effect state for one QEMU launch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PluginInertnessObservation {
    /// Simulation activation state for this launch.
    pub simulation_mode: PluginSimulationMode,
    /// Whether the QEMU argument vector included `-plugin`.
    pub plugin_argument_present: bool,
    /// Whether QEMU called the plugin install entry point.
    pub install_entrypoint_called: bool,
    /// Whether a host-to-plugin control socket was opened.
    pub control_socket_opened: bool,
    /// Whether the plugin mapped the shared-memory region.
    pub shared_memory_mapped: bool,
    /// Number of plugin-owned callback families registered with QEMU.
    pub registered_callback_count: usize,
    /// Calls made into patched QEMU capabilities.
    pub patch_capability_calls: PluginPatchCapabilityCalls,
}

impl PluginInertnessObservation {
    /// Builds the required sim-off observation.
    #[must_use]
    pub const fn sim_off() -> Self {
        Self {
            simulation_mode: PluginSimulationMode::Off,
            plugin_argument_present: false,
            install_entrypoint_called: false,
            control_socket_opened: false,
            shared_memory_mapped: false,
            registered_callback_count: 0,
            patch_capability_calls: PluginPatchCapabilityCalls::none(),
        }
    }
}

/// Validated plugin-side inertness report.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PluginInertnessReport {
    /// Simulation activation state that was checked.
    pub simulation_mode: PluginSimulationMode,
    /// Whether the QEMU argument vector included `-plugin`.
    pub plugin_argument_present: bool,
    /// Whether QEMU called the plugin install entry point.
    pub install_entrypoint_called: bool,
    /// Whether a host-to-plugin control socket was opened.
    pub control_socket_opened: bool,
    /// Whether the plugin mapped the shared-memory region.
    pub shared_memory_mapped: bool,
    /// Number of plugin-owned callback families registered with QEMU.
    pub registered_callback_count: usize,
    /// Calls made into patched QEMU capabilities.
    pub patch_capability_calls: PluginPatchCapabilityCalls,
    /// Number of callback families owned by this plugin build.
    pub owned_callback_kinds_checked: usize,
}

impl PluginInertnessReport {
    /// Returns the total plugin-side effect count represented by this report.
    #[must_use]
    pub const fn effect_count(self) -> usize {
        self.plugin_argument_present as usize
            + self.install_entrypoint_called as usize
            + self.control_socket_opened as usize
            + self.shared_memory_mapped as usize
            + self.registered_callback_count
            + self.patch_capability_calls.total()
    }
}

/// Error returned when sim-off plugin state is not inert.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum PluginInertnessError {
    /// A sim-off launch included a plugin argument.
    #[error("sim-off launch passed a QEMU -plugin argument")]
    PluginArgumentWhenSimulationOff,
    /// QEMU called the plugin install entry point while simulation was off.
    #[error("sim-off launch called the QEMU plugin install entry point")]
    InstallEntrypointCalledWhenSimulationOff,
    /// A sim-off launch opened the plugin control socket.
    #[error("sim-off launch opened a host-to-plugin control socket")]
    ControlSocketOpenedWhenSimulationOff,
    /// A sim-off launch mapped the plugin shared-memory region.
    #[error("sim-off launch mapped the plugin shared-memory region")]
    SharedMemoryMappedWhenSimulationOff,
    /// A sim-off launch registered plugin callbacks with QEMU.
    #[error("sim-off launch registered {count} plugin callback families")]
    CallbacksRegisteredWhenSimulationOff {
        /// Number of callback families registered while simulation was off.
        count: usize,
    },
    /// A sim-off launch invoked patched QEMU capabilities.
    #[error("sim-off launch invoked patched QEMU capabilities")]
    PatchCapabilitiesInvokedWhenSimulationOff {
        /// Per-capability call counts observed while simulation was off.
        calls: PluginPatchCapabilityCalls,
    },
}

/// Validates plugin-side inertness for one launch observation.
///
/// # Errors
///
/// Returns [`PluginInertnessError`] when simulation mode is off and any plugin
/// load, setup, callback registration, or patched-capability call is observed.
pub fn assert_plugin_inert(
    observation: PluginInertnessObservation,
) -> Result<PluginInertnessReport, PluginInertnessError> {
    if matches!(observation.simulation_mode, PluginSimulationMode::Off) {
        validate_sim_off(observation)?;
    }

    Ok(report_from(observation))
}

fn validate_sim_off(observation: PluginInertnessObservation) -> Result<(), PluginInertnessError> {
    if observation.plugin_argument_present {
        return Err(PluginInertnessError::PluginArgumentWhenSimulationOff);
    }
    if observation.install_entrypoint_called {
        return Err(PluginInertnessError::InstallEntrypointCalledWhenSimulationOff);
    }
    if observation.control_socket_opened {
        return Err(PluginInertnessError::ControlSocketOpenedWhenSimulationOff);
    }
    if observation.shared_memory_mapped {
        return Err(PluginInertnessError::SharedMemoryMappedWhenSimulationOff);
    }
    if observation.registered_callback_count != 0 {
        return Err(PluginInertnessError::CallbacksRegisteredWhenSimulationOff {
            count: observation.registered_callback_count,
        });
    }
    if observation.patch_capability_calls.total() != 0 {
        return Err(
            PluginInertnessError::PatchCapabilitiesInvokedWhenSimulationOff {
                calls: observation.patch_capability_calls,
            },
        );
    }
    Ok(())
}

fn report_from(observation: PluginInertnessObservation) -> PluginInertnessReport {
    PluginInertnessReport {
        simulation_mode: observation.simulation_mode,
        plugin_argument_present: observation.plugin_argument_present,
        install_entrypoint_called: observation.install_entrypoint_called,
        control_socket_opened: observation.control_socket_opened,
        shared_memory_mapped: observation.shared_memory_mapped,
        registered_callback_count: observation.registered_callback_count,
        patch_capability_calls: observation.patch_capability_calls,
        owned_callback_kinds_checked: OWNED_DEVICE_CALLBACK_KINDS.len(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_not_inert(observation: PluginInertnessObservation) -> PluginInertnessError {
        match assert_plugin_inert(observation) {
            Ok(report) => panic!("plugin inertness assertion should fail, got {report:?}"),
            Err(error) => error,
        }
    }

    #[test]
    fn plugin_sim_off_observation_has_no_load_or_effects() {
        let report = match assert_plugin_inert(PluginInertnessObservation::sim_off()) {
            Ok(report) => report,
            Err(error) => panic!("sim-off plugin observation should be inert: {error}"),
        };

        assert_eq!(report.simulation_mode, PluginSimulationMode::Off);
        assert!(!report.plugin_argument_present);
        assert!(!report.install_entrypoint_called);
        assert!(!report.control_socket_opened);
        assert!(!report.shared_memory_mapped);
        assert_eq!(report.registered_callback_count, 0);
        assert_eq!(
            report.patch_capability_calls,
            PluginPatchCapabilityCalls::none()
        );
        assert_eq!(
            report.owned_callback_kinds_checked,
            OWNED_DEVICE_CALLBACK_KINDS.len()
        );
        assert_eq!(report.effect_count(), 0);
    }

    #[test]
    fn plugin_sim_off_rejects_every_load_or_effect_vector() {
        for (observation, expected_error) in [
            (
                PluginInertnessObservation {
                    plugin_argument_present: true,
                    ..PluginInertnessObservation::sim_off()
                },
                PluginInertnessError::PluginArgumentWhenSimulationOff,
            ),
            (
                PluginInertnessObservation {
                    install_entrypoint_called: true,
                    ..PluginInertnessObservation::sim_off()
                },
                PluginInertnessError::InstallEntrypointCalledWhenSimulationOff,
            ),
            (
                PluginInertnessObservation {
                    control_socket_opened: true,
                    ..PluginInertnessObservation::sim_off()
                },
                PluginInertnessError::ControlSocketOpenedWhenSimulationOff,
            ),
            (
                PluginInertnessObservation {
                    shared_memory_mapped: true,
                    ..PluginInertnessObservation::sim_off()
                },
                PluginInertnessError::SharedMemoryMappedWhenSimulationOff,
            ),
            (
                PluginInertnessObservation {
                    registered_callback_count: OWNED_DEVICE_CALLBACK_KINDS.len(),
                    ..PluginInertnessObservation::sim_off()
                },
                PluginInertnessError::CallbacksRegisteredWhenSimulationOff {
                    count: OWNED_DEVICE_CALLBACK_KINDS.len(),
                },
            ),
        ] {
            assert_eq!(assert_not_inert(observation), expected_error);
        }

        for patch_calls in [
            PluginPatchCapabilityCalls {
                time_control_requests: 1,
                ..PluginPatchCapabilityCalls::none()
            },
            PluginPatchCapabilityCalls {
                time_control_status_queries: 1,
                ..PluginPatchCapabilityCalls::none()
            },
            PluginPatchCapabilityCalls {
                virtual_clock_updates: 1,
                ..PluginPatchCapabilityCalls::none()
            },
            PluginPatchCapabilityCalls {
                exact_deadline_reads: 1,
                ..PluginPatchCapabilityCalls::none()
            },
            PluginPatchCapabilityCalls {
                direct_virtual_time_advances: 1,
                ..PluginPatchCapabilityCalls::none()
            },
            PluginPatchCapabilityCalls {
                preemption_injections: 1,
                ..PluginPatchCapabilityCalls::none()
            },
            PluginPatchCapabilityCalls {
                vcpu_register_reads: 1,
                ..PluginPatchCapabilityCalls::none()
            },
            PluginPatchCapabilityCalls {
                rr_cursor_reads: 1,
                ..PluginPatchCapabilityCalls::none()
            },
            PluginPatchCapabilityCalls {
                network_receive_capacity_queries: 1,
                ..PluginPatchCapabilityCalls::none()
            },
            PluginPatchCapabilityCalls {
                network_receive_queues: 1,
                ..PluginPatchCapabilityCalls::none()
            },
            PluginPatchCapabilityCalls {
                network_receive_flushes: 1,
                ..PluginPatchCapabilityCalls::none()
            },
            PluginPatchCapabilityCalls {
                coverage_callback_registrations: 1,
                ..PluginPatchCapabilityCalls::none()
            },
            PluginPatchCapabilityCalls {
                coverage_exec_callbacks: 1,
                ..PluginPatchCapabilityCalls::none()
            },
            PluginPatchCapabilityCalls {
                whitebox_trap_registrations: 1,
                ..PluginPatchCapabilityCalls::none()
            },
            PluginPatchCapabilityCalls {
                guest_memory_reads: 1,
                ..PluginPatchCapabilityCalls::none()
            },
            PluginPatchCapabilityCalls {
                guest_memory_writes: 1,
                ..PluginPatchCapabilityCalls::none()
            },
        ] {
            assert_eq!(
                assert_not_inert(PluginInertnessObservation {
                    patch_capability_calls: patch_calls,
                    ..PluginInertnessObservation::sim_off()
                }),
                PluginInertnessError::PatchCapabilitiesInvokedWhenSimulationOff {
                    calls: patch_calls,
                },
            );
        }
    }

    #[test]
    fn plugin_sim_on_observation_records_loaded_plugin_effects() {
        let patch_calls = PluginPatchCapabilityCalls {
            time_control_requests: 1,
            time_control_status_queries: 1,
            virtual_clock_updates: 1,
            exact_deadline_reads: 1,
            direct_virtual_time_advances: 1,
            preemption_injections: 1,
            vcpu_register_reads: 1,
            rr_cursor_reads: 1,
            network_receive_capacity_queries: 1,
            network_receive_queues: 1,
            network_receive_flushes: 1,
            coverage_callback_registrations: 1,
            coverage_exec_callbacks: 1,
            whitebox_trap_registrations: 1,
            guest_memory_reads: 1,
            guest_memory_writes: 1,
        };
        let report = match assert_plugin_inert(PluginInertnessObservation {
            simulation_mode: PluginSimulationMode::On,
            plugin_argument_present: true,
            install_entrypoint_called: true,
            control_socket_opened: true,
            shared_memory_mapped: true,
            registered_callback_count: OWNED_DEVICE_CALLBACK_KINDS.len(),
            patch_capability_calls: patch_calls,
        }) {
            Ok(report) => report,
            Err(error) => panic!("sim-on plugin effects should be observable: {error}"),
        };

        assert_eq!(report.simulation_mode, PluginSimulationMode::On);
        assert_eq!(
            report.registered_callback_count,
            OWNED_DEVICE_CALLBACK_KINDS.len()
        );
        assert_eq!(report.patch_capability_calls, patch_calls);
        assert_eq!(
            report.effect_count(),
            4 + OWNED_DEVICE_CALLBACK_KINDS.len() + patch_calls.total()
        );
    }
}
