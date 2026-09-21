//! Default-enabled, independently configurable OCI container capabilities.
//!
//! Runtime shells construct one [`ContainerRollout`] from their native flags or
//! Worker variables and attach it to the shared service. The service remains
//! the enforcement point, so neither a direct Connect request nor a routed
//! Distribution request can bypass a disabled capability.

/// Independently deployable OCI container capabilities.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ContainerRollout {
    /// Allows Distribution discovery, token grants, and repository reads.
    pub pull: bool,
    /// Allows Distribution discovery, token grants, and repository writes.
    pub push: bool,
    /// Allows verified AOS container publication transactions.
    pub verified_publication: bool,
    /// Allows reviewed container repository, tag, and retention mutations.
    pub administration: bool,
    /// Allows reviewed garbage-collection planning and execution.
    pub garbage_collection: bool,
}

impl Default for ContainerRollout {
    fn default() -> Self {
        Self::all_enabled()
    }
}

impl ContainerRollout {
    /// Returns a configuration with every container capability enabled.
    ///
    /// This is also the default for native and Worker deployments.
    #[must_use]
    pub const fn all_enabled() -> Self {
        Self {
            pull: true,
            push: true,
            verified_publication: true,
            administration: true,
            garbage_collection: true,
        }
    }

    /// Returns a configuration with every container capability explicitly disabled.
    #[must_use]
    pub const fn all_disabled() -> Self {
        Self {
            pull: false,
            push: false,
            verified_publication: false,
            administration: false,
            garbage_collection: false,
        }
    }

    /// Returns whether Distribution discovery has at least one enabled use.
    #[must_use]
    pub const fn distribution_enabled(self) -> bool {
        self.pull || self.push
    }

    /// Returns whether the named Distribution repository action is enabled.
    #[must_use]
    pub fn distribution_action_enabled(self, action: &str) -> bool {
        match action {
            "pull" => self.pull,
            "push" => self.push,
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::ContainerRollout;

    #[test]
    fn defaults_enable_containers_and_explicit_opt_outs_remain_independent() {
        assert_eq!(ContainerRollout::default(), ContainerRollout::all_enabled());

        let disabled = ContainerRollout::all_disabled();
        assert!(!disabled.distribution_enabled());
        assert!(!disabled.distribution_action_enabled("pull"));
        assert!(!disabled.distribution_action_enabled("push"));

        let pull_only = ContainerRollout {
            pull: true,
            ..ContainerRollout::all_disabled()
        };
        assert!(pull_only.distribution_enabled());
        assert!(pull_only.distribution_action_enabled("pull"));
        assert!(!pull_only.distribution_action_enabled("push"));
    }

    #[test]
    fn all_flag_combinations_preserve_independent_capabilities() {
        for bits in 0_u8..32 {
            let rollout = ContainerRollout {
                pull: bits & 1 != 0,
                push: bits & 2 != 0,
                verified_publication: bits & 4 != 0,
                administration: bits & 8 != 0,
                garbage_collection: bits & 16 != 0,
            };
            assert_eq!(rollout.distribution_enabled(), rollout.pull || rollout.push);
            assert_eq!(rollout.distribution_action_enabled("pull"), rollout.pull);
            assert_eq!(rollout.distribution_action_enabled("push"), rollout.push);
            assert!(!rollout.distribution_action_enabled("delete"));
        }
    }
}
