//! Names the existing deployment and administrative-pin journal DATA keys.
//!
//! These byte strings are comparison and encoding DATA. They are not a closed
//! Root-key grammar, protected provenance, a currentness proof or permission to
//! mutate a journal. Actual native role owners retain their existing gates.

/// Names the protected deployment-head record in the DesiredState namespace.
pub const HEAD_KEY: &[u8] = b"\0aos-policy-deployment-head-v1\0";

/// Names the saved deployment signer-pin pair in DesiredState.
pub const SIGNER_PINS_KEY: &[u8] = b"\0aos-policy-signer-pins-v1\0";

/// Names the administrative Controller hold public pin in DesiredState.
pub const CONTROLLER_HOLD_PIN_KEY: &[u8] = b"\0aos-policy-controller-hold-pin-v1\0";

/// Names the administrative Source hold public pin in DesiredState.
pub const SOURCE_HOLD_PIN_KEY: &[u8] = b"\0aos-policy-source-hold-pin-v1\0";

/// Names the canonical V2 signed project head in DesiredState.
pub const PROJECT_HEAD_KEY_V2: &[u8] = b"\0aos-policy-project-head-v2\0";

/// Names the canonical V2 signed project input in DesiredState.
pub const PROJECT_INPUT_KEY_V2: &[u8] = b"\0aos-policy-project-input-v2\0";

/// Names the independently provisioned Cache readback public pin.
pub const CACHE_PIN_KEY: &[u8] = b"\0aos-policy-cache-readback-pin-v1\0";

/// Names the historical V1 project head rejected by the original V2 stage.
pub const PROJECT_HEAD_KEY: &[u8] = b"\0aos-policy-project-head-v1\0";

/// Names the historical V1 project input rejected by the original V2 stage.
pub const PROJECT_INPUT_KEY: &[u8] = b"\0aos-policy-project-input-v1\0";
/// Names the fixed protected compiler directory without granting an opener.
pub const PROTECTED_POLICY_ROOT: &str = "/var/lib/aos/sandbox/policy-compiler";

/// Names the compiler-state journal in the fixed Policy directory.
pub const POLICY_STATE_JOURNAL: &str = "state.journal";

/// Names the authority journal in the fixed Policy directory.
pub const POLICY_AUTHORITY_JOURNAL: &str = "authority.journal";

/// Names the historical V1 binding family, which cannot issue publication authority.
pub const POLICY_BINDING_KEY_PREFIX: &[u8] = b"\0aos-policy-compiler-binding-v1\0";

/// Bounds retained legacy and V2 authority binding rows before replay acceptance.
pub const MAXIMUM_POLICY_BINDINGS: usize = 4_096;

/// Returns the ordinary compiler-state replay limits as comparison DATA.
#[must_use]
pub fn policy_state_journal_limits()
    -> aos_sandbox_protocol::domain_ledger::transaction::JournalLimits
{
    Default::default()
}
