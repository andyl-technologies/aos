//! Read-only scalar CPU observations at authenticated paused SIM boundaries.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::{QmpCommandKind, QmpError};

/// Command for a paused CPU's architectural PC and absolute instruction count.
pub const QMP_QUERY_PAUSED_CPU_COMMAND: &str = "query-crucible-paused-cpu";
/// Current scalar observation encoding.
pub const QMP_PAUSED_CPU_SCHEMA_VERSION: u32 = 1;

/// Immutable CPU scalars observed without guest memory access or execution.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct QmpPausedCpu {
    /// Encoding version authenticated by the decoder.
    pub schema_version: u32,
    /// Paused CPU observation scope, always one.
    pub scope: u32,
    /// Native admitted VM-stop generation.
    pub generation: u64,
    /// Realized CPU index.
    pub vcpu_index: u32,
    /// Architectural program counter, independent of host addresses.
    pub pc: u64,
    /// Raw retired instructions in this machine incarnation.
    pub absolute_icount: u64,
}

pub(super) fn parse_paused_cpu(
    value: &Value,
    vcpu: u32,
    generation: Option<u64>,
) -> Result<QmpPausedCpu, QmpError> {
    let invalid = || QmpError::UnexpectedResponse {
        command: QmpCommandKind::QueryPausedCpu,
        response: value.to_string(),
    };
    let observation: QmpPausedCpu = serde_json::from_value(value.clone()).map_err(|_| invalid())?;
    if observation.schema_version != QMP_PAUSED_CPU_SCHEMA_VERSION
        || observation.scope != 1
        || observation.generation == 0
        || observation.generation == u64::MAX
        || observation.vcpu_index != vcpu
        || generation.is_some_and(|expected| observation.generation != expected)
        || observation.absolute_icount > i64::MAX as u64
    {
        return Err(invalid());
    }
    Ok(observation)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn scalar_observation_authenticates_scope_cpu_and_generation() -> Result<(), QmpError> {
        let value = json!({"schema-version":1,"scope":1,"generation":17,"vcpu-index":0,"pc":1048592,"absolute-icount":123456});
        let observed = parse_paused_cpu(&value, 0, Some(17))?;
        assert_eq!(observed.pc, 1048592);
        assert_eq!(observed.absolute_icount, 123456);
        assert!(parse_paused_cpu(&value, 1, Some(17)).is_err());
        assert!(parse_paused_cpu(&value, 0, Some(16)).is_err());
        for (field, replacement) in [
            ("schema-version", json!(2)),
            ("scope", json!(0)),
            ("generation", json!(0)),
            ("absolute-icount", json!(u64::MAX)),
        ] {
            let mut changed = value.clone();
            changed[field] = replacement;
            assert!(parse_paused_cpu(&changed, 0, None).is_err());
        }
        let mut extended = value;
        extended["native-pointer"] = json!(0);
        assert!(parse_paused_cpu(&extended, 0, None).is_err());

        Ok(())
    }
}
