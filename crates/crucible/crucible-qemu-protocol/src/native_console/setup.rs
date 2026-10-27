//! Immutable console admission in the sealed composite setup descriptor.

use super::*;

/// Maximum retained issued bodies admitted by the setup format.
///
/// This is independent of byte-ring capacity. A launch may configure a smaller
/// inventory; overflow must refuse before its original publication effects.
pub const NATIVE_CONSOLE_MAX_ISSUED_AUTHORIZATIONS: u32 = 65_536;
/// Exact fixed header bytes preceding the canonical closed stream plan.
pub const NATIVE_CONSOLE_SETUP_HEADER_BYTES: usize = 32;
/// Maximum encoded console setup body.
pub const NATIVE_CONSOLE_SETUP_MAX_BYTES: usize = NATIVE_CONSOLE_SETUP_HEADER_BYTES
    + NATIVE_CONSOLE_PLAN_HEADER_BYTES
    + NATIVE_CONSOLE_MAX_STREAMS * NATIVE_CONSOLE_PLAN_ROW_BYTES;

/// Explicit bounded admission policy, not a runnable phase or native capability.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NativeConsoleSetupPlan {
    plan: NativeConsolePlan,
    issued_authorization_capacity: u32,
    authorization_allowance: u32,
}

impl NativeConsoleSetupPlan {
    /// Validates the configured inventory, allowance, and closed stream plan.
    ///
    /// # Errors
    ///
    /// Refuses an empty plan, malformed stream owners, zero/oversized inventory,
    /// or zero/out-of-ring allowance. Actual native resolution remains required.
    pub fn new(
        plan: NativeConsolePlan,
        issued_authorization_capacity: u32,
        authorization_allowance: u32,
    ) -> Result<Self, NativeConsoleError> {
        plan.encode()?;
        if plan.streams.is_empty()
            || issued_authorization_capacity == 0
            || issued_authorization_capacity > NATIVE_CONSOLE_MAX_ISSUED_AUTHORIZATIONS
            || authorization_allowance == 0
            || authorization_allowance > NATIVE_CONSOLE_CAPACITY
        {
            return Err(NativeConsoleError::Field);
        }
        Ok(Self {
            plan,
            issued_authorization_capacity,
            authorization_allowance,
        })
    }

    /// Returns the immutable logical stream plan admitted by setup.
    #[must_use]
    pub const fn plan(&self) -> &NativeConsolePlan {
        &self.plan
    }

    /// Returns the explicitly configured full-body custody capacity.
    #[must_use]
    pub const fn issued_authorization_capacity(&self) -> u32 {
        self.issued_authorization_capacity
    }

    /// Returns the fixed byte allowance for each genuinely issued authorization.
    #[must_use]
    pub const fn authorization_allowance(&self) -> u32 {
        self.authorization_allowance
    }

    /// Encodes the canonical bounded policy and closed plan.
    ///
    /// # Errors
    ///
    /// Refuses malformed nested plan fields or an unrepresentable body length.
    pub fn encode(&self) -> Result<Vec<u8>, NativeConsoleError> {
        let plan = self.plan.encode()?;
        let length = NATIVE_CONSOLE_SETUP_HEADER_BYTES + plan.len();
        let wire_length = u32::try_from(length).map_err(|_| NativeConsoleError::Length)?;
        let mut bytes = vec![0; length];
        bytes[..8].copy_from_slice(b"NCSETUP1");
        put32(&mut bytes, 8, 1);
        put32(&mut bytes, 12, wire_length);
        put32(&mut bytes, 16, self.issued_authorization_capacity);
        put32(&mut bytes, 20, self.authorization_allowance);
        bytes[NATIVE_CONSOLE_SETUP_HEADER_BYTES..].copy_from_slice(&plan);
        Ok(bytes)
    }

    /// Decodes the complete immutable admission policy and nested plan.
    ///
    /// # Errors
    ///
    /// Refuses an oversized/truncated body, wrong framing, reserved bytes,
    /// trailing data, invalid policy, or noncanonical closed plan.
    pub fn decode(bytes: &[u8]) -> Result<Self, NativeConsoleError> {
        if bytes.len() < NATIVE_CONSOLE_SETUP_HEADER_BYTES
            || bytes.len() > NATIVE_CONSOLE_SETUP_MAX_BYTES
        {
            return Err(NativeConsoleError::Length);
        }
        if &bytes[..8] != b"NCSETUP1"
            || get32(bytes, 8) != 1
            || get32(bytes, 12) as usize != bytes.len()
            || bytes[24..32].iter().any(|value| *value != 0)
        {
            return Err(NativeConsoleError::Framing);
        }
        Self::new(
            NativeConsolePlan::decode(&bytes[NATIVE_CONSOLE_SETUP_HEADER_BYTES..])?,
            get32(bytes, 16),
            get32(bytes, 20),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plan() -> NativeConsolePlan {
        NativeConsolePlan {
            slot: 0,
            logical_generation: 3,
            node_sequence_base: 0,
            streams: vec![NativeConsoleStream {
                stream: 1,
                device: NativeConsoleDevice::Serial16550,
                device_identity: [9; 32],
                owner_mask: 1,
                sequence_base: 0,
            }],
        }
    }

    #[test]
    fn explicit_inventory_capacity_and_allowance_refuse_out_of_profile_values()
    -> Result<(), NativeConsoleError> {
        for (capacity, allowance) in [(0, 1), (65_537, 1), (1, 0), (1, 4_097)] {
            assert!(NativeConsoleSetupPlan::new(plan(), capacity, allowance).is_err());
        }
        let admitted = NativeConsoleSetupPlan::new(plan(), 17, 2)?;
        assert_eq!(
            NativeConsoleSetupPlan::decode(&admitted.encode()?)?,
            admitted
        );
        Ok(())
    }
}
