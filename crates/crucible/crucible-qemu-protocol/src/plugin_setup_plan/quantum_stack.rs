//! Assembles plan eleven with distinct explicit Main/RR stack observations.
//!
//! ```text
//! CRUCSU11 | schema11/header56/total/A/S/W/Startup128/Purpose2520/Publisher224
//! zero:u32 | Stack576:u32 | zero:u32
//! App | Selectable | Workspace? | Startup | CRUCPUR8 | CRUCPSP2 | CRUCSTK1
//! ```
//!
//! This carrier corroborates identities and checked inventory only. Its parser
//! authenticates no sealed role, profile, native account or nominal stack loan.
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::*;
use crate::publisher_subscription::quantum::{
    QUANTUM_STACK_PURPOSE_BYTES, QuantumPublisherPurpose, QuantumStackPurpose,
};
use crate::publisher_subscription::PUBLISHER_PURPOSE_BYTES;

const HEADER: usize = 56;

/// Retains decoded plan-eleven data without issuing any resource or operation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QuantumStackPlanParts {
    /// Decoded app-random configuration.
    pub app_random: AppRandomBranchPlan,
    /// Decoded selectable catalog configuration.
    pub selectable: SelectableCatalogPlan,
    /// Exact schema-two subscription observations.
    pub publisher: QuantumPublisherPurpose,
    /// Exact Main/RR stack inventory and parent observations.
    pub stacks: QuantumStackPurpose,
}

impl PluginSetupPlan {
    /// Reports plan eleven's exact extent before allocation or physical birth.
    ///
    /// # Errors
    /// Refuses nested encoding errors, overflow or the unchanged aggregate cap.
    pub fn preexec_quantum_stack_encoded_len(
        &self,
        has_workspace: bool,
    ) -> Result<usize, PluginSetupPlanError> {
        checked_extent(self.preexec_publisher_encoded_len(has_workspace)?)
    }

    /// Encodes the exact plan-eleven carrier with one final output allocation.
    ///
    /// Nested encoders also allocate their existing app and selectable bodies.
    /// The actual issuer must price their simultaneous peak before calling.
    /// This performs no sealed-file authentication or stack-grant issuance.
    ///
    /// # Errors
    /// Refuses missing startup, mixed parent coordinates, invalid stack or nested
    /// data, and any extent exceeding the fixed individual or aggregate caps.
    pub fn encode_preexec_quantum_stack(
        &self,
        purpose: &[u8; PROCESS_PURPOSE_BYTES],
        workspace: Option<&[u8; DEVICE_DIGEST_PURPOSE_BYTES]>,
        publisher: &QuantumPublisherPurpose,
        stacks: &QuantumStackPurpose,
    ) -> Result<Vec<u8>, PluginSetupPlanError> {
        let startup = self.startup_operation.as_ref().ok_or_else(invalid)?;
        preexec::validate_binding(startup, purpose, workspace.map(|bytes| bytes.as_slice()))?;
        super::publisher::validate_binding(&publisher.session, purpose)?;
        same_parent(stacks, publisher)?;
        let stack_bytes = stacks.encode().map_err(|_| invalid())?;
        let subscription = publisher.encode().map_err(|_| invalid())?;
        let total = self.preexec_quantum_stack_encoded_len(workspace.is_some())?;

        let app = self.app_random_branch_plan.encode();
        let selectable = self
            .selectable_catalog_plan
            .encode()
            .map_err(|source| PluginSetupPlanError::Selectable { source })?;
        let mut bytes = Vec::with_capacity(total);
        bytes.extend_from_slice(b"CRUCSU11");
        // The checked aggregate and individual caps all fit protocol u32 fields.
        for word in [
            11,
            HEADER as u32,
            total as u32,
            app.len() as u32,
            selectable.len() as u32,
            workspace.map_or(0, |_| DEVICE_DIGEST_PURPOSE_BYTES as u32),
            STARTUP_OPERATION_BYTES as u32,
            PROCESS_PURPOSE_BYTES as u32,
            PUBLISHER_PURPOSE_BYTES as u32,
            0,
            QUANTUM_STACK_PURPOSE_BYTES as u32,
            0,
        ] {
            bytes.extend_from_slice(&word.to_be_bytes());
        }
        bytes.extend_from_slice(&app);
        bytes.extend_from_slice(&selectable);
        if let Some(workspace) = workspace {
            bytes.extend_from_slice(workspace);
        }
        bytes.extend_from_slice(&startup.encode());
        bytes.extend_from_slice(purpose);
        bytes.extend_from_slice(&subscription);
        bytes.extend_from_slice(&stack_bytes);
        Ok(bytes)
    }

    /// Decodes only plan eleven and its exact Purpose2 and stack sections.
    ///
    /// # Errors
    /// Refuses other editions, unknown flags, malformed lengths, truncation,
    /// trailing data, invalid nested records, parent changes or excessive size.
    pub fn decode_preexec_quantum_stack_parts(
        bytes: &[u8],
    ) -> Result<QuantumStackPlanParts, PluginSetupPlanError> {
        if bytes.len() > PLUGIN_SETUP_PLAN_MAX_BYTES {
            return Err(too_large(bytes.len()));
        }
        if bytes.len() < HEADER
            || bytes[..8] != *b"CRUCSU11"
            || read_u32(bytes, 8)? != 11
            || read_u32(bytes, 12)? != HEADER as u32
            || read_u32(bytes, 16)? as usize != bytes.len()
            || read_u32(bytes, 32)? as usize != STARTUP_OPERATION_BYTES
            || read_u32(bytes, 36)? as usize != PROCESS_PURPOSE_BYTES
            || read_u32(bytes, 40)? as usize != PUBLISHER_PURPOSE_BYTES
            || read_u32(bytes, 44)? != 0
            || read_u32(bytes, 48)? as usize != QUANTUM_STACK_PURPOSE_BYTES
            || read_u32(bytes, 52)? != 0
        {
            return Err(invalid());
        }
        let app_len = read_u32(bytes, 20)? as usize;
        let selectable_len = read_u32(bytes, 24)? as usize;
        let workspace_len = read_u32(bytes, 28)? as usize;
        if app_len > MAX_APP_RANDOM_BRANCH_PLAN_BYTES
            || selectable_len > SELECTABLE_CATALOG_PLAN_MAX_BYTES
            || !matches!(workspace_len, 0 | DEVICE_DIGEST_PURPOSE_BYTES)
        {
            return Err(invalid());
        }
        let mut cursor = HEADER;
        let mut take = |length: usize| -> Result<&[u8], PluginSetupPlanError> {
            let end = cursor.checked_add(length).ok_or_else(invalid)?;
            let section = bytes.get(cursor..end).ok_or_else(invalid)?;
            cursor = end;
            Ok(section)
        };
        let app_bytes = take(app_len)?;
        let selectable_bytes = take(selectable_len)?;
        let workspace = take(workspace_len)?;
        let startup_bytes = take(STARTUP_OPERATION_BYTES)?;
        let purpose = take(PROCESS_PURPOSE_BYTES)?;
        let publisher_bytes = take(PUBLISHER_PURPOSE_BYTES)?;
        let stack_bytes = take(QUANTUM_STACK_PURPOSE_BYTES)?;
        if cursor != bytes.len() {
            return Err(invalid());
        }

        let startup = StartupOperation::decode(startup_bytes)
            .map_err(|source| PluginSetupPlanError::Startup { source })?;
        preexec::validate_binding(
            &startup,
            purpose,
            (!workspace.is_empty()).then_some(workspace),
        )?;
        let publisher = QuantumPublisherPurpose::decode(publisher_bytes).map_err(|_| invalid())?;
        super::publisher::validate_binding(&publisher.session, purpose)?;
        let stacks = QuantumStackPurpose::decode(stack_bytes).map_err(|_| invalid())?;
        same_parent(&stacks, &publisher)?;

        Ok(QuantumStackPlanParts {
            app_random: AppRandomBranchPlan::decode(app_bytes)
                .map_err(|source| PluginSetupPlanError::AppRandom { source })?,
            selectable: SelectableCatalogPlan::decode(selectable_bytes)
                .map_err(|source| PluginSetupPlanError::Selectable { source })?,
            publisher,
            stacks,
        })
    }
}

fn same_parent(
    stacks: &QuantumStackPurpose,
    publisher: &QuantumPublisherPurpose,
) -> Result<(), PluginSetupPlanError> {
    let session = &publisher.session;
    if stacks.account_generation != session.account_generation
        || stacks.process_generation != session.process_generation
        || stacks.lender_generation != session.lender_generation
        || stacks.capability != session.capability
        || stacks.reservation != session.reservation
    {
        return Err(invalid());
    }
    Ok(())
}

fn checked_extent(ordinary: usize) -> Result<usize, PluginSetupPlanError> {
    let total = ordinary
        .checked_add(8 + QUANTUM_STACK_PURPOSE_BYTES)
        .ok_or_else(|| too_large(usize::MAX))?;
    if total > PLUGIN_SETUP_PLAN_MAX_BYTES {
        return Err(too_large(total));
    }
    Ok(total)
}

fn too_large(bytes: usize) -> PluginSetupPlanError {
    PluginSetupPlanError::PlanTooLarge {
        bytes,
        maximum: PLUGIN_SETUP_PLAN_MAX_BYTES,
    }
}

fn invalid() -> PluginSetupPlanError {
    PluginSetupPlanError::InvalidPreexecSection {
        section: "Quantum stack purpose",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stack_extent_keeps_the_same_aggregate_cap_and_refuses_widened_overflow() {
        let extra = 8 + 576;
        assert_eq!(
            checked_extent(PLUGIN_SETUP_PLAN_MAX_BYTES - extra).unwrap(),
            PLUGIN_SETUP_PLAN_MAX_BYTES
        );
        assert!(checked_extent(PLUGIN_SETUP_PLAN_MAX_BYTES - extra + 1).is_err());
        assert!(checked_extent(usize::MAX).is_err());
        for (workspace, aggregate) in [(0, 37_745_260), (128, 37_745_132)] {
            assert_eq!(
                56 + aggregate + workspace + 128 + 2520 + 224 + 576,
                PLUGIN_SETUP_PLAN_MAX_BYTES
            );
        }
    }
}
