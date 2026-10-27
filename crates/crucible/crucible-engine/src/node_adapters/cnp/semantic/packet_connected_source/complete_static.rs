//! Retains explicit complete-only input policy evidence before native association.
//!
//! The original installed graph supplies full typed rows from its authenticated
//! immutable content closure. These portable rows confer no graph or capture
//! permission. Ordinary connected-four never enters this data path.

use super::*;
use crate::node_adapters::cnp::semantic::packet_complete_source::storage_error::StorageError;
use crate::node_adapters::cnp::semantic::packet_lineage::Rows;

#[path = "complete_static/metadata.rs"]
mod metadata;

pub(super) struct CompleteInputStaticRows {
    rows: Vec<(InputPayload, Vec<ContentRef>)>,
    complete: bool,
    failed: bool,
}

impl PacketConnectedSemanticSource {
    pub(in crate::node_adapters::cnp::semantic) fn complete_prebirth_input_static_storage_with_error<
        E: crate::node_adapters::cnp::semantic::packet_complete_source::storage_error::StorageError,
    >(
        &self,
        maximum: usize,
    ) -> Result<usize, E> {
        self.local_owner_with_error::<E>()?;
        if !self.world.is_complete() || !self.complete_preparation_unbound_with_error::<E>()? {
            return Err(E::refused(
                "complete static data is outside its unbound phase",
            ));
        }
        let slot = self
            .complete_input_static
            .try_borrow()
            .map_err(|_| E::refused("complete static bank busy"))?;
        match slot.as_ref() {
            None => Ok(0),
            Some(original) if original.complete && !original.failed => {
                original.storage_with_error::<E>(maximum)
            }
            Some(_) => Err(E::refused("complete static graph rows incomplete")),
        }
    }

    pub(in crate::node_adapters::cnp::semantic) fn retain_complete_input_static_rows(
        &self,
        supplied: &[(InputPayload, Vec<ContentRef>)],
        maximum: usize,
    ) -> Result<(), OperationFailure> {
        self.local_owner()?;
        if !self.world.is_complete() || maximum == 0 || maximum > 512 * 1024 * 1024 {
            return Err(refused("complete static input allowance unsupported"));
        }
        let mut slot = self
            .complete_input_static
            .try_borrow_mut()
            .map_err(|_| refused("complete static input bank busy"))?;
        if let Some(original) = slot.as_ref() {
            if !original.complete || original.failed || original.rows != supplied {
                return Err(refused(
                    "complete static input rows differ or previous bind failed",
                ));
            }
            original.storage(maximum)?;
            return self.local_owner();
        }
        if !self.complete_preparation_unbound()? {
            return Err(refused(
                "complete static input rows follow native association",
            ));
        }
        validate_rows(&self.definition, supplied, maximum)?;
        *slot = Some(CompleteInputStaticRows {
            rows: Vec::new(),
            complete: false,
            failed: false,
        });
        let original = slot
            .as_mut()
            .ok_or_else(|| refused("complete static input slot absent"))?;
        let result = (|| {
            original
                .rows
                .try_reserve_exact(supplied.len())
                .map_err(unknown)?;
            for (body, dependencies) in supplied {
                // Retain a row before reserving its byte/dependency banks. The
                // authenticated caller still retains every original input row.
                original.rows.push((
                    InputPayload {
                        reference: body.reference.clone(),
                        bytes: Vec::new(),
                    },
                    Vec::new(),
                ));
                let row = original
                    .rows
                    .last_mut()
                    .ok_or_else(|| refused("complete static row absent"))?;
                row.0
                    .bytes
                    .try_reserve_exact(body.bytes.len())
                    .map_err(unknown)?;
                row.1
                    .try_reserve_exact(dependencies.len())
                    .map_err(unknown)?;
                row.0.bytes.extend_from_slice(&body.bytes);
                row.1.extend(dependencies.iter().cloned());
                original.storage(maximum)?;
            }
            original.complete = true;
            self.local_owner()
        })();
        if result.is_err() {
            original.failed = true;
        }
        result
    }

    pub(in crate::node_adapters::cnp::semantic) fn complete_input_static_storage(
        &self,
    ) -> Result<usize, OperationFailure> {
        self.complete_input_static_storage_with_error::<OperationFailure>()
    }

    pub(in crate::node_adapters::cnp::semantic) fn complete_input_static_storage_with_error<
        E: StorageError,
    >(
        &self,
    ) -> Result<usize, E> {
        self.local_owner_with_error::<E>()?;
        if !self.world.is_complete() {
            return Err(E::refused("ordinary input has no complete static bank"));
        }
        let slot = self
            .complete_input_static
            .try_borrow()
            .map_err(|_| E::refused("complete static bank busy"))?;
        let original = slot
            .as_ref()
            .ok_or_else(|| E::refused("complete input static graph rows absent"))?;
        if !original.complete || original.failed {
            return Err(E::refused("complete static graph rows incomplete"));
        }
        original.storage_with_error::<E>(512 * 1024 * 1024)
    }

    pub(super) fn add_complete_input_static_rows(
        &self,
        rows: &mut Rows,
    ) -> Result<(), OperationFailure> {
        self.local_owner()?;
        let slot = self
            .complete_input_static
            .try_borrow()
            .map_err(|_| refused("complete static input bank busy"))?;
        let original = slot
            .as_ref()
            .ok_or_else(|| refused("complete input static graph rows absent"))?;
        if !original.complete || original.failed {
            return Err(refused("complete input static rows failed"));
        }
        for (body, dependencies) in &original.rows {
            rows.add(&body.reference, &body.bytes, dependencies.clone())?;
        }
        self.local_owner()
    }
}

impl CompleteInputStaticRows {
    fn storage(&self, maximum: usize) -> Result<usize, OperationFailure> {
        self.storage_with_error::<OperationFailure>(maximum)
    }

    pub(in crate::node_adapters::cnp::semantic) fn storage_with_error<E: StorageError>(
        &self,
        maximum: usize,
    ) -> Result<usize, E> {
        let mut bytes = std::mem::size_of::<Self>()
            .checked_add(
                self.rows
                    .capacity()
                    .checked_mul(std::mem::size_of::<(InputPayload, Vec<ContentRef>)>())
                    .ok_or_else(|| E::refused("complete static row layout overflow"))?,
            )
            .ok_or_else(|| E::refused("complete static holder overflow"))?;
        for (body, dependencies) in &self.rows {
            for amount in [
                body.bytes.capacity(),
                NodeRuntime::capture_reference_storage(&body.reference).map_err(E::runtime)?,
                dependencies
                    .capacity()
                    .checked_mul(std::mem::size_of::<ContentRef>())
                    .ok_or_else(|| E::refused("complete static dependency layout overflow"))?,
            ] {
                bytes = add_with_error::<E>(bytes, amount, maximum)?;
            }
            for reference in dependencies {
                bytes = add_with_error::<E>(
                    bytes,
                    NodeRuntime::capture_reference_storage(reference).map_err(E::runtime)?,
                    maximum,
                )?;
            }
        }
        if bytes > maximum {
            return Err(E::refused("complete static bank exceeds allowance"));
        }
        Ok(bytes)
    }
}

fn validate_rows(
    definition: &PacketConnectedDefinition,
    rows: &[(InputPayload, Vec<ContentRef>)],
    maximum: usize,
) -> Result<(), OperationFailure> {
    if rows.is_empty()
        || rows.len() > 4096
        || rows
            .windows(2)
            .any(|pair| pair[0].0.reference >= pair[1].0.reference)
    {
        return Err(refused("complete static input row order/extent invalid"));
    }
    let mut bytes = rows
        .len()
        .checked_mul(
            std::mem::size_of::<(InputPayload, Vec<ContentRef>)>()
                + 2 * std::mem::size_of::<bool>(),
        )
        .ok_or_else(|| refused("complete static requested row overflow"))?;
    let mut edges = 0usize;
    for (body, dependencies) in rows {
        edges = edges
            .checked_add(dependencies.len())
            .filter(|edges| *edges <= 65536)
            .ok_or_else(|| refused("complete static input edge limit"))?;
        bytes = add(
            bytes,
            dependencies
                .len()
                .checked_mul(std::mem::size_of::<ContentRef>())
                .ok_or_else(|| refused("complete static dependency request overflow"))?,
            maximum,
        )?;
        body.reference.verify(&body.bytes).map_err(unknown)?;
        bytes = add(bytes, body.bytes.len(), maximum)?;
        // Binary bodies are copied as bytes, never parsed into a giant numeric
        // JSON tree. Only selected ConnectionPolicy roots are decoded below;
        // the graph authority separately authenticates every other typed row.
        bytes = add(
            bytes,
            NodeRuntime::capture_reference_storage(&body.reference).map_err(unknown)?,
            maximum,
        )?;
        if dependencies.windows(2).any(|pair| pair[0] >= pair[1])
            || dependencies.contains(&body.reference)
        {
            return Err(refused("complete static input direct row invalid"));
        }
        for dependency in dependencies {
            dependency.validate().map_err(unknown)?;
            if rows
                .binary_search_by(|row| row.0.reference.cmp(dependency))
                .is_err()
            {
                return Err(refused("complete static input full dependency absent"));
            }
            bytes = add(
                bytes,
                NodeRuntime::capture_reference_storage(dependency).map_err(unknown)?,
                maximum,
            )?;
        }
    }
    let mut seen = Vec::new();
    seen.try_reserve_exact(rows.len()).map_err(unknown)?;
    seen.resize(rows.len(), false);
    for route in &definition.connections {
        let index = rows
            .binary_search_by(|row| row.0.reference.cmp(&route.policy))
            .map_err(|_| refused("complete input policy root absent"))?;
        let parse_bound = rows[index]
            .0
            .bytes
            .len()
            .checked_mul(
                std::mem::size_of::<serde_json::Value>() * 2
                    + NodeRuntime::capture_map_node_storage::<String, serde_json::Value>(),
            )
            .ok_or_else(|| refused("complete input policy parse extent overflow"))?;
        add(bytes, parse_bound, maximum)?;
        let policy: crate::node_admission::ConnectionPolicy = serde_json::from_value(
            canonical::parse_json(&rows[index].0.bytes, maximum).map_err(unknown)?,
        )
        .map_err(unknown)?;
        validate_policy_data(&policy, route.delay_ps)?;
        if rows[index].1.as_slice() != std::slice::from_ref(&policy.causal_proof_ref) {
            return Err(refused("complete input policy direct proof edge changed"));
        }
        seen[index] = true;
    }
    // Only explicitly supplied rows reachable from the actual selected policy
    // roots are retained. No missing row is silently treated as a leaf.
    for _ in 0..rows.len() {
        let mut changed = false;
        for index in 0..rows.len() {
            if !seen[index] {
                continue;
            }
            for dependency in &rows[index].1 {
                let next = rows
                    .binary_search_by(|row| row.0.reference.cmp(dependency))
                    .map_err(|_| refused("complete static dependency lost"))?;
                if !seen[next] {
                    seen[next] = true;
                    changed = true;
                }
            }
        }
        if !changed {
            break;
        }
    }
    if seen.iter().any(|one| !one) {
        return Err(refused("complete static input unrelated row"));
    }
    seen.fill(false);
    for _ in 0..rows.len() {
        let mut advanced = false;
        for index in 0..rows.len() {
            if seen[index] {
                continue;
            }
            let mut ready = true;
            for dependency in &rows[index].1 {
                let child = rows
                    .binary_search_by(|row| row.0.reference.cmp(dependency))
                    .map_err(|_| refused("complete static dependency lost"))?;
                ready &= seen[child];
            }
            if ready {
                seen[index] = true;
                advanced = true;
            }
        }
        if !advanced {
            break;
        }
    }
    if seen.iter().any(|one| !one) {
        return Err(refused("complete static input dependency cycle"));
    }
    Ok(())
}

// Full endpoint, visibility, ordered-domain and qualification checks remain
// in actual graph admission. This data reader binds the exact selected fixed
// delivery and intrinsic queue arithmetic before extracting the proof edge.
fn validate_policy_data(
    policy: &crate::node_admission::ConnectionPolicy,
    selected_delay: U64,
) -> Result<(), OperationFailure> {
    let capacity = policy
        .maximum_payload_bytes
        .get()
        .checked_mul(policy.maximum_pending_events.get())
        .ok_or_else(|| refused("complete input policy capacity overflows"))?;
    let crate::node_admission::ConnectionDelivery::Fixed { latency_ps } = &policy.delivery;
    if policy.schema_version != 1
        || *latency_ps != selected_delay
        || policy.maximum_pending_bytes < policy.maximum_payload_bytes
        || policy.maximum_pending_bytes.get() > capacity
    {
        return Err(refused(
            "complete input policy selected delivery or bounds differ",
        ));
    }
    policy.causal_proof_ref.validate().map_err(unknown)
}

fn add(total: usize, amount: usize, maximum: usize) -> Result<usize, OperationFailure> {
    add_with_error::<OperationFailure>(total, amount, maximum)
}

pub(in crate::node_adapters::cnp::semantic) fn add_with_error<E: StorageError>(
    total: usize,
    amount: usize,
    maximum: usize,
) -> Result<usize, E> {
    total
        .checked_add(amount)
        .filter(|sum| *sum <= maximum)
        .ok_or_else(|| E::limit("complete static input aggregate exceeds allowance"))
}

#[cfg(test)]
// crucible-lint: allow panic-shortcut -- Pure selected-policy fixtures fail at the exact invariant.
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn policy() -> crate::node_admission::ConnectionPolicy {
        crate::node_admission::ConnectionPolicy {
            schema_version: 1,
            maximum_payload_bytes: U64::new(32),
            maximum_pending_events: U64::new(4),
            maximum_pending_bytes: U64::new(128),
            visibility: crate::node_admission::VisibilityConversion::Direct,
            delivery: crate::node_admission::ConnectionDelivery::Fixed {
                latency_ps: U64::new(2),
            },
            causal_proof_ref: canonical::content_ref(b"actual causal proof", "application/json")
                .unwrap(),
            state_domain_ids: vec![Id::new("actual-connection-domain").unwrap()],
        }
    }

    #[test]
    fn input_policy_data_binds_selected_delay_and_checked_intrinsic_capacity() {
        let mut policy = policy();
        validate_policy_data(&policy, U64::new(2)).unwrap();
        assert!(validate_policy_data(&policy, U64::new(3)).is_err());
        policy.maximum_pending_bytes = U64::new(129);
        assert!(validate_policy_data(&policy, U64::new(2)).is_err());
        policy.maximum_pending_bytes = U64::new(31);
        assert!(validate_policy_data(&policy, U64::new(2)).is_err());
        policy.maximum_payload_bytes = U64::new(u64::MAX);
        assert!(validate_policy_data(&policy, U64::new(2)).is_err());
    }
}

impl PacketConnectedSemanticSource {
    pub(in crate::node_adapters::cnp::semantic) fn complete_initial_lifecycle_input_static_storage_data(
        &self,
        maximum: usize,
    ) -> Result<usize, crate::node_contract::RuntimeError> {
        use crate::node_contract::RuntimeError;
        self.local_owner_with_error::<RuntimeError>()?;
        if !self.world.is_complete() {
            return Err(RuntimeError::ForeignAuthority);
        }
        let slot = self
            .complete_input_static
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        match slot.as_ref() {
            None => Ok(0),
            Some(original) if original.complete && !original.failed => {
                original.storage_with_error::<RuntimeError>(maximum)
            }
            Some(_) => Err(RuntimeError::OwnerUnavailable),
        }
    }
}
