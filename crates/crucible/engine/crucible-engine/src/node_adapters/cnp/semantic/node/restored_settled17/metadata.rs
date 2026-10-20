//! Validates closed historical container facts without minting allocation grants.

use super::record::*;
use crate::node_contract::RuntimeError;

pub(super) fn validate(record: &NodeRecord17) -> Result<(), RuntimeError> {
    if record.original_operations_capacity < record.original_operations.len()
        || record.original_inputs_capacity < record.original_inputs.len()
        || record.producer_attempts_capacity < record.producer_attempts.len()
        || record.capacities.len() > 131_072
    {
        return Err(RuntimeError::InvalidReceipt);
    }
    for row in &record.capacities {
        layout(row.length, row.element_bytes, row.alignment)?;
        match row.kind {
            CommonCapacityKind17::String | CommonCapacityKind17::Vector => {
                let capacity = row.capacity.ok_or(RuntimeError::InvalidReceipt)?;
                if capacity < row.length || row.shared_group.is_some() {
                    return Err(RuntimeError::InvalidReceipt);
                }
                layout(capacity, row.element_bytes, row.alignment)?;
                if matches!(row.kind, CommonCapacityKind17::String)
                    && (row.element_bytes != 1 || row.alignment != 1)
                {
                    return Err(RuntimeError::InvalidReceipt);
                }
            }
            CommonCapacityKind17::Tree => {
                if row.capacity.is_some() || row.shared_group.is_some() {
                    return Err(RuntimeError::InvalidReceipt);
                }
            }
            CommonCapacityKind17::Shared => {
                // Groups belong to the complete Source graph, not a per-node
                // prefix. Their cross-component equality is checked there.
                if row.length != 1 || row.capacity.is_some() || row.shared_group.is_none() {
                    return Err(RuntimeError::InvalidReceipt);
                }
            }
        }
    }
    if let Some(value) = &record.base_activate_response_history {
        provider(&value.capacities, &value.aliases)?;
    }
    for value in record
        .commands
        .iter()
        .flatten()
        .chain(record.world_manifest.iter())
    {
        provider(&value.capacities, &value.aliases)?;
    }
    for value in record
        .completed
        .iter()
        .flatten()
        .chain(record.observation_completed.iter())
    {
        provider(&value.capacities, &value.aliases)?;
    }
    Ok(())
}

fn provider(rows: &[ProviderCapacity17], aliases: &[ProviderAlias17]) -> Result<(), RuntimeError> {
    if rows.len() > 131_072 || aliases.len() > 131_072 {
        return Err(RuntimeError::InvalidReceipt);
    }
    for ProviderCapacity17(kind, extent, element_bytes, alignment) in rows {
        layout(*extent, *element_bytes, *alignment)?;
        if matches!(kind, ProviderCapacityKind17::String)
            && (*element_bytes != 1 || *alignment != 1)
        {
            return Err(RuntimeError::InvalidReceipt);
        }
        if matches!(
            kind,
            ProviderCapacityKind17::Shared | ProviderCapacityKind17::Boxed
        ) && *element_bytes != 1
        {
            return Err(RuntimeError::InvalidReceipt);
        }
    }
    // These rows are cumulative in the actual Provider bank. A group can be
    // born in an earlier component; complete Source validation owns that join.
    Ok(())
}

fn layout(extent: usize, element_bytes: usize, alignment: usize) -> Result<(), RuntimeError> {
    if !alignment.is_power_of_two() || alignment > isize::MAX as usize {
        return Err(RuntimeError::InvalidReceipt);
    }
    extent
        .checked_mul(element_bytes)
        .ok_or(RuntimeError::ResourceLimit)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    #[test]
    fn historical_provider_rows_require_alignment_and_closed_kinds() -> TestResult {
        let valid: ProviderCapacity17 = serde_json::from_str(r#"["vector",7,8,8]"#)?;
        provider(&[valid], &[])?;
        assert!(serde_json::from_str::<ProviderCapacity17>(r#"["vector",7,8]"#).is_err());
        assert!(serde_json::from_str::<ProviderCapacity17>(r#"["pointer",7,8,8]"#).is_err());
        let bad: ProviderCapacity17 = serde_json::from_str(r#"["string",7,1,3]"#)?;
        assert!(provider(&[bad], &[]).is_err());
        Ok(())
    }

    #[test]
    fn historical_aliases_preserve_numeric_groups_and_reject_unknown_kinds() -> TestResult {
        let original = r#"["content-bytes",9]"#;
        let alias: ProviderAlias17 = serde_json::from_str(original)?;
        assert_eq!(serde_json::to_string(&alias)?, original);
        assert!(serde_json::from_str::<ProviderAlias17>(r#"["raw-address",9]"#).is_err());
        assert!(serde_json::from_str::<ProviderAlias17>(r#"["content-bytes",9,10]"#).is_err());
        Ok(())
    }

    #[test]
    fn common_capacities_preserve_spares_and_reject_unknown_fields() -> TestResult {
        let original = r#"{"kind":"vector","length":0,"capacity":17,"element_bytes":8,"alignment":8,"shared_group":null}"#;
        let row: CommonCapacity17 = serde_json::from_str(original)?;
        assert_eq!(row.capacity, Some(17));
        assert!(serde_json::from_str::<CommonCapacity17>(r#"{"kind":"vector","length":0,"capacity":17,"element_bytes":8,"alignment":8,"shared_group":null,"address":1}"#).is_err());
        assert!(serde_json::from_str::<CommonCapacity17>(r#"{"kind":"pointer","length":0,"capacity":17,"element_bytes":8,"alignment":8,"shared_group":null}"#).is_err());
        Ok(())
    }
}
