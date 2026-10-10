//! Bounds the distinct independently authored native storage group selection.

use super::super::super::{
    InstalledHostIoProfile, InstalledNodeKind, InstalledNodeSelection, NodeObservedError, refused,
};
use crucible_node_contract::Validate;

/// Borrows one validated independent finite request source and its Block consumer.
pub(in crate::node_observed_executor::factory) struct IndependentGroupSelection<'a> {
    pub(in crate::node_observed_executor::factory::native_state) source: &'a InstalledNodeSelection,
    pub(in crate::node_observed_executor::factory::native_state) block: &'a InstalledNodeSelection,
    pub(in crate::node_observed_executor::factory::native_state) selections:
        &'a [InstalledNodeSelection],
}

/// Recognizes the distinct prospective group without changing the Clock path.
pub(in crate::node_observed_executor::factory::native_state) fn selected(
    selections: &[InstalledNodeSelection],
) -> bool {
    selections.get(2..).is_some_and(|additional| {
        additional.iter().any(|selected| {
            matches!(
                selected.kind,
                InstalledNodeKind::HostScripted { .. } | InstalledNodeKind::HostIo { .. }
            )
        })
    })
}

impl<'a> IndependentGroupSelection<'a> {
    /// Validates the supported disconnected CPU plus independently owned group.
    ///
    /// This source preflight does not create a native model, child, graph seal or
    /// execution permit. The two authored group node names need not match a
    /// fixture; the original source profile names its actual public consumer.
    ///
    /// # Errors
    /// Refuses another native selector, an unsupported or aliased owner, another
    /// group geometry, an invalid identity or a route outside the group.
    pub(in crate::node_observed_executor::factory) fn new(
        selections: &'a [InstalledNodeSelection],
    ) -> Result<Self, NodeObservedError> {
        Self::new_selected(selections, false)
    }

    /// Selects the distinct complete preparation-bearing x86 source composition.
    pub(in crate::node_observed_executor::factory::native_state) fn new_preserving(
        selections: &'a [InstalledNodeSelection],
    ) -> Result<Self, NodeObservedError> {
        Self::new_selected(selections, true)
    }

    fn new_selected(
        selections: &'a [InstalledNodeSelection],
        preserving: bool,
    ) -> Result<Self, NodeObservedError> {
        let [clock, cpu, first, second] = selections else {
            return Err(refused(
                "independent storage composition requires its Clock/CPU and two group owners",
            ));
        };
        if clock.node.as_str() != "clock"
            || clock.owner.as_str() != "owner/clock"
            || !matches!(clock.kind, InstalledNodeKind::HostClock)
            || cpu.node.as_str() != "cpu"
            || cpu.owner.as_str() != "owner/cpu"
            || !match (&cpu.kind, preserving) {
                (InstalledNodeKind::Gem5Closed { isa }, false)
                | (InstalledNodeKind::Gem5ClosedPreserving { isa }, true) => {
                    *isa == super::super::super::InstalledGem5Isa::X86_64
                }
                _ => false,
            }
        {
            return Err(refused(
                "independent storage composition requires the existing live x86 native selection",
            ));
        }

        for selected in selections {
            selected.node.validate()?;
            selected.owner.validate()?;
        }
        if selections
            .windows(2)
            .any(|pair| pair[0].node >= pair[1].node)
            || selections.iter().enumerate().any(|(index, selected)| {
                selections[..index]
                    .iter()
                    .any(|prior| prior.owner == selected.owner)
            })
        {
            return Err(refused(
                "independent storage composition has an unsorted or duplicated original owner",
            ));
        }

        let (source, block) = match (&first.kind, &second.kind) {
            (InstalledNodeKind::HostScripted { .. }, InstalledNodeKind::HostIo { .. }) => {
                (first, second)
            }
            (InstalledNodeKind::HostIo { .. }, InstalledNodeKind::HostScripted { .. }) => {
                (second, first)
            }
            _ => {
                return Err(refused(
                    "independent storage composition supports exactly one script and one Block",
                ));
            }
        };
        let InstalledNodeKind::HostScripted { profile } = &source.kind else {
            return Err(refused("independent original script disappeared"));
        };
        profile.script.validate()?;
        profile.consumer.validate()?;
        if profile.consumer != block.node {
            return Err(refused(
                "independent original script may address only its enrolled Block consumer",
            ));
        }
        let InstalledNodeKind::HostIo {
            profile: InstalledHostIoProfile::Block { base_image, .. },
        } = &block.kind
        else {
            return Err(refused(
                "independent storage composition excludes the unqualified 9p family",
            ));
        };
        base_image.validate()?;

        Ok(Self {
            source,
            block,
            selections: &selections[2..],
        })
    }
}

#[cfg(test)]
mod tests;
