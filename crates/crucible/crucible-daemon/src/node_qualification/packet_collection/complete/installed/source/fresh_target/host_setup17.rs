//! Borrows every actual setup owner at the selected Host17 copy boundary.
//!
//! Only the two concrete installed callers construct this loan. Its field census
//! shares the enclosing action counter and binds the already-held actual capsule;
//! no caller byte total or erased callback stands in for an owner observation.

use super::*;
use crate::node_qualification::packet_collection::complete::retained::Counter;
use crucible_engine::node_contract::RuntimeError;
use crucible_node_format::ContentRef;
use std::{
    collections::BTreeMap,
    mem::{size_of, size_of_val},
};

pub(in crate::node_qualification::packet_collection::complete) struct HostSource17SetupBorrow<'a> {
    input: Setup<'a>,
}

enum Setup<'a> {
    Prepared(&'a PreparedCompleteRestoration),
    Direct {
        pin: &'a InstalledCompleteSceneManifest,
        directory: &'a PathBuf,
        selected: &'a Manifest,
        measurements: &'a [PacketFixtureMeasurements; 3],
        content: &'a BTreeMap<ContentRef, Vec<u8>>,
    },
}

impl<'a> HostSource17SetupBorrow<'a> {
    pub(super) fn prepared_data(owner: &'a PreparedCompleteRestoration) -> Self {
        Self {
            input: Setup::Prepared(owner),
        }
    }

    pub(super) fn direct_data(
        pin: &'a InstalledCompleteSceneManifest,
        directory: &'a PathBuf,
        selected: &'a Manifest,
        measurements: &'a [PacketFixtureMeasurements; 3],
        content: &'a BTreeMap<ContentRef, Vec<u8>>,
    ) -> Self {
        Self {
            input: Setup::Direct {
                pin,
                directory,
                selected,
                measurements,
                content,
            },
        }
    }

    pub(in crate::node_qualification::packet_collection::complete) fn authenticate_target_data(
        &self,
        selection: &crucible_engine::node_contract::HostSchedulingSelection,
        resources: &crucible_node_format::ResourceLimits,
    ) -> Result<(), RuntimeError> {
        match &self.input {
            Setup::Prepared(owner) => {
                owner.authenticate_host_setup17_target_data(selection, resources)
            }
            Setup::Direct { selected, .. } => {
                if !std::ptr::eq(selection, &selected.host)
                    || !std::ptr::eq(resources, &selected.resources)
                {
                    return Err(RuntimeError::ForeignAuthority);
                }
                Ok(())
            }
        }
    }

    pub(in crate::node_qualification::packet_collection::complete) fn charge_data(
        &self,
        counter: &mut Counter,
        original: Option<&Rc<RefCell<PacketCompleteRestorationPrebirth>>>,
    ) -> Result<(), RuntimeError> {
        match &self.input {
            Setup::Prepared(owner) => owner.charge_host_setup17_data(counter, original),
            Setup::Direct {
                pin,
                directory,
                selected,
                measurements,
                content,
            } => {
                let InstalledCompleteSceneManifest { path, expected } = pin;
                counter
                    .add(
                        size_of::<InstalledCompleteSceneManifest>()
                            + size_of::<PathBuf>()
                            + size_of::<Manifest>()
                            + size_of::<[PacketFixtureMeasurements; 3]>()
                            + size_of::<BTreeMap<ContentRef, Vec<u8>>>(),
                    )
                    .map_err(limit)?;
                counter.charge(path).map_err(limit)?;
                counter.charge(expected).map_err(limit)?;
                counter.charge(*directory).map_err(limit)?;
                selected.charge_host_setup17_data(counter)?;
                counter.charge(*measurements).map_err(limit)?;
                counter.charge(*content).map_err(limit)
            }
        }
    }

    pub(in crate::node_qualification::packet_collection::complete) fn counter_scratch_data()
    -> Result<usize, RuntimeError> {
        let terms = [
            Manifest::host_setup17_counter_scratch_data(),
            PreparedCompleteRestoration::host_setup17_counter_scratch_data()?,
            size_of::<Self>(),
            size_of::<&Self>(),
            size_of::<Setup<'static>>(),
            size_of::<&mut Counter>(),
            size_of::<&crucible_engine::node_contract::HostSchedulingSelection>(),
            size_of::<&crucible_node_format::ResourceLimits>(),
            size_of::<Option<&Rc<RefCell<PacketCompleteRestorationPrebirth>>>>(),
            size_of::<Result<(), RuntimeError>>(),
        ];
        terms.iter().try_fold(size_of_val(&terms), |total, bytes| {
            total.checked_add(*bytes).ok_or(RuntimeError::ResourceLimit)
        })
    }
}

fn limit(_: QualificationError) -> RuntimeError {
    RuntimeError::ResourceLimit
}
