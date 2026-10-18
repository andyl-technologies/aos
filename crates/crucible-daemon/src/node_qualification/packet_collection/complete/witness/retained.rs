//! Observes the same Oracle's original typed journals, effects and consuming role.
//!
//! Core retains shared runtime/activation authorities; this observer charges the
//! Oracle's independent token routes and activation-record clones only.

use super::*;
use crate::node_qualification::packet_collection::complete::retained::Counter;
use crucible_node_provider::retained_metadata::{
    RetainedCompleteSourceDefinition, RetainedPacketNativeRecord,
};

impl PacketCompleteNativeOracle {
    pub(in crate::node_qualification::packet_collection::complete) fn charge_retained_storage(
        &self,
        counter: &mut Counter,
    ) -> Result<(), QualificationError> {
        self.roster.charge_retained_storage(counter)?;
        for program in &self.programmes {
            let borrowed = match program {
                PacketConnectedSourceProgram::Producer { program } => {
                    RetainedCompleteSourceDefinition::Program(program)
                }
                PacketConnectedSourceProgram::Reactive { program } => {
                    RetainedCompleteSourceDefinition::Connected(program)
                }
            };
            counter.metadata(
                &borrowed
                    .observe_retained_metadata()
                    .map_err(|_| refused())?,
            )?;
        }
        // The group is a fixed three-FD owner with no heap fields. Reader/group
        // aliases retain this same Rc backing; no descriptor is duplicated.
        counter.rc(&self.receiver_group)?;
        counter.rc(&self.receiver_reader)?;
        counter.charge(&self.effect_paths)?;
        counter.charge(&self.schedule)?;
        counter.charge(&self.plan)?;
        let observed = self.observed.try_borrow().map_err(|_| refused())?;
        charge_observed_storage_data(counter, &observed)?;
        self.originals.charge_retained_storage(counter)
    }
}

/// Counts the actual journal independently of Source/currentness callbacks.
///
/// The enclosing owner charges the Oracle root and separately supplies the
/// selected metadata visitor's transient/fixed windows before this walk.
pub(super) fn charge_observed_storage_data(
    counter: &mut Counter,
    observed: &Observed,
) -> Result<(), QualificationError> {
    counter.add(
        observed
            .seals
            .capacity()
            .checked_mul(std::mem::size_of::<Seal>())
            .ok_or_else(refused)?,
    )?;
    for seal in &observed.seals {
        counter.charge(&seal.reference)?;
        counter.charge(&seal.bytes)?;
        counter.charge(&seal.native)?;
        let borrowed = match &seal.body {
            NativeBody::Producer(body) => RetainedPacketNativeRecord::Producer(body),
            NativeBody::Reactive(body) => RetainedPacketNativeRecord::Reactive(body),
            NativeBody::Stage(body) => RetainedPacketNativeRecord::Stage(body),
            NativeBody::Commit(body) => RetainedPacketNativeRecord::Commit(body),
        };
        counter.metadata(
            &borrowed
                .observe_retained_metadata()
                .map_err(|_| refused())?,
        )?;
    }
    for effects in &observed.effects {
        counter.add(
            effects
                .capacity()
                .checked_mul(std::mem::size_of::<effects::Effect>())
                .ok_or_else(refused)?,
        )?;
        for effect in effects {
            match effect {
                effects::Effect::Producer {
                    bytes: _,
                    length: _,
                } => {}
                effects::Effect::Reactive(effect) => {
                    let borrowed = match effect {
                        effects::ReactiveEffect::Delivery { delivery } => {
                            RetainedPacketNativeRecord::DeliveredInput(delivery)
                        }
                        effects::ReactiveEffect::Reaction {
                            operation,
                            reaction,
                        } => {
                            counter.charge(operation)?;
                            RetainedPacketNativeRecord::Reaction(reaction)
                        }
                        effects::ReactiveEffect::Publication { publication } => {
                            RetainedPacketNativeRecord::Publication(publication)
                        }
                    };
                    counter.metadata(
                        &borrowed
                            .observe_retained_metadata()
                            .map_err(|_| refused())?,
                    )?;
                }
            }
        }
    }
    Ok(())
}
