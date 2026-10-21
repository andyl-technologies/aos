//! Reconstructs and joins initial DATA under the original physical custody.

use super::*;
use crate::reference_packet::service::complete_restore::import18::{
    InitialConstructionData, authenticate_initial_headers_data,
    initial_construction_from_wire_data, initial_quote_formatter_data,
};

impl OriginalImport18RawBootstrap {
    /// Spends independent Initial DATA reconstruction after Source correspondence.
    ///
    /// This matches all header announcements with the shared physical formula.
    /// It cannot create an opaque Initial/Recipe, native model or phase grant.
    ///
    /// # Errors
    /// Refuses re-entry, incomplete Source checking, stale/foreign custody,
    /// insufficient construction funding, or any original header/body mismatch.
    pub(in super::super) fn reconstruct_initial_data(&mut self) -> Result<(), ProviderError> {
        if self.initial_reconstruction_started {
            return Err(refused());
        }
        self.initial_reconstruction_started = true;
        let outcome = self.reconstruct_current_initial();
        let terminal = self.typed_bodies_data().map(|_| ());
        outcome?;
        terminal?;
        self.initial_reconstructed = true;
        Ok(())
    }

    fn reconstruct_current_initial(&mut self) -> Result<(), ProviderError> {
        if !self.source_authenticated {
            return Err(refused());
        }
        let bodies = self.typed_bodies_data()?;
        let formatter = initial_quote_formatter_data(bodies.launch.launch_data())?;
        let raw = raw_storage_floor(self.bodies.each_ref().map(Vec::len))?;
        let base = self.source_authentication_row.ok_or_else(refused)?;
        // Earlier parser/comparison work is finished. Its retained outputs stay
        // owned, while this quote has its own fixed controls and formatters.
        let quote = [
            base[0],
            base[1].max(formatter[1]),
            raw[2].checked_add(formatter[2]).ok_or_else(exhausted)?,
        ];
        self.initial_reconstruction_row = Some(quote);
        self.admit_source_row(quote)?;

        let bodies = self.typed_bodies_data()?;
        let derived = initial_construction_from_wire_data(
            bodies.launch,
            bodies.boot,
            self.bounds.requested_peak,
        )?;
        let row = derived.row;
        self.initial_construction = Some(derived);
        self.initial_reconstruction_row = Some(row);
        self.admit_source_row(row)?;
        let derived = self.initial_construction.as_ref().ok_or_else(refused)?;
        for (bank, maximum) in self.bodies.iter().zip(derived.maximum_encoded_bytes) {
            if bank.len() > maximum {
                return Err(refused());
            }
        }
        let bodies = self.typed_bodies_data()?;
        authenticate_initial_headers_data(
            bodies.recipe,
            bodies.launch,
            bodies.boot,
            self.header.as_ref().ok_or_else(refused)?,
            derived,
        )?;
        self.authenticate_controller_kernel_data()?;
        self.authenticate_controller_executable_data()
    }

    fn authenticate_controller_kernel_data(&self) -> Result<(), ProviderError> {
        let bodies = self.typed_bodies_data()?;
        let launch = bodies.launch.launch_data();
        let peer =
            rustix::net::sockopt::socket_peercred(&self.stream).map_err(std::io::Error::from)?;
        // The private launch must name the same real parent whose inherited
        // socket and original nonrenewing cut guard this entire transition.
        // An otherwise internally consistent announcement cannot replace it.
        if launch.controller_pid.get() != u64::from(peer.pid.as_raw_nonzero().get() as u32)
            || launch.controller_uid.get() != u64::from(peer.uid.as_raw())
        {
            return Err(ProviderError::Correlation(
                "original import18 controller kernel DATA",
            ));
        }
        Ok(())
    }
}

pub(super) fn counter_scratch_data() -> usize {
    size_of::<InitialConstructionData>()
        + size_of::<Result<InitialConstructionData, ProviderError>>()
        + size_of::<&InitialConstructionData>()
        + size_of::<Option<&InitialConstructionData>>()
        + size_of::<[usize; 3]>() * 4
        + size_of::<
            std::iter::Zip<std::slice::Iter<'static, Vec<u8>>, std::array::IntoIter<usize, 3>>,
        >()
        + size_of::<usize>() * 2
        + size_of::<Option<usize>>()
        + size_of::<Result<(), ProviderError>>() * 3
        + size_of::<rustix::net::UCred>()
        + size_of::<Result<rustix::net::UCred, rustix::io::Errno>>()
        + size_of::<Result<rustix::net::UCred, std::io::Error>>()
        + size_of::<rustix::process::Pid>()
        + size_of::<rustix::process::Uid>()
        + size_of::<u32>() * 2
        + size_of::<u64>() * 2
        + size_of::<&crate::reference_packet::service::PacketNative5SourceLaunch>()
        + size_of::<bool>()
}
