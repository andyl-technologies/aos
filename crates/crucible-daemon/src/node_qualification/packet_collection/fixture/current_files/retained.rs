//! Observes the actual retained complete-byte descriptors and their metadata.
//!
//! This counts requested userspace storage. Kernel file/FD tables, transient
//! read buffers and the enclosing CurrentFiles Rc are separate owners. An
//! acquired lease has opaque notification-thread backing and is unsupported.

use std::{
    fs::File,
    mem::{align_of, size_of},
};

use crate::node_qualification::{
    QualificationError, packet_collection::complete::retained::Counter,
};

impl super::CurrentFiles {
    pub(in crate::node_qualification::packet_collection) fn charge_retained_storage(
        &self,
        counter: &mut Counter,
    ) -> Result<(), QualificationError> {
        if self
            .originals
            .iter()
            .any(|original| original.file.lease().is_some())
        {
            return Err(QualificationError::Refused(
                "complete retained accounting cannot observe a notification worker",
            ));
        }
        counter.add(
            self.originals
                .capacity()
                .checked_mul(size_of::<super::Original>())
                .ok_or(QualificationError::Refused(
                    "complete descriptor bank overflows",
                ))?,
        )?;
        for original in &self.originals {
            counter.charge(&original.path)?;
            counter.charge(&original.content)?;
            // This borrowed File is the Arc's actual data address. Separate
            // opens of the same pathname remain separate allocations.
            counter.shared_header(
                (original.file.file() as *const File).cast(),
                size_of::<File>(),
                align_of::<File>(),
            )?;
        }
        Ok(())
    }
}
