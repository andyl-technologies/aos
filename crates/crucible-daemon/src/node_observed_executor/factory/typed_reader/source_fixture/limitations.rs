//! Retains the complete public limitations body in all original source launches.

use super::{InstalledTypedReaderSourceFixture, invalid};
use crucible_node_contract::ContentRef;
use crucible_node_provider::{
    ProviderError,
    reference_service::{InstalledContent, ReferenceNegotiatedLineageReaderLaunchBootstrap},
};

pub(super) fn originals<'a>(
    launches: &'a [ReferenceNegotiatedLineageReaderLaunchBootstrap; 3],
    reference: &ContentRef,
) -> Result<&'a [u8], ProviderError> {
    bodies(
        launches
            .iter()
            .map(|launch| launch.bootstrap.installed_content.as_slice()),
        reference,
    )
}

fn bodies<'a>(
    originals: impl Iterator<Item = &'a [InstalledContent]>,
    reference: &ContentRef,
) -> Result<&'a [u8], ProviderError> {
    let mut original: Option<&[u8]> = None;
    let mut count = 0usize;
    for installed in originals {
        let mut objects = installed
            .iter()
            .filter(|object| &object.reference == reference);
        let body = objects.next().ok_or_else(invalid)?.bytes.as_slice();
        if objects.next().is_some() {
            return Err(invalid());
        }
        reference.verify(body)?;
        if original.is_some_and(|prior| prior != body) {
            return Err(invalid());
        }
        original = Some(body);
        count += 1;
    }
    if count != 3 {
        return Err(invalid());
    }
    original.ok_or_else(invalid)
}

impl InstalledTypedReaderSourceFixture {
    /// Borrows the exact complete public limitations document from all original launches.
    ///
    /// # Errors
    /// Refuses changed current plan, absent/corrupt/duplicate original bodies or
    /// disagreement among the three independently installed source originals.
    pub(in super::super) fn original_limitations_bytes(
        &self,
    ) -> Result<(&ContentRef, &[u8]), ProviderError> {
        let plan_bytes = super::launch::encode(&self.plan, 1024 * 1024)?;
        self.authenticate_plan(&self.reference, &plan_bytes, &self.plan)
            .map_err(|_| invalid())?;
        let reference = &self.plan.limitations;
        let original = bodies(
            self.sources
                .iter()
                .map(|source| source.launch.bootstrap.installed_content.as_slice()),
            reference,
        )?;
        self.authenticate_plan(&self.reference, &plan_bytes, &self.plan)
            .map_err(|_| invalid())?;
        Ok((reference, original))
    }
}

#[cfg(test)]
#[path = "limitations_tests.rs"]
mod tests;
