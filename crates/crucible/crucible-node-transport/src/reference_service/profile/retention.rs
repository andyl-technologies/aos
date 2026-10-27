//! Counts all original profile retention fields before an owning clone.
//!
//! This borrowed serialization is an allocation credit, not a new wire format
//! or source qualification. It includes both retained body containers and the
//! separately retained selected definition, rather than charging public labels.

use super::*;
use serde::{Serialize, Serializer, ser::SerializeSeq};
use std::io::{self, Write};

impl ReferenceProfile {
    /// Credits complete profile retention before copying source metadata or bodies.
    ///
    /// Counts a borrowed envelope containing every owned field and body container.
    /// Source authenticity, semantic class and actual native custody remain
    /// independent obligations. No profile fields are cloned by this check.
    ///
    /// # Errors
    /// Refuses zero, above64MiB or insufficient encoded retention credit.
    pub fn preflight_retention(&self, maximum_bytes: usize) -> Result<(), ProviderError> {
        measure(self, maximum_bytes).map(|_| ())
    }
}

fn measure(profile: &ReferenceProfile, maximum: usize) -> Result<usize, ProviderError> {
    if maximum == 0 || maximum > 64 * 1024 * 1024 {
        return Err(ProviderError::ResourceExhausted("profile retention credit"));
    }
    let selection = match profile.selection {
        ProfileSelection::Cnp => ("cnp", false),
        ProfileSelection::Closed => ("closed", true),
        ProfileSelection::Linked { closed_ingress } => ("linked", closed_ingress),
        ProfileSelection::PublicLinked { closed_ingress } => ("public_linked", closed_ingress),
        ProfileSelection::PublicLineage { closed_ingress } => ("public_lineage", closed_ingress),
        ProfileSelection::PublicProgress { closed_ingress } => ("public_progress", closed_ingress),
    };
    let definition = profile.input_reader.as_ref().map(|original| {
        (
            original.declaration(),
            original.selection(),
            original.handler(),
            original.objects(),
        )
    });
    let mut credit = Credit(maximum);
    // Nested tuples keep serde's finite tuple grammar while covering every
    // actual field, including the private role references and duplicate bodies.
    serde_json::to_writer(
        &mut credit,
        &(
            (
                &profile.descriptor,
                &profile.implementation,
                &profile.operating_contract,
                &profile.capabilities,
                &profile.guarantees,
                &profile.owner,
                &profile.node_manifest,
                &profile.provider_manifest,
            ),
            (
                &profile.configuration_ref,
                &profile.content_possession_schema,
                &profile.profile_ref,
                &profile.capabilities_ref,
                &profile.guarantees_ref,
                &profile.ownership_ref,
            ),
            (
                &profile.contents,
                Bodies(&profile.content),
                definition,
                selection,
            ),
        ),
    )
    .map_err(|_| ProviderError::ResourceExhausted("complete profile retention bytes"))?;
    Ok(maximum - credit.0)
}

struct Bodies<'a>(&'a [ProfileContent]);

impl Serialize for Bodies<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut sequence = serializer.serialize_seq(Some(self.0.len()))?;
        for body in self.0 {
            sequence.serialize_element(&(&body.reference, &body.bytes))?;
        }
        sequence.end()
    }
}

struct Credit(usize);

impl Write for Credit {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0 = self
            .0
            .checked_sub(bytes.len())
            .ok_or_else(|| io::Error::other("profile retention bytes exhausted"))?;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
#[path = "retention_tests.rs"]
mod tests;
