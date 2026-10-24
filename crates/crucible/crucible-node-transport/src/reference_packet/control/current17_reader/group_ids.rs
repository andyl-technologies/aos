//! Returns same-pass Control and Hold identities without building typed payloads.

use super::*;

/// Retains independently validated native Control edges in either read pass.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CurrentControl17GroupIds {
    pub(crate) capture_identity: usize,
    pub(crate) hold: Option<usize>,
    pub(crate) evidence: Option<(usize, usize, usize)>,
}

/// Retains the exact full Hold group and its original Control identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CurrentControlHold17GroupIds {
    pub(crate) hold: usize,
    pub(crate) capture_identity: usize,
}

/// Reads the rooted Control and returns its actual groups in the same pass.
///
/// # Errors
/// Refuses wrong roles, incomplete typed fields, or source metadata/alias limits.
pub(crate) fn read_current_rooted_control17_fields_data(
    spans: &crate::protocol_snapshot::native_wholegraph17::NativeCurrentGraph17RootSpans<'_>,
    ledger: &mut Ledger<'_, '_, '_>,
    build: bool,
) -> Result<(Option<CurrentControl17Data>, CurrentControl17GroupIds), ProviderError> {
    CurrentControl17Data::read_encoding_fields_data(
        spans.control_data(),
        ledger,
        build,
        ControlEncoding17::Rooted {
            hold: spans.hold_data(),
        },
    )
}

/// Reads the defining full Hold with same-pass group output and no rescan.
///
/// # Errors
/// Refuses malformed fields, changed shared payloads or exact row disagreement.
pub(crate) fn read_current_control_hold_root17_fields_data(
    input: &[u8],
    ledger: &mut Ledger<'_, '_, '_>,
    build: bool,
) -> Result<
    (
        Option<CurrentControlHold17Data>,
        CurrentControlHold17GroupIds,
    ),
    ProviderError,
> {
    CurrentControlHold17Data::read_fields_data(input, ledger, build)
}

impl CurrentControl17Data {
    /// Returns the same identities validated while reading this retained owner.
    pub(crate) fn group_ids_data(&self) -> CurrentControl17GroupIds {
        CurrentControl17GroupIds {
            capture_identity: self.capture_identity_role.group,
            hold: self.complete_restored_hold.as_ref().map(|hold| hold.group),
            evidence: self
                .complete_restored_evidence
                .as_ref()
                .map(|evidence| (evidence.boot, evidence.commit, evidence.hold)),
        }
    }
}

impl CurrentControlHold17Data {
    /// Returns both checked identities of this complete historical Hold.
    pub(crate) const fn group_ids_data(&self) -> CurrentControlHold17GroupIds {
        CurrentControlHold17GroupIds {
            hold: self.group,
            capture_identity: self.control_identity_role.group,
        }
    }
}
