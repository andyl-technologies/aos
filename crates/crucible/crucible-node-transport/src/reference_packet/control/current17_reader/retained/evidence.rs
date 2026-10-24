//! Keeps every completed evidence role in its supplied concrete attempt.

use super::*;

#[derive(Default)]
pub(super) struct CurrentEvidence17ReadAttempt {
    started: bool,
    pub(super) completed: Option<CurrentEvidence17Data>,
    boot: Option<usize>,
    commit: Option<usize>,
    hold: Option<usize>,
}

impl CurrentEvidence17ReadAttempt {
    pub(super) fn read_into(
        &mut self,
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<(usize, usize, usize), ProviderError> {
        use crate::reference_packet::service::ack_emitter::NativeAckBoot;
        if self.started {
            return Err(ProviderError::Conflict(
                "native17 evidence read already attempted",
            ));
        }
        self.started = true;
        let mut fields = Fields::object(input)?;
        ledger.read::<EvidenceSchema17>(fields.named("schema")?, false)?;
        self.boot = Some(reference_role(
            fields.named("boot_role")?,
            "native-boot",
            MetadataSharedKind::NativeBoot,
            NativeAckBoot::current_boot_shared_layout17_data(),
            ledger,
        )?);
        self.commit = Some(reference_role(
            fields.named("commit_role")?,
            "native-complete-restore-commit",
            MetadataSharedKind::NativeRestoreCommitAttempt,
            NativeAckBoot::current_commit_shared_layout17_data(),
            ledger,
        )?);
        self.hold = Some(reference_role(
            fields.named("hold_role")?,
            "native-complete-restore-physical-hold",
            MetadataSharedKind::NativeRestoredPhysicalHold,
            (
                size_of::<PacketCompleteRestorePhysicalHold>(),
                align_of::<PacketCompleteRestorePhysicalHold>(),
            ),
            ledger,
        )?);
        fields.finish()?;
        let groups = (
            self.boot.ok_or_else(invalid)?,
            self.commit.ok_or_else(invalid)?,
            self.hold.ok_or_else(invalid)?,
        );
        if build {
            self.completed = Some(CurrentEvidence17Data {
                boot: groups.0,
                commit: groups.1,
                hold: groups.2,
            });
        }
        Ok(groups)
    }
}
