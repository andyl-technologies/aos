//! Retained fixed credential reads under the actual original Root receiving loan.
//!
//! File, allocation, partial buffer and whole read results remain here while
//! the daemon retains its complete credential verification result and performs
//! independent startup-journal posts. Ordinary startup uses its existing reader.

use std::fs::{File, Metadata};
use std::io::{self, Read as _};
use std::path::Path;

use aos_sandbox::normal_root::{
    RootStartupCredentialMemberV1 as Member, RootStartupCredentialReceivingLoanV1 as Loan,
};

use super::{CREDENTIAL_ROOT, read_bounded};

#[derive(Default)]
struct CredentialReadOriginal {
    file: Option<io::Result<File>>,
    bytes: Vec<u8>,
    reservation: Option<Result<(), std::collections::TryReserveError>>,
    read: Option<io::Result<()>>,
    export_reservation: Option<Result<(), std::collections::TryReserveError>>,
    export: Option<Vec<u8>>,
    closed: Option<io::Error>,
    admitted_capacity: usize,
    attempted: bool,
    exported: bool,
}

pub(super) struct RootStartupCredentialReads {
    members: [CredentialReadOriginal; 12],
    retired: [Option<io::Result<Metadata>>; 2],
}

impl Default for RootStartupCredentialReads {
    fn default() -> Self {
        Self { members: std::array::from_fn(|_| CredentialReadOriginal::default()),
               retired: [None, None] }
    }
}

impl RootStartupCredentialReads {
    pub(super) fn failure(&self) -> Option<(&'static str, &(dyn std::error::Error + 'static))> {
        for (member, original) in Member::ALL.into_iter().zip(&self.members) {
            if let Some(cause) = original.failure(member) {
                return Some((member.name(), cause));
            }
        }
        for (name, result) in ["project-head.packet", "project-layer.json"]
            .into_iter().zip(&self.retired)
        {
            if let Some(Err(cause)) = result {
                if cause.kind() != io::ErrorKind::NotFound {
                    return Some((name, cause));
                }
            }
        }
        None
    }

    pub(super) fn read(
        &mut self,
        loan: Option<&Loan<'_>>,
        member: Member,
    ) -> io::Result<Vec<u8>> {
        let path = Path::new(CREDENTIAL_ROOT).join(member.name());
        let Some(loan) = loan.filter(|loan| loan.is_resource_receiving()) else {
            return read_bounded(&path, member.maximum_bytes() as u64);
        };
        loan.require_reading().map_err(io::Error::other)?;
        let original = &mut self.members[member.index()];
        original.observe_once(&path, member.maximum_bytes());
        original.copy_positive_once()
    }

    pub(super) fn optional(
        &mut self,
        loan: Option<&Loan<'_>>,
        member: Member,
    ) -> io::Result<Option<Vec<u8>>> {
        match self.read(loan, member) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error),
        }
    }

    pub(super) fn explicit_project(
        &mut self,
        loan: Option<&Loan<'_>>,
    ) -> io::Result<Option<(Vec<u8>, Vec<u8>)>> {
        // Both original reads precede the unchanged pair classifier, including
        // when the first read fails. Their whole native causes stay in slots.
        let packet = self.read(loan, Member::ProjectHead);
        let input = self.read(loan, Member::ProjectInput);
        match (packet, input) {
            (Ok(packet), Ok(input)) if packet.len() == super::EXPLICIT_PROJECT_PACKET_BYTES => {
                Ok(Some((packet, input)))
            }
            (Err(packet), Err(input)) if packet.kind() == io::ErrorKind::NotFound
                && input.kind() == io::ErrorKind::NotFound => Ok(None),
            _ => Err(io::Error::new(io::ErrorKind::InvalidData,
                "project packet and input credentials must be provisioned together")),
        }
    }

    pub(super) fn require_no_retired(&mut self, loan: Option<&Loan<'_>>) -> io::Result<()> {
        let Some(loan) = loan.filter(|loan| loan.is_resource_receiving()) else {
            return super::require_no_retired_project_credentials(Path::new(CREDENTIAL_ROOT));
        };
        loan.require_reading().map_err(io::Error::other)?;
        for (index, name) in ["project-head.packet", "project-layer.json"].into_iter().enumerate() {
            if self.retired[index].is_some() {
                return Err(io::Error::other("Root retired-credential check repeated"));
            }
            self.retired[index] = Some(std::fs::symlink_metadata(Path::new(CREDENTIAL_ROOT).join(name)));
            match self.retired[index].as_ref() {
                Some(Ok(_)) => return Err(io::Error::new(io::ErrorKind::InvalidData,
                    "retired project source credentials are unsupported")),
                Some(Err(error)) if error.kind() == io::ErrorKind::NotFound => {}
                Some(Err(error)) => return Err(io::Error::new(error.kind(),
                    "Root retired-credential metadata failed")),
                None => return Err(io::Error::other("Root retired-credential result absent")),
            }
        }
        Ok(())
    }
}

impl CredentialReadOriginal {
    fn failure(&self, member: Member) -> Option<&(dyn std::error::Error + 'static)> {
        if let Some(Err(cause)) = &self.file {
            let optional_absence = cause.kind() == io::ErrorKind::NotFound
                && matches!(member, Member::ProjectHead | Member::ProjectInput
                    | Member::CachePin | Member::ControllerPin | Member::SourcePin);
            if !optional_absence {
                return Some(cause);
            }
        }
        self.reservation.as_ref().and_then(|result| result.as_ref().err())
            .map(|cause| cause as &(dyn std::error::Error + 'static))
            .or_else(|| self.read.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| cause as &(dyn std::error::Error + 'static)))
            .or_else(|| self.export_reservation.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| cause as &(dyn std::error::Error + 'static)))
            .or_else(|| self.closed.as_ref().map(|cause| cause as &(dyn std::error::Error + 'static)))
    }

    fn observe_once(&mut self, path: &Path, maximum: usize) {
        if self.attempted {
            self.closed.get_or_insert_with(|| io::Error::other("Root credential read repeated"));
            return;
        }
        self.attempted = true;
        self.file = Some(File::open(path));
        if !matches!(self.file, Some(Ok(_))) {
            return;
        }
        let Some(length) = maximum.checked_add(1) else {
            self.closed = Some(io::Error::other("Root credential bound overflow"));
            return;
        };
        self.reservation = Some(self.bytes.try_reserve_exact(length));
        if !matches!(self.reservation, Some(Ok(()))) {
            return;
        }
        if self.bytes.capacity() > length {
            self.closed = Some(io::Error::other("Root credential reserve exceeds admitted capacity"));
            return;
        }
        self.admitted_capacity = self.bytes.capacity();
        self.bytes.resize(length, 0);
        let mut filled = 0;
        self.read = Some((|| {
            let file = self.file.as_mut().and_then(|result| result.as_mut().ok())
                .ok_or_else(|| io::Error::other("Root credential original absent"))?;
            while filled < length {
                let read = file.read(&mut self.bytes[filled..])?;
                if read == 0 {
                    break;
                }
                filled += read;
            }
            if filled == 0 || filled > maximum {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "credential size"));
            }
            Ok(())
        })());
        self.bytes.truncate(filled);
    }

    fn copy_positive_once(&mut self) -> io::Result<Vec<u8>> {
        if let Some(Err(error)) = &self.file {
            return Err(io::Error::new(error.kind(), "Root original credential open failed"));
        }
        if self.closed.is_some() || self.exported {
            return Err(io::Error::other("Root original credential receiving is closed"));
        }
        if !matches!(self.reservation, Some(Ok(()))) || !matches!(self.read, Some(Ok(()))) {
            let kind = self.read.as_ref().and_then(|result| result.as_ref().err())
                .map_or(io::ErrorKind::Other, io::Error::kind);
            return Err(io::Error::new(kind, "Root original credential read failed"));
        }

        self.export = Some(Vec::new());
        let export = self.export.as_mut().ok_or_else(|| io::Error::other("Root credential destination absent"))?;
        self.export_reservation = Some(export.try_reserve_exact(self.bytes.len()));
        if !matches!(self.export_reservation, Some(Ok(()))) || export.capacity() > self.bytes.len() {
            self.closed = Some(io::Error::other("Root credential copy reserve failed"));
            return Err(io::Error::other("Root credential copy reserve failed"));
        }
        export.extend_from_slice(&self.bytes);
        self.exported = true;
        self.export.take().ok_or_else(|| io::Error::other("Root credential copy absent"))
    }
}
