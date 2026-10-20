//! One same-original, argv9-bound paid template observation.
//!
//! Only the real Storage receiving original can create the guard. The reached
//! scanner borrows that SAME ledger directly; no copied ceiling or second
//! account funds the scan. Independent original posts run before any earlier
//! accounting/tree failure is projected into the sticky receiving state.

use super::*;
use std::path::Path;
use aos_sandbox_guest_root_tree::guest_root_tree::{
    GuestRootTreeErrorV1, GuestRootTemplateComparisonDataV2, compare_guest_root_template_receiving_observed_v2,
};

// The measured twelve-argument producer has the template at index9,
// hold-key profile at10 and optional output-key source at11. Share this one
// lookup across initial admission and later same-template currentness joins.
fn template_package_argument_v1(arguments: &[String]) -> Option<&Path> {
    arguments.get(9).map(Path::new)
}

pub(super) struct GuestRootTemplateReceivingV1 {
    entered: bool,
    positive: bool,
    comparison: Option<Result<GuestRootTemplateComparisonDataV2, GuestRootTreeErrorV1>>,
    post: Option<NativeResult>,
}

impl GuestRootTemplateReceivingV1 {
    pub(super) const fn new() -> Self {
        Self {
            entered: false,
            positive: false,
            comparison: None,
            post: None,
        }
    }

    pub(super) fn positive(&self) -> bool {
        self.positive
    }

    pub(super) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.comparison.as_ref().and_then(|result| result.as_ref().err())
            .map(|cause| cause as &dyn Error)
            .or_else(|| native_failure(&self.post))
    }
}

/// Borrows one actual argv9 template observation and its original payer.
///
/// Dropping an unfinished observation closes the original. A tree's digest is
/// measurement DATA; the protected upper owner still checks its package binding
/// and expected digest and retains every actual upper failure.
#[must_use]
pub struct StorageGuestRootTemplateReceivingLoanV1<'cut, 'original> {
    receiving: &'cut mut StoragePrepareReceivingLoanV1<'original>,
    package: &'cut Path,
    finished: bool,
}

impl<'original> StoragePrepareReceivingLoanV1<'original> {
    /// Pays fixed upper template work and joins the actual captured argv9.
    ///
    /// Both independently captured PID1 property flights must name this exact
    /// package. `upper` is the concrete upper owner's DATA demand, not authority.
    /// Variable names/path/model growth is charged separately by the shared
    /// scanner before it grows, through this same original's actual ledger.
    ///
    /// # Errors
    ///
    /// Refuses reentry, changed original custody, argument mismatch or any
    /// earlier accounting/native failure; all earlier obligations stay charged.
    pub fn borrow_guest_root_template_once_v1<'cut>(
        &'cut mut self,
        package: &'cut Path,
        upper: ResourceVector,
    ) -> Result<StorageGuestRootTemplateReceivingLoanV1<'cut, 'original>, StorageReceivingClosedV1> {
        // Arms and completes the existing prepaid currentness pool before the
        // scan. Its independent post can therefore run without a new debit even
        // if the scanner later refuses a dominant allocation obligation.
        self.original.recheck().map_err(|_| StorageReceivingClosedV1)?;
        let receiving = self.receiving()?;
        if receiving.template.entered {
            receiving.first.get_or_insert(Failure::Closed);
            return Err(StorageReceivingClosedV1);
        }
        receiving.template.entered = true;
        let same_argument = |result: &Option<ParentResult>| {
            result.as_ref().and_then(|result| result.as_ref().ok())
                .and_then(|parent| template_package_argument_v1(parent.0.arguments()))
                .is_some_and(|argument| argument == package)
        };
        if !same_argument(&receiving.before) || !same_argument(&receiving.after) {
            receiving.first.get_or_insert(Failure::Closed);
            return Err(StorageReceivingClosedV1);
        }
        receiving.reserve(upper)?;
        Ok(StorageGuestRootTemplateReceivingLoanV1 {
            receiving: self,
            package,
            finished: false,
        })
    }
}

impl StoragePrepareReceivingLoanV1<'_> {
    /// Joins the upper template to the same completed actual argv9 scan.
    ///
    /// # Errors
    ///
    /// Refuses a different package/root, digest, original or unfinished scan.
    /// This restricts the existing concrete template; it creates no template.
    pub fn require_guest_root_template_v1(
        &mut self,
        root: &Path,
        digest: &[u8; 32],
    ) -> Result<(), StorageReceivingClosedV1> {
        self.original.recheck().map_err(|_| StorageReceivingClosedV1)?;
        let receiving = self.receiving()?;
        let joined = |result: &Option<ParentResult>| {
            result.as_ref().and_then(|result| result.as_ref().ok())
                .and_then(|parent| template_package_argument_v1(parent.0.arguments()))
                .is_some_and(|argument| root.parent() == Some(argument)
                    && root.file_name() == Some(std::ffi::OsStr::new("root")))
        };
        if !receiving.template.positive
            || !joined(&receiving.before)
            || !joined(&receiving.after)
            || !matches!(receiving.template.comparison, Some(Ok(observed)) if &observed.digest_v2() == digest)
        {
            receiving.first.get_or_insert(Failure::Closed);
            return Err(StorageReceivingClosedV1);
        }
        Ok(())
    }
}

impl StorageGuestRootTemplateReceivingLoanV1<'_, '_> {
    /// Measures the fixed `root` beneath that same actual package once.
    ///
    /// # Errors
    ///
    /// Keeps the complete tree/native Result and the actual ledger's first
    /// accounting refusal on their original owners. No replacement account,
    /// caller path or detached resource permit can enter the scanner.
    pub fn measure_once_v1(&mut self) -> Result<[u8; 32], StorageReceivingClosedV1> {
        let receiving = self.receiving.receiving()?;
        if receiving.template.comparison.is_some() {
            receiving.first.get_or_insert(Failure::Closed);
            return Err(StorageReceivingClosedV1);
        }
        let root = self.package.join("root");
        receiving.template.comparison = Some(compare_guest_root_template_receiving_observed_v2(
            &root, &root, &mut receiving.ledger,
        ));
        match receiving.template.comparison.as_ref() {
            Some(Ok(observed)) => Ok(observed.digest_v2()),
            _ => Err(StorageReceivingClosedV1),
        }
    }

    /// Borrows shape DATA from this actual already-entered scan, without IO.
    ///
    /// # Errors
    /// Refuses an absent or negative comparison on the same original.
    pub fn comparison_census_data_v2(&mut self) -> Result<GuestRootTemplateComparisonDataV2, StorageReceivingClosedV1> {
        self.receiving.receiving()?.template.comparison.as_ref()
            .and_then(|result| result.as_ref().ok()).copied().ok_or(StorageReceivingClosedV1)
    }

    /// Retains the independent original post even after an upper/tree refusal.
    ///
    /// Callers park their complete upper Result before this post. A missing or
    /// failed comparison never becomes positive. This completes only receiving
    /// bookkeeping; it does not accept the upper expected-digest comparison.
    ///
    /// # Errors
    ///
    /// Refuses missing/failed measurement or post, preserving the earlier exact
    /// accounting/tree cause ahead of later currentness debt. There is no retry.
    pub fn finish_once_v1(&mut self) -> Result<(), StorageReceivingClosedV1> {
        if self.finished {
            return Err(StorageReceivingClosedV1);
        }
        self.finished = true;
        let post = self.receiving.original.recheck();
        let Some(StorageResourceRecipientCustodyV1::Receiving { receiving, .. }) =
            self.receiving.original.recipient.as_mut()
        else {
            return Err(StorageReceivingClosedV1);
        };
        let accounting_failed = receiving.ledger.failure().is_some();
        let tree_failed = !matches!(receiving.template.comparison, Some(Ok(_)));
        receiving.template.post = Some(post);
        receiving.template.positive = !accounting_failed && !tree_failed
            && matches!(receiving.template.post, Some(Ok(()))) && receiving.first.is_none();
        if accounting_failed {
            receiving.first = Some(Failure::Accounting);
        } else if tree_failed {
            // The actual tree failure preceded the independent post; retain
            // both and project the earlier one. Upper parse errors stay upper.
            receiving.first = Some(Failure::Template);
        } else if !receiving.template.positive {
            receiving.first.get_or_insert(Failure::Template);
        }
        if receiving.template.positive {
            Ok(())
        } else {
            Err(StorageReceivingClosedV1)
        }
    }
}

impl Drop for StorageGuestRootTemplateReceivingLoanV1<'_, '_> {
    fn drop(&mut self) {
        if !self.finished {
            self.receiving.original.open = false;
            if let Some(StorageResourceRecipientCustodyV1::Receiving { receiving, .. }) =
                self.receiving.original.recipient.as_mut()
            {
                receiving.first.get_or_insert(Failure::Template);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn measured_storage_roster_keeps_template_separate_from_output_key() {
        // This is passive roster DATA copied from the actual fixed Nix
        // ExecStart producer; it cannot create a recipient or receiving loan.
        let mut arguments = [
            "/nix/store/storage/bin/aos-storaged", "0", "0", "100000", "64",
            "/nix/store/zfs/sbin/zfs", "/run/credentials/storage", "/bootstrap",
            "-", "/nix/store/guest-template", "-", "-",
        ].map(str::to_owned);

        assert_eq!(template_package_argument_v1(&arguments),
            Some(Path::new("/nix/store/guest-template")));
        arguments[10] = "zfs-hold-key-v1".to_owned();
        arguments[11] = "/private/output-key".to_owned();
        assert_eq!(template_package_argument_v1(&arguments),
            Some(Path::new("/nix/store/guest-template")));
        assert_ne!(template_package_argument_v1(&arguments), Some(Path::new(&arguments[11])));
        assert!(template_package_argument_v1(&arguments[..9]).is_none());
    }
}
