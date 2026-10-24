//! Exercises caller-owned audit refusal before any namespace effect.

use std::cell::Cell;

use super::*;

struct RefusedAudit {
    checks: Cell<u64>,
}

impl QuotaAudit for RefusedAudit {
    fn check(&self) -> Result<(), QuotaAuditRefusal> {
        self.checks.set(self.checks.get() + 1);
        Err(QuotaAuditRefusal)
    }

    fn progress(&self, _: u64) -> Result<(), QuotaAuditRefusal> {
        panic!("a refused audit cannot reach inventory progress")
    }
}

#[test]
fn original_refusal_precedes_kernel_access_and_project_admission() {
    let root = tempfile::tempdir().unwrap();
    let audit = RefusedAudit {
        checks: Cell::new(0),
    };
    let admitted = Cell::new(false);
    let mut admission = |_| {
        admitted.set(true);
        Ok(())
    };

    let result = AuditedProjectQuotaBinding::bind_existing_audited(
        root.path(),
        701,
        16 << 20,
        16,
        &audit,
        true,
        Some(&mut admission),
    );

    assert!(matches!(
        result,
        Err(LinuxProjectQuotaError::AuditRefused(QuotaAuditRefusal))
    ));
    assert_eq!(audit.checks.get(), 1);
    assert!(!admitted.get());
    assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 0);
}
