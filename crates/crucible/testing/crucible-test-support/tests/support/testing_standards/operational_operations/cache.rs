//! Checked caller and service custody for shared Packed metadata waits.

use super::{Companion, Contract};

pub(super) const CONTRACTS: &[Contract] = &[
    Contract {
        package: "crucible-store",
        target: "src/content_store/packed/shared_cache",
        required: &[
            (
                r#"fn check(&mut self) -> Result<(), StoreError> { checked_reader::check(self.original, self.boundary) }"#,
                1,
            ),
            (
                r#"loop { read.check()?; match self.state.try_lock() { Ok(state) => return Ok(state), Err(TryLockError::WouldBlock) => read.wait()?, Err(TryLockError::Poisoned(_)) => return Err(StoreError::Unauthorized), } }"#,
                1,
            ),
            (
                r#"fn wait(&mut self) -> Result<(), StoreError> { self.check()?;"#,
                1,
            ),
            (r#"from_millis(1)); self.check() }"#, 1),
            (r#"drop(state); self.wait()?; continue;"#, 1),
            (
                r#"let mut pending = PendingFill { cache, rows: row_bytes, directory: directory_bytes, active: true, };"#,
                1,
            ),
            (
                r#"let directory_credit = reserve(directory_bytes.checked_sub(cache.credit_bytes).ok_or(StoreError::Quota)?, &mut || self.check(), )?; self.check()?;"#,
                1,
            ),
            (
                r#"let row_credit = reserve(row_bytes.checked_sub(cache.credit_bytes).ok_or(StoreError::Quota)?, &mut || self.check(), )?; self.check()?;"#,
                1,
            ),
            (
                r#"impl<Credit> Drop for PendingFill<'_, Credit> { fn drop(&mut self) { if self.active { self.cache.pending_rows.fetch_sub(self.rows, AtomicOrdering::AcqRel); self.cache.pending_directory.fetch_sub(self.directory, AtomicOrdering::AcqRel); } } }"#,
                1,
            ),
            (
                r#"impl<Credit> Drop for Rows<Credit> { fn drop(&mut self) { drop(self.manifest.take()); } }"#,
                1,
            ),
            (r#"drop(std::mem::take(&mut self.entries));"#, 1),
            (
                r#"while let Some(mut owner) = self.directory_credits.take() { self.directory_credits = owner.body_mut().next.take(); drop(owner); }"#,
                1,
            ),
            (
                r#"drop(state); drop(rows); drop(directory); drop(pending);"#,
                1,
            ),
            (r#"pending.active = false; drop(state);"#, 1),
            (r#"HostOperationSupervisor::new("#, 0),
            (r#"Instant::now("#, 0),
            (r#"HostOperationClass::Preparation"#, 0),
        ],
        expressions: &[(
            r#"std::thread::sleep(std::time::Duration::from_millis(1));"#,
            1,
        )],
        identifiers: &[],
        companions: &[
            Companion {
                path: "crates/crucible/control/crucible-daemon/src/campaign_store_quota.rs",
                required: &[
                    (r#"mod metadata;"#, 1),
                    (
                        r#"request.retain_in(&service.packed_metadata, |bytes, check| { service.reserve_metadata_checked(bytes, Some(check)) })?;"#,
                        1,
                    ),
                    (r#"HostServiceLease::close_pair(resident, metadata);"#, 1),
                    (r#"HostOperationSupervisor::new("#, 1),
                    (r#".begin(HostOperationClass::Preparation)"#, 3),
                    (r#"Instant::now("#, 0),
                ],
            },
            Companion {
                path: "crates/crucible/control/crucible-daemon/src/campaign_store_quota/metadata.rs",
                required: &[
                    (
                        r#"pub(super) fn reserve_metadata_checked(&self, bytes: u64, mut caller: Option<&mut dyn FnMut() -> Result<(), StoreError>>, )"#,
                        1,
                    ),
                    (
                        r#"if let Some(check) = caller.as_mut() { check()?; } let operation = self.supervisor.begin(HostOperationClass::Preparation).map_err(supervision_error)?;"#,
                        1,
                    ),
                    (
                        r#"if let Err(first) = check() { caller_failure = Some(first);"#,
                        1,
                    ),
                    (
                        r#"let reservation = self.reserve_precharged_metadata(charged, &operation, &mut check); drop(check); if let Some(first) = caller_failure { return Err(first); }"#,
                        1,
                    ),
                    (
                        r#"let caller_post = match caller.as_mut() { Some(check) => check(), None => Ok(()), }; let service_post = credit.complete(&operation); caller_post?; service_post"#,
                        1,
                    ),
                    (
                        r#"pub(super) fn reserve_precharged_metadata(&self, charged: u64, operation: &HostOperationGuard, caller: &mut dyn FnMut() -> Result<(), ProviderCause>, )"#,
                        1,
                    ),
                    (r#"loop { operation.wait_slice()?; caller()?;"#, 1),
                    (
                        r#"Err(TryLockError::Poisoned(_)) => return Err(HostServiceError::Unavailable.into()),"#,
                        1,
                    ),
                    (
                        r#"None => { contended = true; Err(HostServiceError::Unavailable) }"#,
                        1,
                    ),
                    (r#"drop(admission); if contended {"#, 1),
                    (
                        r#"let (metadata, resident) = reservation?; return Ok(QuotaMetadataCredit::new(resident, metadata));"#,
                        1,
                    ),
                    (r#"HostOperationSupervisor::new("#, 0),
                    (r#".begin(HostOperationClass::Preparation)"#, 1),
                    (r#"Instant::now("#, 0),
                ],
            },
            Companion {
                path: "crates/crucible/storage/crucible-store/src/content_store/checked_reader.rs",
                required: &[(
                    r#"original.verify_live().map_err(|error| batch::admission_under(original, error))?; boundary()?; original.verify_live().map_err(|error| batch::admission_under(original, error))"#,
                    1,
                )],
            },
            Companion {
                path: "crates/crucible/storage/crucible-store/src/content_store/packed/read_view/manifest.rs",
                required: &[
                    (
                        r#"if count != paid_rows { return Err(StoreError::Corrupt { id }); }"#,
                        1,
                    ),
                    (
                        r#"if entries.capacity() != count { return Err(StoreError::Quota); } checked_reader::check(original, boundary)?; Ok(ManifestCopy {"#,
                        1,
                    ),
                    (
                        r#"if entries.capacity() != count { return Err(StoreError::Quota); } checked::authenticate_manifest_into("#,
                        1,
                    ),
                    (
                        r#"if entries.len() != count || FileStamp::read(file, original, boundary)? != stamp { return Err(StoreError::Corrupt { id }); }"#,
                        1,
                    ),
                ],
            },
        ],
    },
    Contract {
        package: "crucible-daemon",
        target: "src/campaign_store_quota/metadata",
        required: &[
            (
                r#"pub(super) fn reserve_metadata_checked(&self, bytes: u64, mut caller: Option<&mut dyn FnMut() -> Result<(), StoreError>>, )"#,
                1,
            ),
            (
                r#"if let Some(check) = caller.as_mut() { check()?; } let operation = self.supervisor.begin(HostOperationClass::Preparation).map_err(supervision_error)?;"#,
                1,
            ),
            (
                r#"if let Err(first) = check() { caller_failure = Some(first);"#,
                1,
            ),
            (
                r#"let reservation = self.reserve_precharged_metadata(charged, &operation, &mut check); drop(check); if let Some(first) = caller_failure { return Err(first); }"#,
                1,
            ),
            (
                r#"let caller_post = match caller.as_mut() { Some(check) => check(), None => Ok(()), }; let service_post = credit.complete(&operation); caller_post?; service_post"#,
                1,
            ),
            (
                r#"pub(super) fn reserve_precharged_metadata(&self, charged: u64, operation: &HostOperationGuard, caller: &mut dyn FnMut() -> Result<(), ProviderCause>, )"#,
                1,
            ),
            (r#"loop { operation.wait_slice()?; caller()?;"#, 1),
            (
                r#"Err(TryLockError::Poisoned(_)) => return Err(HostServiceError::Unavailable.into()),"#,
                1,
            ),
            (
                r#"None => { contended = true; Err(HostServiceError::Unavailable) }"#,
                1,
            ),
            (r#"drop(admission); if contended {"#, 1),
            (
                r#"let (metadata, resident) = reservation?; return Ok(QuotaMetadataCredit::new(resident, metadata));"#,
                1,
            ),
            (r#".begin(HostOperationClass::Preparation)"#, 1),
            (r#"Instant::now("#, 0),
            (r#"HostOperationSupervisor::new("#, 0),
        ],
        expressions: &[(r#"std::thread::sleep(Duration::from_millis(1));"#, 2)],
        identifiers: &[],
        companions: &[
            Companion {
                path: "crates/crucible/control/crucible-daemon/src/campaign_store_quota.rs",
                required: &[
                    (r#"mod metadata;"#, 1),
                    (
                        r#"request.retain_in(&service.packed_metadata, |bytes, check| { service.reserve_metadata_checked(bytes, Some(check)) })?;"#,
                        1,
                    ),
                    (r#"HostServiceLease::close_pair(resident, metadata);"#, 1),
                    (r#"HostOperationSupervisor::new("#, 1),
                    (r#".begin(HostOperationClass::Preparation)"#, 3),
                    (r#"Instant::now("#, 0),
                ],
            },
            Companion {
                path: "crates/crucible/storage/crucible-store/src/content_store/packed/shared_cache.rs",
                required: &[
                    (
                        r#"fn check(&mut self) -> Result<(), StoreError> { checked_reader::check(self.original, self.boundary) }"#,
                        1,
                    ),
                    (
                        r#"loop { read.check()?; match self.state.try_lock() { Ok(state) => return Ok(state), Err(TryLockError::WouldBlock) => read.wait()?, Err(TryLockError::Poisoned(_)) => return Err(StoreError::Unauthorized), } }"#,
                        1,
                    ),
                    (
                        r#"fn wait(&mut self) -> Result<(), StoreError> { self.check()?;"#,
                        1,
                    ),
                    (r#"from_millis(1)); self.check() }"#, 1),
                    (r#"drop(state); self.wait()?; continue;"#, 1),
                    (
                        r#"let mut pending = PendingFill { cache, rows: row_bytes, directory: directory_bytes, active: true, };"#,
                        1,
                    ),
                    (
                        r#"let directory_credit = reserve(directory_bytes.checked_sub(cache.credit_bytes).ok_or(StoreError::Quota)?, &mut || self.check(), )?; self.check()?;"#,
                        1,
                    ),
                    (
                        r#"let row_credit = reserve(row_bytes.checked_sub(cache.credit_bytes).ok_or(StoreError::Quota)?, &mut || self.check(), )?; self.check()?;"#,
                        1,
                    ),
                    (
                        r#"impl<Credit> Drop for PendingFill<'_, Credit> { fn drop(&mut self) { if self.active { self.cache.pending_rows.fetch_sub(self.rows, AtomicOrdering::AcqRel); self.cache.pending_directory.fetch_sub(self.directory, AtomicOrdering::AcqRel); } } }"#,
                        1,
                    ),
                    (
                        r#"impl<Credit> Drop for Rows<Credit> { fn drop(&mut self) { drop(self.manifest.take()); } }"#,
                        1,
                    ),
                    (r#"drop(std::mem::take(&mut self.entries));"#, 1),
                    (
                        r#"while let Some(mut owner) = self.directory_credits.take() { self.directory_credits = owner.body_mut().next.take(); drop(owner); }"#,
                        1,
                    ),
                    (
                        r#"drop(state); drop(rows); drop(directory); drop(pending);"#,
                        1,
                    ),
                    (r#"pending.active = false; drop(state);"#, 1),
                ],
            },
            Companion {
                path: "crates/crucible/host/crucible-host-resources/src/host_services.rs",
                required: &[
                    (r#"let _freed = reclaim(required)?;"#, 1),
                    (r#"self.reserve_paired_bytes(other, bytes)"#, 1),
                    (
                        r#"let first = self.reserve_completed(0, 0, bytes, std::convert::identity)?; let second = other.reserve_completed(0, 0, bytes, std::convert::identity)?; Ok((first.into_lease(), second.into_lease()))"#,
                        1,
                    ),
                ],
            },
        ],
    },
];
