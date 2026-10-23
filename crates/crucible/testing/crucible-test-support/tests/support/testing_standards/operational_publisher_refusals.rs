//! Binds publisher refusal observations to once-owned production state.
//!
//! Component fixtures own real kernel roles or borrowed native ABI views. They
//! grant no Source, Native membership, command loan or physical-return authority.

use super::{Companion, Contract};

const MAPPING_REFUSAL: &str = r#"fn uncertain_mapping_disposition_refuses_retry_and_retains_every_physical_role() {
    let mut body = physical_fixture();
    body.construct_with(|| Ok(()), header()).unwrap();
    body.mapping_return_uncertain = true;
    let mapping = body.mapping;

    assert!(!body.return_physical(false));
    assert!(!body.return_physical(false));
    assert_eq!(body.mapping, mapping);
    assert!(body.roles.iter().all(Option::is_some));

    // The test has not called munmap; clear only this injected component fact
    // to dispose its known-live fixture. Production never resets uncertainty.
    body.mapping_return_uncertain = false;
    assert!(body.return_physical(false));
}"#;

const PHYSICAL_FIXTURE: &str = r#"pub(super) fn physical_fixture() -> SessionBody<()> {
    SessionBody {
        roles: std::array::from_fn(|_| None),
        closing_roles: [None; 3],
        fdinfo: None,
        closing_fdinfo: None,
        mapping: None,
        mapping_return_uncertain: false,
        exported: false,
        purpose: None,
        failure: None,
        original_after: None,
        command: command::CommandJournal::default(),
        _custody: (),
    }
}"#;

const PHYSICAL_RETURN: &str = r#"fn return_physical(&mut self, cleanup_proven: bool) -> bool {
        if self.mapping_return_uncertain
            || self.closing_roles.iter().any(Option::is_some)
            || self.closing_fdinfo.is_some()
            || (self.exported && !cleanup_proven)
        {
            return false;
        }
        if let Some(address) = self.mapping.take() {
            // SAFETY: the exact journaled mapping has no remaining host users.
            // Failure keeps its address and complete paid body without retry.
            if unsafe { libc::munmap(address as *mut libc::c_void, PUBLISHER_REGION_BYTES) } != 0 {
                self.mapping = Some(address);
                self.mapping_return_uncertain = true;
                return false;
            }
        }
        if let Some(file) = self.fdinfo.take() {
            let descriptor = file.into_raw_fd();
            self.closing_fdinfo = Some(descriptor);
            if crate::spawn::close_child_source_fd(descriptor).is_err() {
                return false;
            }
            self.closing_fdinfo = None;
        }
        for (index, role) in self.roles.iter_mut().enumerate() {
            if let Some(role) = role.take() {
                let descriptor = role.into_raw_fd();
                self.closing_roles[index] = Some(descriptor);
                if crate::spawn::close_child_source_fd(descriptor).is_err() {
                    return false;
                }
                self.closing_roles[index] = None;
            }
        }
        true
    }"#;

const PHYSICAL_BIRTH: &str = r#"fn construct_with(
        &mut self,
        mut original: impl FnMut() -> Result<(), HostSupervisionError>,
        header: PublisherHeader,
    ) -> Result<(), PublisherSessionError> {
        if let Some(cause) = self.failure {
            return Err(self.error(cause));
        }
        if self.roles.iter().any(Option::is_some) || self.mapping.is_some() {
            return Err(geometry_error());
        }
        let result = (|| {
            let bytes = header.encode().map_err(|_| OperationFailure::Geometry)?;
            let mut check = || original().map_err(OperationFailure::Original);
            check()?;
            self.roles[0] = Some(
                rustix::fs::memfd_create(
                    c"crucible-publisher-session",
                    rustix::fs::MemfdFlags::CLOEXEC | rustix::fs::MemfdFlags::ALLOW_SEALING,
                )
                .map_err(OperationFailure::Kernel)?,
            );
            check()?;
            let region = self.roles[0].as_ref().ok_or(OperationFailure::Geometry)?;
            rustix::fs::ftruncate(region, PUBLISHER_REGION_BYTES as u64)
                .map_err(OperationFailure::Kernel)?;
            check()?;
            let mut offset = 0;
            while offset < bytes.len() {
                check()?;
                let count = rustix::io::pwrite(region, &bytes[offset..], offset as u64)
                    .map_err(OperationFailure::Kernel)?;
                check()?;
                if count == 0 {
                    return Err(OperationFailure::Geometry);
                }
                offset += count;
            }
            let seals = rustix::fs::SealFlags::SEAL
                | rustix::fs::SealFlags::SHRINK
                | rustix::fs::SealFlags::GROW;
            check()?;
            rustix::fs::fcntl_add_seals(region, seals).map_err(OperationFailure::Kernel)?;
            check()?;
            if rustix::fs::fcntl_get_seals(region).map_err(OperationFailure::Kernel)? != seals {
                return Err(OperationFailure::Geometry);
            }
            check()?;
            // SAFETY: the retained regular memfd has the exact fixed extent.
            // Record the output before any independent Original observation.
            let pointer = unsafe {
                libc::mmap(
                    std::ptr::null_mut(),
                    PUBLISHER_REGION_BYTES,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_SHARED,
                    region.as_raw_fd(),
                    0,
                )
            };
            if pointer == libc::MAP_FAILED {
                return Err(observation_error(std::io::Error::last_os_error()));
            }
            self.mapping = Some(pointer as usize);
            check()?;
            // SAFETY: this exact new mapping is still retained in the journal.
            if unsafe { libc::madvise(pointer, PUBLISHER_REGION_BYTES, libc::MADV_DONTFORK) } != 0 {
                return Err(observation_error(std::io::Error::last_os_error()));
            }
            check()?;
            let stat = rustix::fs::fstat(region).map_err(OperationFailure::Kernel)?;
            check()?;
            for index in 1..3 {
                self.roles[index] = Some(
                    rustix::event::eventfd(
                        0,
                        rustix::event::EventfdFlags::CLOEXEC
                            | rustix::event::EventfdFlags::NONBLOCK,
                    )
                    .map_err(OperationFailure::Kernel)?,
                );
                check()?;
            }
            let producer_event = self.event_identity(&mut original, 1)?;
            let receiver_event = self.event_identity(&mut original, 2)?;
            let purpose = PublisherPurpose {
                lender_generation: header.lender_generation,
                account_generation: header.account_generation,
                process_generation: header.process_generation,
                capability: header.capability,
                reservation: header.reservation,
                device: stat.st_dev,
                inode: stat.st_ino,
                producer_event,
                receiver_event,
                backing_bytes: backing_bytes().ok_or(OperationFailure::Geometry)?,
            };
            purpose.encode().map_err(|_| OperationFailure::Geometry)?;
            self.purpose = Some(purpose);
            Ok(())
        })();
        self.finish(result, original().err())
    }"#;

const COMMAND_REFUSAL: &str = r#"fn invalid_command_preflight_preserves_actual_region_and_cannot_retry_birth() {
    for changed in 0..14 {
        let mut body = ready_session();
        let before = region_bytes(&body);
        let mut offer = publication();
        match changed {
            0 => offer.sequence = 4,
            1 => offer.offer_generation = 2,
            2 => offer.ticket_serial = 2,
            3 => offer.permission = PublisherPermission::Revoked,
            4 => offer.command = None,
            5 => offer.cohort.cohort_current = false,
            6 => offer.cohort.row_count = 0,
            7 => offer.cohort.borrowed_mask = 0,
            8 => offer.cohort.projected_mask = 0,
            9 => offer.cohort.parents[0].state = 3,
            10 => offer.cohort.binding.cap = [8; 32],
            11 => offer.cohort.binding.reservation = [8; 32],
            12 => offer.cohort.binding.account_generation = 4,
            13 => offer.cohort.binding.process_generation = 8,
            _ => unreachable!(),
        }

        assert!(body.publish_command_offer(offer).is_err(), "case {changed}");
        assert!(body.command.offer.is_none(), "case {changed}");
        assert!(body.command.first.is_some(), "case {changed}");
        assert!(body.publish_command_offer(publication()).is_err());
        assert_eq!(region_bytes(&body), before, "case {changed}");
        assert!(body.return_physical(true));
    }
}"#;

const COMMAND_FIXTURE: &str = r#"pub(super) fn ready_session() -> SessionBody<()> {
    let mut body = physical_fixture();
    body.construct_with(|| Ok(()), header()).unwrap();
    // Exercise the physical component after its export cut. This field does
    // not supply a real remote borrower or a production cleanup receipt.
    body.exported = true;
    body
}"#;

const COMMAND_PUBLISH: &str = r#"pub(super) fn publish_command_offer(
        &mut self,
        publication: PublisherPublication,
    ) -> Result<PublisherLoanIdentity, OperationFailure> {
        let result = self.publish_command_offer_inner(publication);
        if let Err(first) = result {
            self.command.first.get_or_insert(first);
        }
        result
    }"#;

const COMMAND_PREFLIGHT: &str = r#"fn publish_command_offer_inner(
        &mut self,
        publication: PublisherPublication,
    ) -> Result<PublisherLoanIdentity, OperationFailure> {
        if self.command.first.is_some()
            || self.command.offer.is_some()
            || self.failure.is_some()
            || self.original_after.is_some()
            || !self.exported
            || publication.sequence != 2
            || publication.offer_generation != 1
            || publication.ticket_serial != 1
            || publication.permission != PublisherPermission::Borrowable
            || publication.command.is_none()
            || !publication.cohort.cohort_current
            || !(1..=4).contains(&publication.cohort.row_count)
            || publication.cohort.borrowed_mask != (1 << publication.cohort.row_count) - 1
            || publication.cohort.projected_mask != publication.cohort.borrowed_mask
            || publication.cohort.parents[..publication.cohort.row_count as usize]
                .iter()
                .any(|row| row.state != 0)
        {
            return Err(OperationFailure::Geometry);
        }
        let bytes = publication
            .encode()
            .map_err(|_| OperationFailure::Geometry)?;
        let purpose = self.purpose.ok_or(OperationFailure::Geometry)?;
        let binding = publication.cohort.binding;
        if purpose.capability != binding.cap
            || purpose.reservation != binding.reservation
            || purpose.account_generation != binding.account_generation
            || purpose.process_generation != binding.process_generation
        {
            return Err(OperationFailure::Geometry);
        }
        let issued = PublisherTicket {
            serial: publication.ticket_serial,
            phase: PublisherTicketPhase::Issued,
        }
        .encode()
        .map_err(|_| OperationFailure::Geometry)?;
        let words = self.command_words()?;
        if words[PUBLICATION_WORD].load(Ordering::SeqCst) != 0
            || words[TICKET_WORD].load(Ordering::SeqCst) != 0
        {
            return Err(OperationFailure::Geometry);
        }

        // The canonical journal receives every coordinate before the first
        // actual shared effect. Failure cannot recreate local birth privilege.
        self.command.offer = Some(RetainedOffer {
            publication,
            bytes,
            publication_attempted: true,
            publication_committed: false,
            ticket_attempted: false,
            ticket_issued: false,
            withdrawal_attempted: false,
            withdrawn: false,
            revocation_attempted: false,
            revoked: false,
        });
        let offer = self
            .command
            .offer
            .as_ref()
            .ok_or(OperationFailure::Geometry)?;
        let words = self.command_words()?;
        words[PUBLICATION_WORD]
            .compare_exchange(0, 1_u64.to_be(), Ordering::SeqCst, Ordering::SeqCst)
            .map_err(|_| OperationFailure::Geometry)?;
        for (index, chunk) in offer.bytes.as_chunks::<8>().0.iter().enumerate().skip(1) {
            words[PUBLICATION_WORD + index].store(u64::from_ne_bytes(*chunk), Ordering::SeqCst);
        }
        words[PUBLICATION_WORD].store(publication.sequence.to_be(), Ordering::SeqCst);
        let offer = self
            .command
            .offer
            .as_mut()
            .ok_or(OperationFailure::Geometry)?;
        offer.publication_committed = true;
        offer.ticket_attempted = true;

        self.command_words()?[TICKET_WORD]
            .compare_exchange(0, issued.to_be(), Ordering::SeqCst, Ordering::SeqCst)
            .map_err(|_| OperationFailure::Geometry)?;
        self.command
            .offer
            .as_mut()
            .ok_or(OperationFailure::Geometry)?
            .ticket_issued = true;

        Ok(PublisherLoanIdentity {
            ticket_serial: publication.ticket_serial,
            offer_generation: publication.offer_generation,
            command_sequence: publication.sequence,
        })
    }"#;

const CURRENT_REFUSAL: &str = r#"fn publisher_current_preserves_first_native_refusal_without_retry_or_transfer() {
    CURRENT_CALLS.store(0, Ordering::Relaxed);
    let fixture = Fixture::new(false);
    let descriptors = fixture.descriptors();
    let keeper = validate_output(&fixture.output(&descriptors[..5]), refused_current).unwrap();

    for _ in 0..2 {
        assert!(
            matches!(keeper.check_current(7), Err(StartupSourceError::NativeStatus { status }) if status == -libc::ESTALE)
        );
    }
    assert!(keeper.begin_publisher_transfer().is_err());
    assert_eq!(CURRENT_CALLS.load(Ordering::Relaxed), 1);
}"#;

const CURRENT_CALLBACK: &str = r#"extern "C" fn refused_current(_: u64, version: u32, size: usize, _: *mut Output) -> i32 {
    assert_eq!(version, 4);
    assert_eq!(size, size_of::<Output>());
    CURRENT_CALLS.fetch_add(1, Ordering::Relaxed);
    -libc::ESTALE
}"#;

const CURRENT_CHECK: &str = r#"pub(super) fn check_current(
        &self,
        plugin_id: u64,
        retained: &NativeSetupBorrow,
    ) -> Result<(), StartupSourceError> {
        let mut observation =
            self.observation
                .try_lock()
                .map_err(|_| StartupSourceError::Ownership {
                    reason: "publisher setup observation is already borrowed or poisoned",
                })?;
        if let Some(first) = observation.first {
            return Err(first);
        }
        if observation.runtime_transfer_attempted {
            // The old v4 current API is installer-only. Once transfer is
            // attempted, the distinct durable Runtime field retains all debt;
            // the ordinary Source/runtime-purpose checks remain compulsory.
            return Ok(());
        }

        let mut output = Output::empty();
        let status = (self.current)(plugin_id, 4, size_of::<Output>(), &mut output);
        let result = if status != 0 {
            Err(StartupSourceError::NativeStatus { status })
        } else {
            validate_output(&output, self.current).and_then(|observed| {
                let publisher = observed.publisher.as_ref().ok_or_else(malformed)?;
                if observed.control.as_raw_fd() != retained.control.as_raw_fd()
                    || observed.roles.map(|role| role.map(|fd| fd.as_raw_fd()))
                        != retained.roles.map(|role| role.map(|fd| fd.as_raw_fd()))
                    || publisher.frame != self.frame
                    || publisher.roles != self.roles
                {
                    return Err(malformed());
                }
                Ok(())
            })
        };
        if let Err(first) = result {
            observation.first = Some(first);
        }
        result
    }"#;

const CURRENT_TRANSFER: &str = r#"pub(super) fn begin_runtime_transfer(&self) -> Result<(), StartupSourceError> {
        let mut observation =
            self.observation
                .try_lock()
                .map_err(|_| StartupSourceError::Ownership {
                    reason: "publisher setup observation is already borrowed or poisoned",
                })?;
        if let Some(first) = observation.first {
            return Err(first);
        }
        if observation.runtime_transfer_attempted {
            return Err(StartupSourceError::Ownership {
                reason: "publisher service transfer cannot be repeated",
            });
        }
        observation.runtime_transfer_attempted = true;
        Ok(())
    }"#;

const CURRENT_CALLER: &str = r#"pub(super) fn check_current(&self, plugin_id: u64) -> Result<(), StartupSourceError> {
        if let Some(publisher) = self.publisher.as_ref() {
            publisher.check_current(plugin_id, self)
        } else {
            Ok(())
        }
    }"#;

const TRANSFER_CALLER: &str = r#"fn begin_publisher_transfer(&self) -> Result<(), StartupSourceError> {
        self.publisher
            .as_ref()
            .ok_or(StartupSourceError::Ownership {
                reason: "native publisher service is absent",
            })?
            .begin_runtime_transfer()
    }"#;

pub(super) const CONTRACTS: &[Contract] = &[
    Contract {
        package: "crucible-qemu-host",
        target: "src/spawn/source_supervision/publisher/tests",
        required: &[MAPPING_REFUSAL, PHYSICAL_FIXTURE],
        expressions: &[(MAPPING_REFUSAL, 1)],
        companions: &[Companion {
            path: "crates/crucible/qemu/crucible-qemu-host/src/spawn/source_supervision/publisher.rs",
            required: &[PHYSICAL_RETURN, PHYSICAL_BIRTH],
            counts: &[(PHYSICAL_RETURN, 1), (PHYSICAL_BIRTH, 1)],
        }],
    },
    Contract {
        package: "crucible-qemu-host",
        target: "src/spawn/source_supervision/publisher/command/tests",
        required: &[COMMAND_REFUSAL, COMMAND_FIXTURE],
        expressions: &[(COMMAND_REFUSAL, 1)],
        companions: &[
            Companion {
                path: "crates/crucible/qemu/crucible-qemu-host/src/spawn/source_supervision/publisher/command.rs",
                required: &[COMMAND_PUBLISH, COMMAND_PREFLIGHT],
                counts: &[(COMMAND_PUBLISH, 1), (COMMAND_PREFLIGHT, 1)],
            },
            Companion {
                path: "crates/crucible/qemu/crucible-qemu-host/src/spawn/source_supervision/publisher/tests.rs",
                required: &[PHYSICAL_FIXTURE],
                counts: &[(PHYSICAL_FIXTURE, 1)],
            },
        ],
    },
    Contract {
        package: "crucible-qemu-plugin",
        target: "src/startup_source/native_setup/publisher/tests",
        required: &[CURRENT_REFUSAL, CURRENT_CALLBACK],
        expressions: &[(CURRENT_REFUSAL, 1)],
        companions: &[
            Companion {
                path: "crates/crucible/qemu/crucible-qemu-plugin/src/startup_source/native_setup/publisher.rs",
                required: &[CURRENT_CHECK, CURRENT_TRANSFER],
                counts: &[(CURRENT_CHECK, 1), (CURRENT_TRANSFER, 1)],
            },
            Companion {
                path: "crates/crucible/qemu/crucible-qemu-plugin/src/startup_source/native_setup.rs",
                required: &[CURRENT_CALLER, TRANSFER_CALLER],
                counts: &[(CURRENT_CALLER, 1), (TRANSFER_CALLER, 1)],
            },
        ],
    },
];

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::{mask_with_companions, read_companions};

    fn has_retry(code: &str) -> bool {
        crate::flaky_escape_failures("unreviewed", "unreviewed", code)
            .iter()
            .any(|finding| finding.contains("`retry`"))
    }

    fn source(contract: &Contract) -> Result<String, std::io::Error> {
        let root = crate::workspace_root();
        let path = crate::workspace::package_path(&root.join("crates"), contract.package)
            .join(format!("{}.rs", contract.target));
        Ok(crate::scrub_comments_and_strings(&std::fs::read_to_string(
            path,
        )?))
    }

    #[test]
    fn publisher_refusal_classification_requires_the_actual_owner_and_preserves_added_retries()
    -> Result<(), Box<dyn std::error::Error>> {
        for contract in CONTRACTS {
            let code = source(contract)?;
            let companions = read_companions(contract)?;

            assert!(has_retry(&code));
            assert!(!has_retry(&mask_with_companions(
                contract,
                &code,
                &companions
            )));
            let extra = format!("{code}\nfn unrelated_retry() {{ loop {{ retry(); }} }}");
            assert!(has_retry(&mask_with_companions(
                contract,
                &extra,
                &companions
            )));

            for (index, binding) in contract.companions.iter().enumerate() {
                for required in binding.required {
                    let mut changed = companions.clone();
                    assert!(changed[index].contains(required));
                    changed[index] = changed[index].replacen(required, "foreign();", 1);
                    assert!(has_retry(&mask_with_companions(contract, &code, &changed)));
                }
            }
        }
        Ok(())
    }

    #[test]
    fn publisher_refusal_classification_rejects_changed_effects_and_refusal_observations()
    -> Result<(), Box<dyn std::error::Error>> {
        for (index, before, after) in [
            (
                0,
                "body.mapping_return_uncertain=true;",
                "body.mapping_return_uncertain=false;",
            ),
            (
                0,
                "assert!(!body.return_physical(false));",
                "assert!(body.return_physical(false));",
            ),
            (
                0,
                "assert_eq!(body.mapping,mapping);",
                "assert_eq!(body.mapping,None);",
            ),
            (
                0,
                "body.roles.iter().all(Option::is_some)",
                "body.roles.iter().all(Option::is_none)",
            ),
            (1, "forchangedin0..14", "forchangedin0..13"),
            (
                1,
                "assert!(body.command.first.is_some(),",
                "assert!(body.command.first.is_none(),",
            ),
            (
                1,
                "assert_eq!(region_bytes(&body),before,",
                "assert_ne!(region_bytes(&body),before,",
            ),
            (2, "for_in0..2", "for_in0..1"),
            (
                2,
                "assert!(keeper.begin_publisher_transfer().is_err());",
                "assert!(keeper.begin_publisher_transfer().is_ok());",
            ),
            (
                2,
                "assert_eq!(CURRENT_CALLS.load(Ordering::Relaxed),1);",
                "assert_eq!(CURRENT_CALLS.load(Ordering::Relaxed),2);",
            ),
        ] {
            let contract = &CONTRACTS[index];
            let code = super::super::compact_code(&source(contract)?);
            let companions = read_companions(contract)?;

            assert!(
                code.contains(before),
                "missing actual refusal cut: {before}"
            );
            // Mutate the reviewed function even when another test contains
            // the same physical-return assertion or publication expression.
            let owner = contract
                .required
                .iter()
                .find_map(|required| {
                    let required =
                        super::super::compact_code(&crate::scrub_comments_and_strings(required));
                    required.contains(before).then_some(required)
                })
                .unwrap_or_else(|| panic!("missing reviewed owner for cut: {before}"));
            let changed = code.replacen(&owner, &owner.replacen(before, after, 1), 1);
            assert!(
                has_retry(&mask_with_companions(contract, &changed, &companions)),
                "changed refusal was classified: {before}"
            );
        }
        Ok(())
    }
}
