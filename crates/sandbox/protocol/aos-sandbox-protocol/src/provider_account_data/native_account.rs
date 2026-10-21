//! Shares the canonical Git account relation and complete coverage lookup.
//!
//! This is saved account DATA only. Enrollment, owner currentness, the actual
//! native COMMIT observer and the original protected writer remain separate.
//!
//! ```text
//! AOSGUBA1 | version:u16=1 | reserved:u16=0 | project16 | generationBE64
//!          | predecessor32 | origin32
//!          | committed[ResourceDimension::COUNT] | reserved[...]  (452)
//! AOSGUBH1 | version:u16=1 | reserved:u16=0 | project16 | generationBE64
//!          | account-digest32                                  (68)
//! ```

/// Defines the existing private account codec and exact three-PUT comparison.
#[macro_export]
macro_rules! define_provider_native_account_data_recipe_v1 {
    ($invalid:expr) => {
        const ACCOUNT_PREFIX: &[u8] = b"git-upload/account-revision/";
        const HEAD_PREFIX: &[u8] = b"git-upload/account-current/";
        const ACCOUNT_MAGIC: &[u8; 8] = b"AOSGUBA1";
        const HEAD_MAGIC: &[u8; 8] = b"AOSGUBH1";
        const ACCOUNT_DOMAIN: &[u8] = b"aos.sandbox.git-upload.account-revision.v1\0";
        const ACCOUNT_BYTES: usize = 452;
        const HEAD_BYTES: usize = 68;
        
        fn account_key(project: ProjectId, generation: u64) -> Vec<u8> {
            key(ACCOUNT_PREFIX, project.as_bytes(), Some(generation))
        }
        
        fn account_head_key(project: ProjectId) -> Vec<u8> {
            key(HEAD_PREFIX, project.as_bytes(), None)
        }
        
        fn check_record_header(
            bytes: &[u8],
            magic: &[u8; 8],
            minimum: usize,
        ) -> Result<(ProjectId, u64), PublisherPolicyError> {
            if bytes.len() < minimum || bytes.get(..8) != Some(magic.as_slice())
                || u16::from_be_bytes(array(bytes, 8)?) != 1
                || u16::from_be_bytes(array(bytes, 10)?) != 0
            {
                return Err($invalid);
            }
            let project = ProjectId::from_bytes(array(bytes, 12)?);
            let generation = u64::from_be_bytes(array(bytes, 28)?);
            if project.as_bytes() == &[0; 16] || generation == 0 {
                return Err($invalid);
            }
            Ok((project, generation))
        }
        
        struct AccountRevision {
            predecessor: ObjectDigest,
            origin: ObjectDigest,
            committed: ResourceVector,
            reserved: ResourceVector,
            digest: ObjectDigest,
        }
        
        // Called only after the existing header/width/key checks. Both namespace
        // replay and the native co-commit relation use these same account amounts.
        fn decode_account_contents(bytes: &[u8]) -> Result<AccountRevision, PublisherPolicyError> {
            let mut vectors = [[0; ResourceDimension::COUNT]; 2];
            let mut offset = 100;
            for vector in &mut vectors {
                for amount in vector {
                    *amount = u64::from_be_bytes(array(bytes, offset)?);
                    offset += 8;
                }
            }
            Ok(AccountRevision {
                predecessor: ObjectDigest::from_bytes(array(bytes, 36)?),
                origin: ObjectDigest::from_bytes(array(bytes, 68)?),
                committed: ResourceVector::new(vectors[0]),
                reserved: ResourceVector::new(vectors[1]),
                digest: commitment(ACCOUNT_DOMAIN, bytes),
            })
        }
        
        pub(crate) fn require_coverage_native_account_transaction(
            transaction: &JournalTransaction,
        ) -> Result<(), PublisherPolicyError> {
            let records = transaction.records();
            if records.len() != 3
                || records.iter().any(|record| record.namespace() != RecordNamespace::PublisherPolicy)
            {
                return Err($invalid);
            }
            require_coverage_native_account_parts(transaction.id(), [
                (records[0].key(), records[0].value()),
                (records[1].key(), records[1].value()),
                (records[2].key(), records[2].value()),
            ])
        }
        
        fn require_coverage_native_account_parts(
            transaction_id: &[u8; 16],
            records: [(&[u8], Option<&[u8]>); 3],
        ) -> Result<(), PublisherPolicyError> {
            let coverage = super::account_coverage::AccountCoverageV1::decode(
                records[0].1.ok_or($invalid)?,
            )?;
            coverage.require_empty_first_profile()?;
            let account = records[1].1.ok_or($invalid)?;
            let head = records[2].1.ok_or($invalid)?;
            let (project, generation) = check_record_header(account, ACCOUNT_MAGIC, ACCOUNT_BYTES)?;
            let (head_project, head_generation) = check_record_header(head, HEAD_MAGIC, HEAD_BYTES)?;
            if account.len() != ACCOUNT_BYTES
                || head.len() != HEAD_BYTES
                || generation != 2
                || coverage.project()? != project
                || coverage.generation()? != generation
                || records[0].0 != coverage.key()?
                || records[1].0 != account_key(project, generation)
                || records[2].0 != account_head_key(project)
                || (head_project, head_generation) != (project, generation)
                || transaction_id != &coverage.transaction()?
            {
                return Err($invalid);
            }
            let revision = decode_account_contents(account)?;
            let (committed, reserved) = coverage.fold()?;
            if coverage.account()? != revision.digest
                || coverage.origin()? != revision.origin
                || revision.committed != committed
                || revision.reserved != reserved
                || ObjectDigest::from_bytes(array(head, 36)?) != revision.digest
            {
                return Err($invalid);
            }
            Ok(())
        }
        
            pub(crate) fn require_complete_coverage_read_state_data_v1(
                state: &std::collections::BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
            ) -> Result<(), PublisherPolicyError> {
                let mut coverage_rows = state.iter().filter(|((namespace, key), _)| {
                    *namespace == RecordNamespace::PublisherPolicy
                        && key.starts_with(super::account_coverage::PREFIX)
                });
                let ((_, coverage_key), bytes) = coverage_rows.next()
                    .ok_or($invalid)?;
                if coverage_rows.next().is_some() {
                    return Err($invalid);
                }
                let coverage = super::account_coverage::AccountCoverageV1::decode(bytes)?;
                let project = coverage.project()?;
                let account_key = account_key(project, 2);
                let head_key = account_head_key(project);
                let account = state.get(&(RecordNamespace::PublisherPolicy, account_key.clone()))
                    .ok_or($invalid)?;
                let head = state.get(&(RecordNamespace::PublisherPolicy, head_key.clone()))
                    .ok_or($invalid)?;
                require_coverage_native_account_parts(&coverage.transaction()?, [
                    (coverage_key, Some(bytes)), (&account_key, Some(account)), (&head_key, Some(head)),
                ])
            }
        
    };
}
