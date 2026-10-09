//! Protected local assessment custody, current closure and shared provider quota.

use super::*;
use aos_assessment::input::EvaluationData;
use aos_assessment::result::PackageAssessmentV1;

#[derive(Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct SourceBudget {
    day: u64,
    requests: u32,
    next_eligible_at: u64,
}

impl StateStore {
    pub(in crate::commands::maintain) fn assessment_directory(&self) -> Result<PathBuf> {
        let directory = self.repository.join("assessments");
        secure_directory(&directory)?;
        Ok(directory)
    }

    pub(in crate::commands::maintain) fn assessment_closure(
        &self,
    ) -> Result<Option<EvaluationData>> {
        let path = self.assessment_directory()?.join("current-data.json");
        let bytes = read_optional::<serde_json::Value>(&path, "assessment closure")?;
        bytes
            .map(|value| EvaluationData::from_slice(&serde_json::to_vec(&value)?))
            .transpose()
    }

    pub(in crate::commands::maintain) fn retain_assessment(
        &self,
        data: &EvaluationData,
        result: &PackageAssessmentV1,
    ) -> Result<()> {
        let directory = self.assessment_directory()?;
        atomic_write(
            &directory,
            &format!("{}.json", result.digest()?.hex()),
            result,
        )?;
        atomic_write(&directory, "current-data.json", data)?;
        atomic_write(&directory, "current-result.json", result)
    }

    pub(in crate::commands::maintain) fn claim_assessment_source(
        &self,
        provider: &str,
        requests: u32,
        now: u64,
    ) -> Result<()> {
        if !(1..=10).contains(&requests)
            || ![
                "github-releases",
                "github-tags",
                "go-releases",
                "repology",
                "osv",
                "nvd",
                "cisa-kev",
            ]
            .contains(&provider)
        {
            bail!("unsupported local assessment source quota request");
        }
        // Use the existing shared Repology budget, preserving the legacy CLI's
        // host-wide limit instead of creating a second allowance for assessments.
        if provider == "repology" {
            return self.claim_repology_request(now);
        }
        self.with_provider_lock(|| {
            let key = match provider {
                "github-releases" | "github-tags" => "github",
                provider => provider,
            };
            let filename = format!("assessment-budget-{key}.json");
            let mut budget: SourceBudget =
                read_optional(&self.root.join(&filename), "assessment source budget")?
                    .unwrap_or_default();
            let day = now / 86400;
            if budget.day != day {
                budget = SourceBudget {
                    day,
                    ..Default::default()
                };
            }
            if now < budget.next_eligible_at
                || budget
                    .requests
                    .checked_add(requests)
                    .is_none_or(|count| count > 1000)
            {
                bail!("local assessment source quota is unavailable");
            }
            budget.requests += requests;
            // Anonymous NVD requests are conservatively spaced at six seconds.
            // A configured key does not enlarge the installed allowance here.
            budget.next_eligible_at = now + if key == "nvd" { 6 } else { 0 };
            atomic_write(&self.root, &filename, &budget)
        })
    }

    pub(in crate::commands::maintain) fn retain_assessment_source(
        &self,
        partition: &str,
        bytes: &[u8],
    ) -> Result<Sha256Digest> {
        if bytes.len() > 8 * 1024 * 1024 {
            bail!("assessment source exceeds its raw response byte ceiling");
        }
        let directory = self.assessment_source_directory(partition)?;
        let digest = Sha256Digest::of_bytes(bytes);
        let filename = digest.hex();
        match self.read_assessment_source(partition, digest, bytes.len() as u64) {
            Ok(existing) if existing == bytes => return Ok(digest),
            Ok(_) => bail!("assessment source custody has conflicting immutable content"),
            Err(error)
                if error
                    .downcast_ref::<std::io::Error>()
                    .is_some_and(|error| error.kind() == std::io::ErrorKind::NotFound) => {}
            Err(error) => return Err(error),
        }
        // The operation lease excludes local assessment writers in this
        // namespace; immutable identity is verified again by every reader.
        atomic_write_bytes(&directory, &filename, bytes)?;
        Ok(digest)
    }

    pub(in crate::commands::maintain) fn read_assessment_source(
        &self,
        partition: &str,
        digest: Sha256Digest,
        limit: u64,
    ) -> Result<Vec<u8>> {
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(
                self.assessment_source_directory(partition)?
                    .join(digest.hex()),
            )?;
        if !file.metadata()?.is_file() || file.metadata()?.len() > limit.min(8 * 1024 * 1024) {
            bail!("assessment source custody exceeds its exact bounded file profile");
        }
        let mut bytes = Vec::new();
        file.take(limit.min(8 * 1024 * 1024) + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() as u64 > limit || Sha256Digest::of_bytes(&bytes) != digest {
            bail!("assessment source custody does not match its immutable identity");
        }
        Ok(bytes)
    }

    fn assessment_source_directory(&self, partition: &str) -> Result<PathBuf> {
        if partition.is_empty() || partition.len() > 128 || partition.chars().any(char::is_control)
        {
            bail!("invalid local assessment custody partition");
        }
        let directory = self
            .assessment_directory()?
            .join("sources")
            .join(Sha256Digest::of_bytes(partition).hex());
        secure_directory(&directory)?;
        Ok(directory)
    }
}
