//! Exact operation and partition scoped local conditional observation custody.

use aos_assessment::observation::ProviderObservationV1;
use aos_assessment::time::Timestamp;
use aos_assessment_runtime::provider::{
    CachedResponse, NormalizedObject, ProviderOperation, ProviderWorkPlanV1, ProviderWorkResultV1,
};

use super::super::*;

impl StateStore {
    fn conditional_directory(&self, partition: &str) -> Result<PathBuf> {
        let directory = self
            .assessment_source_directory(partition)?
            .join("observations");
        secure_directory(&directory)?;
        Ok(directory)
    }

    pub(in crate::commands::maintain) fn local_conditional_response(
        &self,
        partition: &str,
        operation: &ProviderOperation,
        issued_at: &Timestamp,
        response_limit: u64,
    ) -> Result<Option<CachedResponse>> {
        if operation.source_requests()?.len() != 1
            || matches!(operation, ProviderOperation::QueryOsv { .. })
        {
            return Ok(None);
        }
        self.with_provider_lock(|| {
            let path = self
                .conditional_directory(partition)?
                .join(operation.digest()?.hex());
            let Some(observation) = read_observation(&path)? else {
                return Ok(None);
            };
            CachedResponse::from_observation(operation, observation, issued_at, response_limit)
        })
    }

    pub(in crate::commands::maintain) fn retain_local_conditional_response(
        &self,
        plan: &ProviderWorkPlanV1,
        result: &ProviderWorkResultV1,
    ) -> Result<()> {
        result.validate_for(plan, &result.completed_at)?;
        self.with_provider_lock(|| {
            self.require_settled_source_unlocked(plan, result)?;
            for projection in &result.normalized_objects {
                let NormalizedObject::Observation(observation) = &projection.object else {
                    continue;
                };
                let Some(cache) = CachedResponse::from_observation(
                    &plan.operation,
                    observation.clone(),
                    &result.completed_at,
                    plan.limits.response_bytes,
                )?
                else {
                    continue;
                };
                // Publication follows durable physical settlement and exact raw
                // custody verification. It never changes a logical result head.
                let bytes = self.read_assessment_source(
                    &plan.authorization_partition,
                    cache.evidence.digest,
                    cache.evidence.byte_length,
                )?;
                if bytes.len() as u64 != cache.evidence.byte_length {
                    bail!("conditional response has different retained byte length");
                }
                let directory = self.conditional_directory(&plan.authorization_partition)?;
                let filename = plan.operation.digest()?.hex();
                let previous = read_observation(&directory.join(&filename))?;
                if let Some(previous) = &previous {
                    CachedResponse::from_observation(
                        &plan.operation,
                        previous.clone(),
                        &previous.validated_at,
                        plan.limits.response_bytes,
                    )?;
                    if (previous.validated_at.clone(), previous.digest()?)
                        >= (observation.validated_at.clone(), observation.digest()?)
                    {
                        continue;
                    }
                }
                if previous.is_none() && fs::read_dir(&directory)?.take(4096).count() >= 4096 {
                    bail!("conditional observation index reached its retention bound");
                }
                atomic_write(&directory, &filename, observation)?;
            }
            Ok(())
        })
    }
}

fn read_observation(path: &Path) -> Result<Option<ProviderObservationV1>> {
    let file = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    if !file.metadata()?.is_file() || file.metadata()?.len() > 65536 {
        bail!("conditional observation exceeds its regular-file custody bound");
    }
    let mut bytes = Vec::new();
    file.take(65537).read_to_end(&mut bytes)?;
    Ok(Some(ProviderObservationV1::from_slice(&bytes)?))
}
